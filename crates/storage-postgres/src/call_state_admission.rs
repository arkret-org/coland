//! Durable Call axes validated at the existing Realm authorization cut.

use arkret_models_collaboration::events_payloads::call::{
    CallLifecycleState, CallModerationAssertion, CallModerationCurrentValue, CallRosterAssertion,
    CallRosterCurrentValue, CallRosterDelta, CallStatePayload,
};
use arkret_wire::{Event, RealmCommit};
use coland_storage::{PersistenceError, PersistenceResult};
use diesel::sql_types::{BigInt, Jsonb, Text, Timestamptz};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::Value;

fn refuse(detail: &str) -> PersistenceError {
    PersistenceError::Conflict(format!("failed_precondition: {detail}"))
}

#[derive(QueryableByName)]
struct CurrentRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
    #[diesel(sql_type = Jsonb)]
    source_stream_ref: Value,
    #[diesel(sql_type = Text)]
    current_commit_id: String,
    #[diesel(sql_type = BigInt)]
    current_stream_position: i64,
}

#[derive(QueryableByName)]
struct ValueRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

pub(crate) async fn commit_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
    prepared_key: Option<&coland_storage::CallMediaBindingKey>,
    prepared: Option<&coland_storage::EventApprovalCommit>,
) -> PersistenceResult<()> {
    if event.kind != arkret_wire::EventKind::CallState {
        return Ok(());
    }
    crate::realm_authorization_cut::authorize_capability_gated_event_with_approvals(
        conn, event, commit, prepared,
    )
    .await?;
    arkret_schema::validate_event_for_submit(event)
        .map_err(|e| PersistenceError::SchemaViolation(e.to_string()))?;
    let payload: CallStatePayload = serde_json::from_value(
        serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
    )
    .map_err(PersistenceError::database)?;
    payload.validate().map_err(refuse)?;
    if payload.recording_transition.is_some() || payload.transcript_transition.is_some() {
        return Err(refuse("capture transition writer is unavailable"));
    }
    let call = sql_query("SELECT value,source_stream_ref,current_commit_id,current_stream_position FROM call_state_current_results WHERE realm_id=$1 AND call_id=$2 FOR UPDATE")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(payload.call_id.as_str())
        .get_result::<CurrentRow>(conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(|| refuse("Call has no accepted genesis"))?;
    let source = serde_json::to_value(&commit.stream_ref).map_err(PersistenceError::database)?;
    if call.source_stream_ref != source
        || event.scope_ref.realm_id() != &event.realm_id
        || arkret_wire::CommitStreamRef::from_scope(&event.scope_ref, None)
            .map_err(PersistenceError::database)?
            != commit.stream_ref
    {
        return Err(refuse("Call state differs from the accepted Call scope"));
    }
    if !crate::moderation_report_current_results::scope_member_in_connection(
        conn,
        &event.realm_id,
        &event.scope_ref,
        &event.actor_id,
    )
    .await?
    {
        return Err(refuse(
            "Call participant author lacks exact scope membership",
        ));
    }
    let current: arkret_models_collaboration::events_payloads::call::CallStateCurrentValue =
        serde_json::from_value(call.value).map_err(PersistenceError::database)?;
    if matches!(
        current.to,
        CallLifecycleState::Ended
            | CallLifecycleState::Failed
            | CallLifecycleState::Missed
            | CallLifecycleState::Cancelled
    ) {
        return Err(refuse("call_state_terminal"));
    }
    if let Some(transition) = &payload.state_transition {
        let legal = match transition.from {
            CallLifecycleState::Scheduled => matches!(
                transition.to,
                CallLifecycleState::Ringing
                    | CallLifecycleState::Connecting
                    | CallLifecycleState::Cancelled
                    | CallLifecycleState::Missed
                    | CallLifecycleState::Failed
            ),
            CallLifecycleState::Ringing => matches!(
                transition.to,
                CallLifecycleState::Connecting
                    | CallLifecycleState::Active
                    | CallLifecycleState::Missed
                    | CallLifecycleState::Cancelled
                    | CallLifecycleState::Failed
            ),
            CallLifecycleState::Connecting => matches!(
                transition.to,
                CallLifecycleState::Active | CallLifecycleState::Failed | CallLifecycleState::Ended
            ),
            CallLifecycleState::Active => matches!(
                transition.to,
                CallLifecycleState::Ended | CallLifecycleState::Failed
            ),
            _ => false,
        };
        if transition.from != current.to || !legal {
            return Err(refuse("call_state_transition_invalid"));
        }
        let value = serde_json::to_value(transition).map_err(PersistenceError::database)?;
        sql_query("UPDATE call_state_current_results SET current_commit_id=$3,current_stream_position=$4,value=$5,updated_at=$6 WHERE realm_id=$1 AND call_id=$2")
            .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(payload.call_id.as_str())
            .bind::<Text,_>(commit.commit_id.as_str()).bind::<BigInt,_>(commit.stream_position as i64)
            .bind::<Jsonb,_>(value).bind::<Timestamptz,_>(commit.committed_at)
            .execute(conn).await.map_err(PersistenceError::database)?;
    }
    let previous_focus = axis(conn, event, &payload, "call_focus").await?;
    let focus = if let Some(proposed) = &payload.focus {
        if let Some(previous) = &previous_focus {
            let old = previous.value.get("session_focus").filter(|v| !v.is_null());
            let new = serde_json::to_value(proposed).map_err(PersistenceError::database)?;
            if old.is_some() && old != new.get("session_focus") {
                return Err(refuse("session_focus_already_committed"));
            }
        }
        Some(serde_json::to_value(proposed).map_err(PersistenceError::database)?)
    } else {
        previous_focus.as_ref().map(|row| row.value.clone())
    };
    if let Some(delta) = &payload.roster_delta {
        let previous = axis(conn, event, &payload, "call_roster").await?;
        let roster = match previous.as_ref() {
            Some(row) => {
                let current: CallRosterCurrentValue = serde_json::from_value(row.value.clone())
                    .map_err(PersistenceError::database)?;
                current
                    .validate_for_axis(
                        &commit.stream_ref,
                        &arkret_wire::CurrentRevision {
                            commit_id: arkret_wire::RealmCommitId::new(&row.current_commit_id)
                                .map_err(PersistenceError::database)?,
                            stream_position: row.current_stream_position as u64,
                        },
                    )
                    .map_err(PersistenceError::database)?;
                current
            }
            None => CallRosterCurrentValue {
                assertions: Vec::new(),
            },
        };
        let active: std::collections::BTreeMap<_, _> = roster
            .effective_participants()
            .map_err(PersistenceError::database)?
            .into_iter()
            .map(|participant| {
                (
                    (participant.actor_id.clone(), participant.device_id.clone()),
                    participant,
                )
            })
            .collect();
        match delta {
            CallRosterDelta::Join { participant } => {
                if !active
                    .contains_key(&(participant.actor_id.clone(), participant.device_id.clone()))
                    && active.len() >= 1000
                {
                    return Err(refuse("roster participant limit exceeded"));
                }
                let binding = participant
                    .participant_binding
                    .as_ref()
                    .ok_or_else(|| refuse("participant_binding_invalid: no SFU binding"))?;
                let key =
                    prepared_key.ok_or_else(|| refuse("participant issuer key is unavailable"))?;
                if key.issuer_kid != binding.issuer_kid
                    || binding.expires_at <= event.created_at
                    || binding.expires_at <= commit.committed_at
                    || binding.expires_at > commit.committed_at + chrono::Duration::seconds(600)
                    || participant.joined_at.is_some_and(|at| {
                        at.timestamp() % 300 != 0 || at.timestamp_subsec_nanos() != 0
                    })
                    || focus
                        .as_ref()
                        .and_then(|v| v.get("session_focus"))
                        .and_then(Value::as_str)
                        != participant.focus_id.as_deref()
                {
                    return Err(refuse("participant_binding_invalid"));
                }
                let media = sql_query("SELECT value FROM realm_bootstrap_current_results WHERE realm_id=$1 AND result_family='realm_media_service'")
                    .bind::<Text,_>(event.realm_id.as_str()).get_result::<ValueRow>(conn)
                    .await.optional().map_err(PersistenceError::database)?
                    .ok_or_else(|| refuse("token_issuer_unauthorised"))?;
                let issuer_did =
                    arkret_identity::verification_method_did(binding.issuer_kid.as_str())
                        .map_err(PersistenceError::database)?;
                let issuer = arkret_wire::project_did_to_core_id(&issuer_did)
                    .map_err(PersistenceError::database)?;
                if media.value.get("service_id").and_then(Value::as_str) != Some(issuer.as_str())
                    || !media
                        .value
                        .get("foci")
                        .and_then(Value::as_array)
                        .is_some_and(|rows| {
                            rows.iter().any(|row| {
                                row.get("focus_id").and_then(Value::as_str)
                                    == participant.focus_id.as_deref()
                            })
                        })
                {
                    return Err(refuse("token_issuer_unauthorised"));
                }
                let device = arkret_wire::DeviceId::new(&participant.device_id)
                    .map_err(PersistenceError::database)?;
                let input = arkret_signatures::media::participant_binding_signing_input(
                    &arkret_signatures::media::ParticipantBindingContext {
                        actor_id: &participant.actor_id,
                        device_id: &device,
                        call_id: &payload.call_id,
                        realm_id: &event.realm_id,
                        participant_id: participant
                            .participant_id
                            .as_deref()
                            .ok_or_else(|| refuse("participant ID missing"))?,
                        focus_id: participant
                            .focus_id
                            .as_deref()
                            .ok_or_else(|| refuse("participant focus missing"))?,
                        expires_at: binding.expires_at,
                        media: {
                            let media = participant
                                .media
                                .as_ref()
                                .ok_or_else(|| refuse("signed participant media missing"))?;
                            arkret_models_collaboration::call_invitation::CallInvitationMedia {
                                audio: media.audio.ok_or_else(|| refuse("signed audio missing"))?,
                                video: media.video.ok_or_else(|| refuse("signed video missing"))?,
                                screen: media
                                    .screen
                                    .ok_or_else(|| refuse("signed screen missing"))?,
                            }
                        },
                        issuer_kid: &binding.issuer_kid,
                        subject_binding_digest: &binding.subject_binding_digest,
                    },
                )
                .map_err(PersistenceError::database)?;
                let public = ed25519_dalek::VerifyingKey::from_bytes(&key.public_key)
                    .map_err(PersistenceError::database)?;
                let sig = arkret_canonical::base64url_decode(&binding.sig)
                    .map_err(PersistenceError::database)?;
                let sig = ed25519_dalek::Signature::from_slice(&sig)
                    .map_err(PersistenceError::database)?;
                public
                    .verify_strict(&input, &sig)
                    .map_err(|_| refuse("participant_binding_invalid"))?;
                let digest = arkret_models_collaboration::call_invitation::CallMediaSubjectBinding::public_binding_digest(binding)
                    .map_err(PersistenceError::database)?;
                let changed = sql_query("INSERT INTO call_media_binding_keys (realm_id,call_id,binding_digest,issuer_kid,public_key,accepted_commit_id) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(realm_id,call_id,binding_digest,issuer_kid) DO UPDATE SET public_key=call_media_binding_keys.public_key WHERE call_media_binding_keys.public_key=EXCLUDED.public_key")
                    .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(payload.call_id.as_str())
                    .bind::<Text,_>(digest.as_str()).bind::<Text,_>(binding.issuer_kid.as_str())
                    .bind::<diesel::sql_types::Binary,_>(key.public_key.to_vec())
                    .bind::<Text,_>(commit.commit_id.as_str()).execute(conn).await.map_err(PersistenceError::database)?;
                if changed != 1 {
                    return Err(refuse(
                        "accepted issuer key conflicts with retained binding evidence",
                    ));
                }
            }
            CallRosterDelta::Leave {
                actor_id,
                device_id,
                expected_revision,
            } => {
                if !active.contains_key(&(actor_id.clone(), device_id.clone())) {
                    return Err(refuse("unknown participant"));
                }
                let previous = axis(conn, event, &payload, "call_roster")
                    .await?
                    .ok_or_else(|| refuse("unknown participant"))?;
                if expected_revision.commit_id.as_str() != previous.current_commit_id
                    || expected_revision.stream_position as i64 != previous.current_stream_position
                {
                    return Err(refuse("roster expected_revision mismatch"));
                }
            }
        }
    }
    let roster_value = if let Some(delta) = &payload.roster_delta {
        let current = axis(conn, event, &payload, "call_roster")
            .await?
            .map(|row| serde_json::from_value::<CallRosterCurrentValue>(row.value))
            .transpose()
            .map_err(PersistenceError::database)?
            .unwrap_or(CallRosterCurrentValue {
                assertions: Vec::new(),
            });
        let current = current
            .with_assertion(CallRosterAssertion {
                tag_id: arkret_models_collaboration::exact_current_results::CanonicalEventDot::new(
                    event.event_id.clone(),
                    7,
                )
                .map_err(PersistenceError::database)?,
                source_commit: commit.clone(),
                value: delta.clone(),
            })
            .map_err(|error| refuse(&error.to_string()))?;
        current
            .validate_for_axis(
                &commit.stream_ref,
                &arkret_wire::CurrentRevision {
                    commit_id: commit.commit_id.clone(),
                    stream_position: commit.stream_position,
                },
            )
            .map_err(|error| refuse(&error.to_string()))?;
        Some(serde_json::to_value(current).map_err(PersistenceError::database)?)
    } else {
        None
    };
    let moderation_value = if let Some(delta) = &payload.moderation_delta {
        use arkret_models_collaboration::events_payloads::call::CallModerationDelta;
        let declared_author = match delta {
            CallModerationDelta::RemoveParticipant { removal } => &removal.removed_by,
            CallModerationDelta::RestoreParticipant { restored_by, .. } => restored_by,
        };
        if declared_author != event.actor_id.signing_principal_id() {
            return Err(refuse(
                "Call moderation author differs from its signed actor",
            ));
        }
        let current = axis(conn, event, &payload, "call_moderation")
            .await?
            .map(|row| serde_json::from_value::<CallModerationCurrentValue>(row.value))
            .transpose()
            .map_err(PersistenceError::database)?
            .unwrap_or(CallModerationCurrentValue {
                assertions: Vec::new(),
            });
        let current = current
            .with_assertion(CallModerationAssertion {
                tag_id: arkret_models_collaboration::exact_current_results::CanonicalEventDot::new(
                    event.event_id.clone(),
                    6,
                )
                .map_err(PersistenceError::database)?,
                source_commit: commit.clone(),
                value: delta.clone(),
            })
            .map_err(|error| refuse(&error.to_string()))?;
        current
            .validate_for_axis(
                &commit.stream_ref,
                &arkret_wire::CurrentRevision {
                    commit_id: commit.commit_id.clone(),
                    stream_position: commit.stream_position,
                },
            )
            .map_err(|error| refuse(&error.to_string()))?;
        Some(serde_json::to_value(current).map_err(PersistenceError::database)?)
    } else {
        None
    };
    for (family, value) in [
        (
            "call_focus",
            payload
                .focus
                .as_ref()
                .map(serde_json::to_value)
                .transpose()
                .map_err(PersistenceError::database)?,
        ),
        ("call_roster", roster_value),
        ("call_moderation", moderation_value),
    ] {
        if let Some(value) = value {
            sql_query("INSERT INTO call_axis_current_results (realm_id,call_id,family,source_stream_ref,current_commit_id,current_stream_position,value,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(realm_id,call_id,family) DO UPDATE SET current_commit_id=EXCLUDED.current_commit_id,current_stream_position=EXCLUDED.current_stream_position,value=EXCLUDED.value,updated_at=EXCLUDED.updated_at")
                .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(payload.call_id.as_str())
                .bind::<Text,_>(family).bind::<Jsonb,_>(&source).bind::<Text,_>(commit.commit_id.as_str())
                .bind::<BigInt,_>(commit.stream_position as i64).bind::<Jsonb,_>(&value)
                .bind::<Timestamptz,_>(commit.committed_at).execute(conn).await.map_err(PersistenceError::database)?;
        }
    }
    Ok(())
}

async fn axis(
    conn: &mut AsyncPgConnection,
    event: &Event,
    payload: &CallStatePayload,
    family: &str,
) -> PersistenceResult<Option<CurrentRow>> {
    sql_query("SELECT value,source_stream_ref,current_commit_id,current_stream_position FROM call_axis_current_results WHERE realm_id=$1 AND call_id=$2 AND family=$3 FOR UPDATE")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(payload.call_id.as_str()).bind::<Text,_>(family)
        .get_result(conn).await.optional().map_err(PersistenceError::database)
}
