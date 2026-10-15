//! Join provenance and fresh Consent at the media-token release boundary.

use arkret_models_collaboration::call_invitation::*;
use arkret_models_collaboration::events_payloads::call::{CallParticipant, CallRosterDelta};
use arkret_wire::{ActorId, CommitStreamRef, EventId, EventKind};
use chrono::Utc;

use super::*;

pub(super) async fn current_media_epoch(
    state: &AppState,
    realm: &arkret_wire::RealmId,
) -> Result<MediaServiceEpoch, AppError> {
    let port = state.authority_commits();
    let authority = port
        .current_authority(realm)
        .await
        .map_err(|e| crate::routing::identity::consent::consent_error(e.into()))?
        .ok_or_else(|| token_issuer_unauthorised("accepted Realm authority is unavailable"))?;
    let material = port
        .realm_state_snapshot_material(realm)
        .await
        .map_err(|e| crate::routing::identity::consent::consent_error(e.into()))?
        .ok_or_else(|| token_issuer_unauthorised("accepted Realm current is unavailable"))?;
    let stream = CommitStreamRef::Realm {
        realm_id: realm.clone(),
    };
    let head = material
        .visible_stream_heads
        .iter()
        .find(|head| head.stream_ref == stream)
        .ok_or_else(|| token_issuer_unauthorised("accepted Realm head is unavailable"))?;
    if material.governance_generation != authority.generation {
        return Err(token_issuer_unauthorised(
            "Realm current has a different authority generation",
        ));
    }
    let value = material
        .current_state_entries
        .iter()
        .find_map(|row| match row {
            arkret_wire::TypedCurrentRow::Value {
                selector: arkret_wire::CurrentSelector::RealmMediaService,
                source_stream_ref,
                revision,
                value,
            } if source_stream_ref == &stream
                && revision.stream_position <= head.stream_position
                && (revision.stream_position != head.stream_position
                    || revision.commit_id == head.commit_id) =>
            {
                Some(value)
            }
            _ => None,
        })
        .ok_or_else(|| token_issuer_unauthorised("accepted Realm media binding is unavailable"))?;
    let descriptor: RealmMediaServiceValue = serde_json::from_value(value.clone())
        .map_err(|e| token_issuer_unauthorised(e.to_string()))?;
    descriptor
        .validate()
        .map_err(|e| token_issuer_unauthorised(e.to_string()))?;
    let after_head = port
        .stream_head(&stream)
        .await
        .map_err(|e| crate::routing::identity::consent::consent_error(e.into()))?;
    let after_authority = port
        .current_authority(realm)
        .await
        .map_err(|e| crate::routing::identity::consent::consent_error(e.into()))?;
    if after_head.as_ref() != Some(head) || after_authority.as_ref() != Some(&authority) {
        return Err(crate::app_error!(
            TemporarilyUnavailable,
            "accepted Realm media binding changed during admission"
        ));
    }
    media_service_epoch_from_descriptor(descriptor)
}

async fn accepted_call_record(
    state: &AppState,
    body: &CallMediaTokenExchangeRequestBody,
) -> Result<coland_storage::CommittedEventRecord, AppError> {
    let id = EventId::from_token_bytes(body.call_id.token_bytes())
        .map_err(|e| AppError::param_invalid(e.to_string()))?;
    let record = state
        .persistence()
        .committed_event(&id)
        .await
        .map_err(|e| crate::routing::identity::consent::consent_error(e.into()))?
        .ok_or_else(|| AppError::capability_denied("accepted Call is unavailable"))?;
    if record.event.kind != EventKind::CallCreate || record.event.realm_id != body.realm_id {
        return Err(AppError::capability_denied(
            "media request does not bind an accepted Call",
        ));
    }
    Ok(record)
}

/// Consume the complete accepted roster without requiring unrelated history.
async fn accepted_participant(
    state: &AppState,
    body: &CallMediaTokenExchangeRequestBody,
) -> Result<Option<(CallParticipant, chrono::DateTime<Utc>)>, AppError> {
    let CallJoinContext::Refresh(context) = &body.join_context else {
        return Err(AppError::capability_denied(
            "accepted roster lookup requires private refresh binding",
        ));
    };
    let call = accepted_call_record(state, body).await?;
    let stream = CommitStreamRef::from_scope(&call.event.scope_ref, None)
        .map_err(|e| AppError::param_invalid(e.to_string()))?;
    let material = state
        .authority_commits()
        .realm_state_snapshot_material(&body.realm_id)
        .await
        .map_err(|e| crate::routing::identity::consent::consent_error(e.into()))?
        .ok_or_else(|| AppError::capability_denied("accepted roster current is unavailable"))?;
    let head = material
        .visible_stream_heads
        .iter()
        .find(|head| head.stream_ref == stream)
        .ok_or_else(|| AppError::capability_denied("accepted roster head is unavailable"))?;
    let mut participant = None;
    for row in &material.current_state_entries {
        let arkret_wire::TypedCurrentRow::Value {
            selector: arkret_wire::CurrentSelector::CallRoster { call_id },
            source_stream_ref,
            revision,
            value,
        } = row
        else {
            continue;
        };
        if call_id != &body.call_id {
            continue;
        }
        if source_stream_ref != &stream
            || revision.stream_position > head.stream_position
            || (revision.stream_position == head.stream_position
                && revision.commit_id != head.commit_id)
        {
            return Err(AppError::capability_denied(
                "accepted roster current exceeds its source head",
            ));
        }
        let roster: arkret_models_collaboration::events_payloads::call::CallRosterCurrentValue =
            serde_json::from_value(value.clone())
                .map_err(|e| AppError::capability_denied(e.to_string()))?;
        roster
            .validate_for_axis(&stream, revision)
            .map_err(|e| AppError::capability_denied(e.to_string()))?;
        let identity = &context.subject_binding.roster_identity;
        participant = roster
            .effective_participants()
            .map_err(|e| AppError::capability_denied(e.to_string()))?
            .into_iter()
            .find(|entry| {
                entry.actor_id == identity.actor_id
                    && entry.device_id == identity.device_id.as_str()
            })
            .map(|entry| {
                let accepted = roster
                    .assertions
                    .iter()
                    .filter_map(|row| match &row.value {
                        CallRosterDelta::Join { participant }
                            if participant.actor_id == entry.actor_id
                                && participant.device_id == entry.device_id
                                && participant.participant_binding == entry.participant_binding =>
                        {
                            Some(row.source_commit.committed_at)
                        }
                        _ => None,
                    })
                    .min()
                    .ok_or_else(|| {
                        AppError::capability_denied("accepted binding has no source Commit")
                    })?;
                Ok::<_, AppError>((entry, accepted))
            })
            .transpose()?;
    }
    if state
        .authority_commits()
        .stream_head(&stream)
        .await
        .map_err(|e| crate::routing::identity::consent::consent_error(e.into()))?
        .as_ref()
        != Some(head)
    {
        return Err(crate::app_error!(
            TemporarilyUnavailable,
            "accepted roster changed during refresh"
        ));
    }
    Ok(participant)
}

pub(super) async fn validate_join(
    state: &AppState,
    session: &SessionRecord,
    body: &CallMediaTokenExchangeRequestBody,
) -> Result<Option<String>, AppError> {
    body.validate_join_context_at(Utc::now())
        .map_err(|e| AppError::capability_denied(e.to_string()))?;
    let call = accepted_call_record(state, body).await?;
    match &body.join_context {
        CallJoinContext::Invitation(context) => {
            if context.invitation.scope_ref != call.event.scope_ref {
                return Err(AppError::capability_denied(
                    "invitation scope differs from accepted Call",
                ));
            }
            crate::routing::events::sync::signal::validate_call_invitation(
                state,
                &CallInvitationSendRequestBody {
                    invitation: context.invitation.clone(),
                    envelope: context.envelope.clone(),
                },
            )
            .await?;
            Ok(None)
        }
        CallJoinContext::Voluntary(context) => {
            use arkret_models_identity::{
                CurrentSignerKeyQuerySender, SignerKeyQueryOutcome, SignerKeyQuerySelector,
                SignerKeysQueryRequestBody,
            };
            let request = SignerKeysQueryRequestBody {
                request_id: arkret_wire::RequestId::new_v7_at(Utc::now().timestamp_millis() as u64),
                realm_id: body.realm_id.clone(),
                recipient_account_id: body.actor_id.as_account_id().cloned().ok_or_else(|| {
                    AppError::capability_denied("media actor is not Account-backed")
                })?,
                queries: vec![SignerKeyQuerySelector::CurrentAdmission {
                    sender: CurrentSignerKeyQuerySender::AccountDevice {
                        actor: body.actor_id.clone(),
                        device_id: body.device_id.clone(),
                        verification_method: context.proof.verification_method.clone(),
                    },
                }],
            };
            let resolved =
                crate::routing::identity::current_signer_evidence::resolve_self_signer_keys(
                    state, session, &request,
                )
                .await?;
            resolved
                .validate_for_request(&request)
                .map_err(|e| AppError::capability_denied(e.to_string()))?;
            let Some(SignerKeyQueryOutcome::CurrentDeviceResolved { selector, key }) =
                resolved.results.into_iter().next()
            else {
                return Err(AppError::capability_denied(
                    "voluntary join signer is not currently authorized",
                ));
            };
            let bytes = arkret_canonical::base64url_decode(key.public_key_b64u.as_str())
                .map_err(|e| AppError::capability_denied(e.to_string()))?;
            arkret_signatures::call_invitation::verify_call_voluntary_join(
                body,
                selector.verification_method(),
                &arkret_signatures::PublicKeyMaterial::Ed25519Raw { bytes },
                Utc::now(),
            )
            .map_err(|e| AppError::capability_denied(e.to_string()))?;
            Ok(None)
        }
        CallJoinContext::Refresh(context) => {
            let receipt = &context.subject_binding;
            if receipt.subject_actor_id != body.actor_id
                || receipt.subject_device_id != body.device_id
                || receipt.realm_id != body.realm_id
                || receipt.call_id != body.call_id
                || receipt.focus_id != body.focus_id
                || receipt.participant_id != context.participant_id
                || !receipt.media.permits(&body.invitation_media())
            {
                return Err(AppError::capability_denied(
                    "refresh private subject binding differs from the authenticated leg",
                ));
            }
            let (participant, binding_accepted_at) =
                accepted_participant(state, body).await?.ok_or_else(|| {
                    AppError::capability_denied("refresh has no accepted active participant")
                })?;
            if participant.participant_id.as_deref() != Some(&context.participant_id)
                || participant.focus_id.as_deref() != Some(&body.focus_id)
            {
                return Err(AppError::capability_denied(
                    "refresh differs from the accepted participant tuple",
                ));
            }
            let media = participant.media.as_ref().ok_or_else(|| {
                AppError::capability_denied("accepted participant media range is unavailable")
            })?;
            if !(CallInvitationMedia {
                audio: media.audio.unwrap_or(false),
                video: media.video.unwrap_or(false),
                screen: media.screen.unwrap_or(false),
            })
            .permits(&body.invitation_media())
            {
                return Err(AppError::capability_denied(
                    "refresh expands accepted participant media",
                ));
            }
            let binding = participant.participant_binding.ok_or_else(|| {
                AppError::capability_denied("accepted participant binding is unavailable")
            })?;
            if receipt.issuer_kid != binding.issuer_kid
                || receipt.expires_at != binding.expires_at
                || binding.subject_binding_digest
                    != receipt
                        .signed_digest()
                        .map_err(|e| AppError::capability_denied(e.to_string()))?
            {
                return Err(AppError::capability_denied(
                    "refresh receipt differs from the accepted public binding",
                ));
            }
            let retained = state
                .persistence()
                .accepted_call_media_binding_key(
                    &body.realm_id,
                    &body.call_id,
                    &CallMediaSubjectBinding::public_binding_digest(&binding)
                        .map_err(|e| AppError::capability_denied(e.to_string()))?,
                    &binding.issuer_kid,
                )
                .await
                .map_err(|e| crate::routing::identity::consent::consent_error(e.into()))?;
            let key = if let Some(bytes) = retained {
                ed25519_dalek::VerifyingKey::from_bytes(&bytes)
                    .map_err(|e| AppError::capability_denied(e.to_string()))?
            } else {
                crate::jws_verify::resolve_ed25519_pubkey_at(
                    state,
                    binding.issuer_kid.as_str(),
                    binding_accepted_at,
                )
                .await
                .map_err(|e| AppError::capability_denied(e.to_string()))?
            };
            let tuple = arkret_signatures::media::ParticipantBindingContext {
                actor_id: &receipt.roster_identity.actor_id,
                call_id: &body.call_id,
                device_id: &receipt.roster_identity.device_id,
                expires_at: binding.expires_at,
                focus_id: &body.focus_id,
                participant_id: &context.participant_id,
                realm_id: &body.realm_id,
                media: receipt.media.clone(),
                issuer_kid: &binding.issuer_kid,
                subject_binding_digest: &binding.subject_binding_digest,
            };
            if !super::super::participant_binding::verify_binding_signature(
                &tuple,
                &binding.sig,
                &key,
            ) {
                return Err(AppError::capability_denied(
                    "accepted participant binding is invalid",
                ));
            }
            let signature_bytes = arkret_canonical::base64url_decode(&receipt.sig)
                .map_err(|e| AppError::capability_denied(e.to_string()))?;
            let signature = ed25519_dalek::Signature::from_slice(&signature_bytes)
                .map_err(|e| AppError::capability_denied(e.to_string()))?;
            key.verify_strict(
                &receipt
                    .signing_bytes()
                    .map_err(|e| AppError::capability_denied(e.to_string()))?,
                &signature,
            )
            .map_err(|_| {
                AppError::capability_denied("refresh private subject binding signature is invalid")
            })?;
            Ok(Some(context.participant_id.clone()))
        }
    }
}

pub(super) async fn final_cut(
    state: &AppState,
    session: &SessionRecord,
    body: &CallMediaTokenExchangeRequestBody,
    issued_epoch: &MediaServiceEpoch,
) -> Result<(), AppError> {
    // Recheck provenance and established range at the actual release boundary.
    validate_join(state, session, body).await?;
    if let CallJoinContext::Invitation(context) = &body.join_context {
        let request = CallInvitationAdmissionRequestBody {
            invitation: context.invitation.clone(),
            envelope: context.envelope.clone(),
            admission_phase: CallInvitationAdmissionStage::MediaToken,
            audience_actor_id: ActorId::service(state.service_core_id()),
            subject_actor_id: body.actor_id.clone(),
            subject_device_id: body.device_id.clone(),
            nonce: crate::state::call_admission::nonce()?,
            focus_id: Some(body.focus_id.clone()),
            desired_media: Some(body.invitation_media()),
        };
        let outcome = if request.invitation.holder_account_id.station_id == state.service_core_id()
        {
            crate::state::call_admission::current_cut(state, &request).await?
        } else {
            let bytes = arkret_canonical::canonical_json_bytes(&request)
                .map_err(|e| AppError::internal(e.to_string()))?;
            let response = crate::routing::federation::outbox::signed_peer_request(
                state,
                request.invitation.holder_account_id.station_id.as_str(),
                "/_arkret/peer/rtc/invitation-admission",
                &bytes,
                65536,
            )
            .await
            .map_err(|e| crate::app_error!(TemporarilyUnavailable, e))?;
            if !(200..300).contains(&response.status) {
                return Err(crate::app_error!(
                    TemporarilyUnavailable,
                    "holder admission is unavailable"
                ));
            }
            let outcome: CallInvitationAdmissionOutcome = serde_json::from_slice(&response.body)
                .map_err(|e| AppError::internal(e.to_string()))?;
            let authority = crate::state::authority_consent::holder_authority(
                state,
                &request.invitation.holder_account_id,
            )
            .await?;
            let key = crate::routing::federation::verifying_key_for_service_id(
                state,
                authority.service_id.as_str(),
                outcome.proof.verification_method.as_str(),
                true,
            )
            .await?;
            arkret_signatures::call_invitation::verify_call_invitation_admission(
                &outcome,
                &request,
                &outcome.proof.verification_method,
                &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                    bytes: key.to_bytes().to_vec(),
                },
                authority.generation,
                Utc::now(),
            )
            .map_err(|e| AppError::capability_denied(e.to_string()))?;
            outcome
        };
        if !outcome.admitted {
            return Err(AppError::capability_denied(
                "first invitation Consent denied at token release",
            ));
        }
    }
    crate::routing::identity::session_actor::validated_session_actor(state, session).await?;
    if !state
        .authority_commits()
        .accepted_current_member_joined(&body.realm_id, &body.actor_id)
        .await
        .map_err(|e| crate::routing::identity::consent::consent_error(e.into()))?
        || !actor_has_call_capability(
            state,
            body.realm_id.as_str(),
            &body.actor_id,
            CapabilityActionId::CALL_JOIN,
        )
        .await?
    {
        return Err(AppError::capability_denied(
            "media join authority changed before token release",
        ));
    }
    let cells = CallMediaCells::load(state, body).await?;
    let epoch = current_media_epoch(state, &body.realm_id).await?;
    if &epoch != issued_epoch {
        return Err(crate::app_error!(
            TemporarilyUnavailable,
            "media issuer binding changed before token release"
        ));
    }
    if cells.actor_is_banned(&body.actor_id)
        || session_focus_for_call(&cells, &epoch, &body.focus_id)? != body.focus_id
        || !issuer_kid_belongs_to_service(&configured_media_issuer_kid(state)?, &epoch.service_id)
        || epoch
            .focus(&body.focus_id)
            .is_none_or(|focus| !token_endpoint_is_local(&focus.token_endpoint, state))
        || (body.invitation_media().screen
            && !actor_has_call_capability(
                state,
                body.realm_id.as_str(),
                &body.actor_id,
                CapabilityActionId::CALL_SCREEN_SHARE,
            )
            .await?)
    {
        return Err(AppError::capability_denied(
            "media policy changed before token release",
        ));
    }
    Ok(())
}

pub(super) async fn roster_identity_for_token(
    state: &AppState,
    body: &CallMediaTokenExchangeRequestBody,
) -> Result<CallMediaRosterIdentity, AppError> {
    let candidate = if let CallJoinContext::Refresh(context) = &body.join_context {
        context.subject_binding.roster_identity.clone()
    } else {
        let seed: [u8; 32] = rand::random();
        let key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let multibase =
            arkret_canonical::ed25519_pubkey_to_did_key_multibase(key.verifying_key().as_bytes());
        CallMediaRosterIdentity {
            actor_id: arkret_wire::DidCoreId::new(format!("ak:did_core:key:{multibase}"))
                .map_err(|e| AppError::internal(e.to_string()))?,
            device_id: arkret_wire::DeviceId::new(arkret_identifiers::new_prefixed_uuid7(
                "ak:device:",
            ))
            .map_err(|e| AppError::internal(e.to_string()))?,
        }
    };
    let stored = state
        .persistence()
        .call_media_roster_identity(
            &body.realm_id,
            &body.call_id,
            &body.actor_id,
            &body.device_id,
            &candidate,
        )
        .await
        .map_err(|e| crate::routing::identity::consent::consent_error(e.into()))?;
    if matches!(&body.join_context, CallJoinContext::Refresh(_)) && stored != candidate {
        return Err(AppError::capability_denied(
            "refresh alias conflicts with the private durable mapping",
        ));
    }
    Ok(stored)
}
