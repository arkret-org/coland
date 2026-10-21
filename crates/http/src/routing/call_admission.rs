//! Transient per-holder invitation delivery and authoritative Consent cuts.

use arkret_models_collaboration::call_invitation::*;
use arkret_models_collaboration::events_payloads::consent::ConsentPeer;
use arkret_signatures::proof::{
    Ed25519DetachedJwsVerifier, PublicKeyMaterial, sign_ed25519_detached_jws,
};
use arkret_wire::{AccountId, ActorId, DidUrl};
use chrono::{Duration, Utc};
use coland_http::error::AppError;
use salvo::prelude::*;

use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;
use crate::{JsonResult, json_ok};

fn invalid(error: impl std::fmt::Display) -> AppError {
    AppError::param_invalid(error.to_string())
}
fn unavailable(error: impl std::fmt::Display) -> AppError {
    crate::app_error!(TemporarilyUnavailable, error.to_string())
}

pub(super) fn self_router() -> Router {
    Router::new()
        .push(Router::with_path("consent/current").post(self_current))
        .push(Router::with_path("rtc/invitation").post(self_send))
}
pub(super) fn peer_router() -> Router {
    Router::new()
        .push(Router::with_path("consent/current").post(peer_current))
        .push(Router::with_path("rtc/invitation-admission").post(peer_admission))
        .push(Router::with_path("rtc/invitation").post(peer_relay))
}

fn method(state: &AppState) -> Result<DidUrl, AppError> {
    DidUrl::new(super::federation::federation_service_signature_key_id(
        state.service_did().as_str(),
    ))
    .map_err(invalid)
}

async fn targeted_cut(
    state: &AppState,
    request: &ConsentCurrentReadRequestBody,
) -> Result<coland_storage::ConsentCurrentCut, AppError> {
    if request.audience_actor_id != ActorId::service(request.holder_account_id.station_id.clone())
        || !valid_nonce(&request.nonce)
    {
        return Err(invalid("invalid holder current audience or nonce"));
    }
    state
        .persistence()
        .consent_current_cut(&request.holder_account_id, &request.peer, None)
        .await
        .map_err(unavailable)
}

pub(crate) async fn holder_location(
    state: &AppState,
    holder: &AccountId,
) -> Result<(arkret_wire::RealmId, arkret_wire::DidCoreId), AppError> {
    let origin = state
        .persistence()
        .principal_resolution_by_account_id(holder)
        .await
        .map_err(unavailable)?
        .ok_or_else(|| unavailable("accepted holder PCR origin is unavailable"))?;
    let governance =
        arkret_wire::GenesisGovernance::from_genesis(&origin.genesis_event).map_err(unavailable)?;
    if let arkret_wire::GenesisGovernance::Human(account)
    | arkret_wire::GenesisGovernance::Agent(account) = &governance
    {
        let subject = if governance.is_human() {
            "Human"
        } else {
            "Agent"
        };
        if account != holder {
            return Err(unavailable(format!(
                "{subject} inception differs from the full holder"
            )));
        }
        let current = state
            .authority_commits()
            .current_authority(&origin.pcr_realm_id)
            .await
            .map_err(unavailable)?
            .ok_or_else(|| unavailable(format!("{subject} PCR authority is unavailable")))?;
        governance
            .validate_current(&current.service_id, current.generation)
            .map_err(unavailable)?;
        return Ok((origin.pcr_realm_id, holder.station_id.clone()));
    }
    let endpoint_url = if holder.station_id == state.service_core_id() {
        None
    } else {
        Some(
            super::federation::resolved_peer_route(
                state,
                holder.station_id.as_str(),
                "station",
                false,
            )
            .await
            .map_err(unavailable)?
            .base_url()
            .to_owned(),
        )
    };
    let candidate=arkret_models_collaboration::governance::realm_join_intake::RealmJoinCandidate {
        service_kind:arkret_models_collaboration::governance::realm_join_intake::RealmJoinCandidateServiceKind::Station,
        service_id:holder.station_id.clone(),endpoint_url,source:arkret_models_collaboration::governance::realm_join_intake::AuthorityLocatorSource::Cache,
    };
    let located = super::realm_join::resolve_verified_authority(
        state,
        &origin.pcr_realm_id,
        &[candidate],
        &arkret_wire::Base64UrlString::new(nonce()).map_err(invalid)?,
    )
    .await?;
    Ok((
        origin.pcr_realm_id,
        located.authority.current_service_id().clone(),
    ))
}

async fn current_at_authority(
    state: &AppState,
    request: &ConsentCurrentReadRequestBody,
) -> Result<ConsentCurrentReadOutcome, AppError> {
    let cut = targeted_cut(state, request).await?;
    if cut.service_id != state.service_core_id() {
        return Err(unavailable("this Station no longer governs holder PCR"));
    }
    if cut.records.len() > 1 {
        return Err(unavailable(
            "exact peer has multiple Consent current values",
        ));
    }
    let mut outcome = ConsentCurrentReadOutcome {
        request_digest: canonical_request_digest(request).map_err(invalid)?,
        realm_id: cut.realm_id,
        governance_generation: cut.generation,
        effective_stream_head: cut.head,
        current: match cut.records.into_iter().next() {
            Some(r) => ConsentCurrentState::Present {
                result: ConsentCurrentRow {
                    selector: ConsentCurrentSelector {
                        kind: ConsentCurrentSelectorKind::Consent,
                        peer_id: r.peer.actor_id().clone(),
                    },
                    source_stream_ref: r.commit.stream_ref,
                    revision: arkret_wire::CurrentRevision {
                        commit_id: r.commit.commit_id,
                        stream_position: r.commit.stream_position,
                    },
                    value: r.value,
                },
            },
            None => ConsentCurrentState::NeverWritten,
        },
        evaluated_at: cut.evaluated_at,
        expires_at: cut.evaluated_at + Duration::seconds(30),
        proof: ConsentCurrentReadProof {
            verification_method: method(state)?,
            jws: String::new(),
        },
    };
    outcome.proof.jws = sign_ed25519_detached_jws(
        state.notary_signing_key().as_ref(),
        &outcome.signature_input().map_err(invalid)?,
    )
    .map_err(unavailable)?;
    Ok(outcome)
}

pub(crate) async fn remote_post<T: serde::Serialize, O: serde::de::DeserializeOwned>(
    state: &AppState,
    service: &arkret_wire::DidCoreId,
    path: &str,
    request: &T,
) -> Result<O, AppError> {
    let bytes = arkret_canonical::canonical_json_bytes(request).map_err(invalid)?;
    let response = super::federation::outbox::signed_peer_request(
        state,
        service.as_str(),
        path,
        &bytes,
        1024 * 1024,
    )
    .await
    .map_err(unavailable)?;
    if response.status != 200 {
        return Err(unavailable(
            "holder authority did not answer the outstanding request",
        ));
    }
    serde_json::from_slice(&response.body).map_err(unavailable)
}

async fn verify_verdict(
    state: &AppState,
    realm: &arkret_wire::RealmId,
    service: &arkret_wire::DidCoreId,
    generation: u64,
    method: &DidUrl,
    jws: &str,
    bytes: &[u8],
) -> Result<(), AppError> {
    use arkret_identity::RealmAuthorityKeyDirectory;
    if service == &state.service_core_id() {
        let current = state
            .authority_commits()
            .current_authority(realm)
            .await
            .map_err(unavailable)?
            .ok_or_else(|| unavailable("local PCR authority is unavailable"))?;
        if current.service_id != *service || current.generation != generation {
            return Err(unavailable("local PCR authority cut changed"));
        }
        let signer = arkret_wire::project_did_to_core_id(
            &arkret_identity::verification_method_did(method.as_str()).map_err(unavailable)?,
        )
        .map_err(unavailable)?;
        if signer != *service {
            return Err(unavailable(
                "verdict signer differs from the owning Station",
            ));
        }
        let mut keys = arkret_identity::RealmAuthorityKeyMap::new();
        super::realm_join::insert_method_key(state, &mut keys, method).await?;
        let key = keys
            .public_key(method)
            .ok_or_else(|| unavailable("owning Station key is unavailable"))?;
        return Ed25519DetachedJwsVerifier::new()
            .verify_detached_jws(jws, bytes, &key)
            .map_err(unavailable);
    }
    let located =
        super::realm_join::resolve_verified_authority_of_service(state, realm, service).await?;
    if located.authority.current_generation() != generation {
        return Err(unavailable("holder authority generation changed"));
    }
    let signer = arkret_wire::project_did_to_core_id(
        &arkret_identity::verification_method_did(method.as_str()).map_err(unavailable)?,
    )
    .map_err(unavailable)?;
    if &signer != located.authority.current_service_id() {
        return Err(unavailable(
            "verdict signer is not current holder authority",
        ));
    }
    let mut keys = located.keys.clone();
    super::realm_join::insert_method_key(state, &mut keys, method).await?;
    let key = keys
        .public_key(method)
        .ok_or_else(|| unavailable("current authority key is unavailable"))?;
    Ed25519DetachedJwsVerifier::new()
        .verify_detached_jws(jws, bytes, &key)
        .map_err(unavailable)?;
    if located.authority.current_service_id() != &state.service_core_id() {
        state
            .authority_commits()
            .record_remote_authority(&located.current_authority(), &state.service_core_id())
            .await
            .map_err(unavailable)?;
    }
    Ok(())
}

pub(crate) async fn read_current_for_holder(
    state: &AppState,
    request: &ConsentCurrentReadRequestBody,
) -> Result<ConsentCurrentReadOutcome, AppError> {
    let (realm, service) = holder_location(state, &request.holder_account_id).await?;
    let outcome = if service == state.service_core_id() {
        current_at_authority(state, request).await?
    } else {
        remote_post(state, &service, "/_arkret/peer/consent/current", request).await?
    };
    if outcome.request_digest != canonical_request_digest(request).map_err(invalid)?
        || outcome.expires_at <= Utc::now()
        || outcome.evaluated_at > Utc::now()
        || outcome.expires_at > outcome.evaluated_at + Duration::seconds(30)
    {
        return Err(unavailable(
            "current response does not bind the outstanding holder request",
        ));
    }
    if outcome.realm_id != realm {
        return Err(unavailable("current result names another holder PCR"));
    }
    outcome
        .validate_for_request(request, outcome.governance_generation, Utc::now())
        .map_err(unavailable)?;
    verify_verdict(
        state,
        &realm,
        &service,
        outcome.governance_generation,
        &outcome.proof.verification_method,
        &outcome.proof.jws,
        &outcome.signature_input().map_err(invalid)?,
    )
    .await?;
    Ok(outcome)
}

#[endpoint(operation_id = "ak.self.consent.read.current")]
async fn self_current(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<ConsentCurrentReadOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let request: ConsentCurrentReadRequestBody = req.parse_json().await.map_err(invalid)?;
    let holder =
        super::identity::auth_grant_dpop::authenticated_session_account_id(state, &session).await?;
    if holder != request.holder_account_id {
        return Err(AppError::capability_denied(
            "current read belongs only to exact holder",
        ));
    }
    let outcome = read_current_for_holder(state, &request).await?;
    super::identity::session_actor::validated_session_actor(state, &session).await?;
    json_ok(outcome)
}

#[endpoint(operation_id = "ak.peer.consent.read.current")]
async fn peer_current(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<ConsentCurrentReadOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let peer = super::events::peer::authenticated_peer_context(state, req, true).await?;
    let request: ConsentCurrentReadRequestBody = req.parse_json().await.map_err(invalid)?;
    if peer.source_service_id != request.holder_account_id.station_id {
        return Err(AppError::capability_denied(
            "only exact holder hosting Station may read current",
        ));
    }
    super::consent_private::require_peer_holder(state, &request.holder_account_id).await?;
    json_ok(current_at_authority(state, &request).await?)
}

async fn admission_at_authority(
    state: &AppState,
    request: &CallInvitationAdmissionRequestBody,
) -> Result<CallInvitationAdmissionOutcome, AppError> {
    request.validate().map_err(invalid)?;
    let peer = ConsentPeer::Actor {
        actor_id: request.invitation.inviter_actor_id.clone(),
    };
    let cut = state
        .persistence()
        .consent_current_cut(
            &request.invitation.holder_account_id,
            &peer,
            Some(&request.subject_device_id),
        )
        .await
        .map_err(unavailable)?;
    if cut.service_id != state.service_core_id() {
        return Err(unavailable(
            "this Station is not the current holder authority",
        ));
    }
    let admitted = cut.device_admitted
        && request.invitation.expires_at > cut.evaluated_at
        && match cut.records.as_slice() {
            [record] => record.permits(
                &request.invitation.inviter_actor_id,
                request.invitation.media.consent_scope(),
                cut.evaluated_at,
            ),
            _ => false,
        };
    let mut outcome = CallInvitationAdmissionOutcome {
        request_digest: canonical_request_digest(request).map_err(invalid)?,
        admitted,
        authority_generation: cut.generation,
        evaluated_at: cut.evaluated_at,
        expires_at: (cut.evaluated_at + Duration::seconds(30)).min(request.invitation.expires_at),
        proof: CallInvitationAdmissionProof {
            verification_method: method(state)?.to_string(),
            jws: String::new(),
        },
    };
    outcome.proof.jws = sign_ed25519_detached_jws(
        state.notary_signing_key().as_ref(),
        &outcome.signature_input().map_err(invalid)?,
    )
    .map_err(unavailable)?;
    Ok(outcome)
}

/// Each caller creates a new nonce immediately before its actual release.
pub(crate) async fn fresh_admission(
    state: &AppState,
    request: &CallInvitationAdmissionRequestBody,
) -> Result<CallInvitationAdmissionOutcome, AppError> {
    request.validate().map_err(invalid)?;
    let holder = &request.invitation.holder_account_id;
    if holder.station_id != state.service_core_id() {
        let outcome: CallInvitationAdmissionOutcome = remote_post(
            state,
            &holder.station_id,
            "/_arkret/peer/rtc/invitation-admission",
            request,
        )
        .await?;
        outcome
            .validate_for_request(request, outcome.authority_generation, Utc::now())
            .map_err(unavailable)?;
        let origin = state
            .persistence()
            .principal_resolution_by_account_id(holder)
            .await
            .map_err(unavailable)?
            .ok_or_else(|| {
                unavailable("independently accepted holder PCR origin is unavailable")
            })?;
        let route = super::federation::resolved_peer_route(
            state,
            holder.station_id.as_str(),
            "station",
            false,
        )
        .await
        .map_err(unavailable)?;
        let hint=arkret_models_collaboration::governance::realm_join_intake::RealmJoinCandidate {
            service_kind: arkret_models_collaboration::governance::realm_join_intake::RealmJoinCandidateServiceKind::Station,
            service_id:holder.station_id.clone(), endpoint_url:Some(route.base_url().to_owned()), source:arkret_models_collaboration::governance::realm_join_intake::AuthorityLocatorSource::Cache,
        };
        let located = super::realm_join::resolve_verified_authority(
            state,
            &origin.pcr_realm_id,
            &[hint],
            &arkret_wire::Base64UrlString::new(nonce()).map_err(invalid)?,
        )
        .await?;
        verify_verdict(
            state,
            &origin.pcr_realm_id,
            located.authority.current_service_id(),
            outcome.authority_generation,
            &DidUrl::new(outcome.proof.verification_method.clone()).map_err(invalid)?,
            &outcome.proof.jws,
            &outcome.signature_input().map_err(invalid)?,
        )
        .await?;
        return Ok(outcome);
    }
    validate_relation(
        state,
        &CallInvitationSendRequestBody {
            invitation: request.invitation.clone(),
            envelope: request.envelope.clone(),
        },
    )
    .await?;
    if request.admission_phase == CallInvitationAdmissionPhase::MediaToken {
        let current = state
            .authority_commits()
            .call_current_cut(
                request.invitation.scope_ref.realm_id(),
                &request.invitation.call_id,
                &request.subject_actor_id,
            )
            .await
            .map_err(unavailable)?
            .ok_or_else(|| unavailable("holder Call scope is unavailable"))?;
        if current.scope_ref != request.invitation.scope_ref || matches!(current.lifecycle,arkret_models_collaboration::events_payloads::call::CallLifecycleState::Ended|arkret_models_collaboration::events_payloads::call::CallLifecycleState::Missed|arkret_models_collaboration::events_payloads::call::CallLifecycleState::Cancelled|arkret_models_collaboration::events_payloads::call::CallLifecycleState::Failed) {return Err(AppError::capability_denied("holder Call scope or lifecycle changed"));}
        let resource = match &current.scope_ref {
            arkret_wire::ScopeRef::Circle { circle_id, .. } => circle_id.as_str(),
            _ => current.scope_ref.realm_id().as_str(),
        };
        for action in [
            Some(arkret_wire::CapabilityActionId::CALL_JOIN),
            request.desired_media.as_ref().and_then(|m| {
                m.screen
                    .then_some(arkret_wire::CapabilityActionId::CALL_SCREEN_SHARE)
            }),
        ]
        .into_iter()
        .flatten()
        {
            if !crate::authz::authorize(
                state,
                current.scope_ref.realm_id().as_str(),
                &request.subject_actor_id,
                &[action],
                resource,
                Utc::now(),
            )
            .await?
            .allowed()
            {
                return Err(AppError::capability_denied(
                    "holder lacks current media capability",
                ));
            }
        }
        if current
            .focus
            .as_ref()
            .and_then(|f| f.session_focus.as_ref())
            .is_some_and(|f| request.focus_id.as_deref() != Some(f.as_str()))
            || current.moderation.iter().any(|r| {
                r.actor_id == request.subject_actor_id && r.action==arkret_models_collaboration::events_payloads::call::CallParticipantRemovalAction::Ban
            })
        {
            return Err(AppError::capability_denied(
                "holder focus or moderation changed",
            ));
        }
        let descriptor = state
            .authority_commits()
            .realm_media_service_current(current.scope_ref.realm_id())
            .await
            .map_err(unavailable)?
            .ok_or_else(|| unavailable("media issuer binding is unavailable"))?;
        if request.audience_actor_id != ActorId::service(descriptor.service_id.clone())
            || !descriptor
                .foci
                .iter()
                .any(|f| request.focus_id.as_deref() == Some(f.focus_id.as_str()))
        {
            return Err(AppError::capability_denied(
                "media audience or focus is not current",
            ));
        }
    }
    let (realm, service) = holder_location(state, holder).await?;
    let outcome = if service == state.service_core_id() {
        admission_at_authority(state, request).await?
    } else {
        remote_post(
            state,
            &service,
            "/_arkret/peer/rtc/invitation-admission",
            request,
        )
        .await?
    };
    outcome
        .validate_for_request(request, outcome.authority_generation, Utc::now())
        .map_err(unavailable)?;
    verify_verdict(
        state,
        &realm,
        &service,
        outcome.authority_generation,
        &DidUrl::new(outcome.proof.verification_method.clone()).map_err(invalid)?,
        &outcome.proof.jws,
        &outcome.signature_input().map_err(invalid)?,
    )
    .await?;
    Ok(outcome)
}

#[endpoint(operation_id = "ak.peer.call.invitation.read.admission")]
async fn peer_admission(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<CallInvitationAdmissionOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let peer = super::events::peer::authenticated_peer_context(state, req, true).await?;
    let request: CallInvitationAdmissionRequestBody = req.parse_json().await.map_err(invalid)?;
    request.validate().map_err(invalid)?;
    let hosting = &request.invitation.holder_account_id.station_id;
    if &peer.source_service_id == hosting {
        if request.admission_phase == CallInvitationAdmissionPhase::ProductDelivery
            && request.audience_actor_id != ActorId::service(hosting.clone())
        {
            return Err(AppError::capability_denied(
                "product audience is not exact holder hosting Station",
            ));
        }
        return json_ok(admission_at_authority(state, &request).await?);
    }
    if hosting != &state.service_core_id()
        || request.admission_phase != CallInvitationAdmissionPhase::MediaToken
        || request.audience_actor_id != ActorId::service(peer.source_service_id.clone())
        || super::interop::webrtc::media_service_epoch_for_realm(
            state,
            request.invitation.scope_ref.realm_id().as_str(),
        )
        .await?
        .service_id
            != peer.source_service_id.as_str()
    {
        return Err(AppError::capability_denied(
            "caller is not exact authorized token issuer",
        ));
    }
    json_ok(fresh_admission(state, &request).await?)
}

pub(crate) fn nonce() -> String {
    let bytes: [u8; 32] = rand::random();
    arkret_canonical::base64url_encode(bytes)
}

pub(crate) async fn validate_relation(
    state: &AppState,
    request: &CallInvitationSendRequestBody,
) -> Result<(), AppError> {
    request
        .invitation
        .validate_for_envelope(&request.envelope)
        .map_err(invalid)?;
    super::events::sync::signal::admit_signal_outer(
        state,
        request
            .invitation
            .inviter_actor_id
            .as_account_id()
            .ok_or_else(|| invalid("call invitation requires an Account sender"))?
            .station_id
            .as_str(),
        &request.envelope,
    )
    .await?;
    super::events::sync::signal::verify_signal_scope_authority(
        state,
        &request.envelope,
        &request.invitation.inviter_actor_id,
    )
    .await?;
    let key = if request.envelope.sender_device_id.is_none() {
        super::events::sync::signal::invitation_agent_key(state, &request.envelope).await?
    } else {
        let key = super::events::sync::signal::resolve_signal_delivery_device_key(
            state,
            &request.invitation.holder_account_id,
            &request.envelope,
        )
        .await?;
        let key = PublicKeyMaterial::Ed25519Raw {
            bytes: arkret_canonical::base64url_decode(key.public_key_b64u.as_str())
                .map_err(invalid)?,
        };
        arkret_signatures::verify_ed25519_signal_proof(&request.envelope, &key).map_err(invalid)?;
        key
    };
    Ed25519DetachedJwsVerifier::new()
        .verify_detached_jws(
            &request.invitation.proof.jws,
            &request.invitation.signature_input().map_err(invalid)?,
            &key,
        )
        .map_err(invalid)?;
    let call = state
        .authority_commits()
        .committed_event(
            &arkret_wire::EventId::new(request.invitation.call_id.as_str().replacen(
                "ak:call:",
                "ak:event:",
                1,
            ))
            .map_err(invalid)?,
        )
        .await
        .map_err(unavailable)?;
    if !call.is_some_and(|c| {
        c.event.kind == arkret_wire::EventKind::CallCreate
            && c.event.scope_ref == request.invitation.scope_ref
    }) {
        return Err(AppError::capability_denied(
            "invitation Call is not accepted in exact scope",
        ));
    }
    Ok(())
}

fn deferred() -> CallInvitationSendOutcome {
    CallInvitationSendOutcome {
        status: CallInvitationSendStatus::Deferred,
    }
}

async fn accept_local_invitation(
    state: &AppState,
    source: &str,
    request: CallInvitationSendRequestBody,
) -> Result<(), AppError> {
    super::events::sync::signal::admit_signal_outer(state, source, &request.envelope).await?;
    validate_relation(state, &request).await?;
    if request.invitation.holder_account_id.station_id != state.service_core_id() {
        return Err(AppError::capability_denied(
            "relay destination differs from exact holder Station",
        ));
    }
    let key = format!(
        "{}:{}",
        request.invitation.holder_account_id, request.invitation.envelope_digest
    );
    {
        let mut invitations = state.call_invitations.lock();
        invitations.retain(|_, v| v.invitation.expires_at > Utc::now());
        invitations.insert(key, request.clone());
    }
    super::events::sync::signal::accept_peer_signal(state, source, &request.envelope).await
}

#[endpoint(operation_id = "ak.self.call.invitation.command.send")]
async fn self_send(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<CallInvitationSendOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let request: CallInvitationSendRequestBody = req.parse_json().await.map_err(invalid)?;
    super::events::sync::signal::admit_signal(state, &session, &request.envelope).await?;
    validate_relation(state, &request).await?;
    if request.invitation.holder_account_id.station_id == state.service_core_id() {
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(error) = accept_local_invitation(&state, state.service_id(), request).await {
                tracing::warn!(code=error.wire_code(), %error, "local Call invitation failed closed");
            }
        });
    } else {
        let destination = request.invitation.holder_account_id.station_id.clone();
        let state = state.clone();
        tokio::spawn(async move {
            let result: Result<CallInvitationSendOutcome, _> = remote_post(
                &state,
                &destination,
                "/_arkret/peer/rtc/invitation",
                &request,
            )
            .await;
            if let Err(error) = result {
                tracing::warn!(code=error.wire_code(), %error, "remote Call invitation relay failed closed");
            }
        });
    }
    json_ok(deferred())
}

#[endpoint(operation_id = "ak.peer.call.invitation.command.relay")]
async fn peer_relay(depot: &mut Depot, req: &mut Request) -> JsonResult<CallInvitationSendOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let peer = super::events::peer::authenticated_peer_context(state, req, true).await?;
    let request: CallInvitationSendRequestBody = req.parse_json().await.map_err(invalid)?;
    if request
        .invitation
        .inviter_actor_id
        .as_account_id()
        .map(|account| &account.station_id)
        != Some(&peer.source_service_id)
    {
        return Err(AppError::capability_denied(
            "invitation relay caller is not actual producer Station",
        ));
    }
    request
        .invitation
        .validate_for_envelope(&request.envelope)
        .map_err(invalid)?;
    let state = state.clone();
    tokio::spawn(async move {
        if let Err(error) =
            accept_local_invitation(&state, peer.source_service_id.as_str(), request).await
        {
            tracing::warn!(code=error.wire_code(), %error, "peer Call invitation failed closed");
        }
    });
    json_ok(deferred())
}

pub(crate) async fn delivery_for_device(
    state: &AppState,
    envelope: &arkret_wire::SignalEnvelope,
    holder: &AccountId,
    device: &arkret_wire::DeviceId,
) -> Result<Option<Box<CallInvitationDeliveryView>>, AppError> {
    let key = format!(
        "{}:{}",
        holder,
        canonical_request_digest(envelope).map_err(invalid)?
    );
    let request = state.call_invitations.lock().get(&key).cloned();
    let Some(request) = request else {
        return Ok(None);
    };
    validate_relation(state, &request).await?;
    let admission = CallInvitationAdmissionRequestBody {
        invitation: request.invitation.clone(),
        envelope: envelope.clone(),
        admission_phase: CallInvitationAdmissionPhase::ProductDelivery,
        audience_actor_id: ActorId::service(state.service_core_id()),
        subject_actor_id: ActorId::account(holder.clone()),
        subject_device_id: device.clone(),
        nonce: nonce(),
        focus_id: None,
        desired_media: None,
    };
    let outcome = fresh_admission(state, &admission).await?;
    Ok(outcome.admitted.then(|| {
        Box::new(CallInvitationDeliveryView {
            invitation: request.invitation,
            request: admission,
            outcome,
        })
    }))
}
