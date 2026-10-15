//! Current holder-PCR cuts for an exact encrypted call invitation.

use arkret_models_collaboration::call_invitation::*;
use arkret_wire::{ActorId, EventId, EventKind};
use chrono::{Duration, Utc};

use super::AppState;
use crate::error::AppError;

pub(crate) fn nonce() -> Result<String, AppError> {
    let bytes: [u8; 32] = rand::random();
    Ok(arkret_canonical::base64url_encode(bytes))
}

pub(crate) async fn accepted_call(
    state: &AppState,
    call: &arkret_wire::CallId,
    scope: &arkret_wire::ScopeRef,
) -> Result<(), AppError> {
    let event_id = EventId::from_token_bytes(call.token_bytes())
        .map_err(|e| AppError::param_invalid(e.to_string()))?;
    let record = state
        .persistence()
        .committed_event(&event_id)
        .await
        .map_err(|e| crate::routing::identity::consent::consent_error(e.into()))?
        .ok_or_else(|| AppError::capability_denied("accepted Call is unavailable"))?;
    if record.event.kind != EventKind::CallCreate
        || &record.event.scope_ref != scope
        || record.event.realm_id != *scope.realm_id()
    {
        return Err(AppError::capability_denied(
            "invitation does not bind this accepted Call",
        ));
    }
    Ok(())
}

/// Caller role is checked by the hosting Station before this function. A PCR
/// authority receives only the exact authorized consumer request.
pub(crate) async fn current_cut(
    state: &AppState,
    request: &CallInvitationAdmissionRequestBody,
) -> Result<CallInvitationAdmissionOutcome, AppError> {
    request
        .validate(Utc::now())
        .map_err(|e| AppError::param_invalid(e.to_string()))?;
    let authority =
        super::authority_consent::holder_authority(state, &request.invitation.holder_account_id)
            .await?;
    let outcome = if authority.service_id != state.service_core_id() {
        let bytes = arkret_canonical::canonical_json_bytes(request)
            .map_err(|e| AppError::internal(e.to_string()))?;
        let response = crate::routing::federation::outbox::signed_peer_request(
            state,
            authority.service_id.as_str(),
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
        let key = crate::routing::federation::verifying_key_for_service_id(
            state,
            authority.service_id.as_str(),
            outcome.proof.verification_method.as_str(),
            true,
        )
        .await?;
        arkret_signatures::call_invitation::verify_call_invitation_admission(
            &outcome,
            request,
            &outcome.proof.verification_method,
            &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                bytes: key.to_bytes().to_vec(),
            },
            authority.generation,
            Utc::now(),
        )
        .map_err(|e| AppError::capability_denied(e.to_string()))?;
        outcome
    } else {
        let cut = state
            .persistence()
            .admit_consented_call(request, &state.service_core_id())
            .await
            .map_err(|e| crate::routing::identity::consent::consent_error(e.into()))?
            .ok_or_else(|| {
                crate::app_error!(TemporarilyUnavailable, "holder current cut is unavailable")
            })?;
        let mut outcome = CallInvitationAdmissionOutcome {
            request_digest: request
                .digest()
                .map_err(|e| AppError::internal(e.to_string()))?,
            admitted: cut.admitted,
            authority_generation: cut.authority_generation,
            evaluated_at: cut.evaluated_at,
            expires_at: (cut.evaluated_at + Duration::seconds(30))
                .min(request.invitation.expires_at),
            proof: CallInvitationProof {
                verification_method: arkret_wire::DidUrl::new(
                    crate::routing::federation::federation_service_signature_key_id(
                        state.service_did().as_str(),
                    ),
                )
                .map_err(|e| AppError::internal(format!("{e}")))?,
                jws: String::new(),
            },
        };
        arkret_signatures::call_invitation::sign_call_invitation_admission(
            &mut outcome,
            state.notary_signing_key().as_ref(),
        )
        .map_err(|e| AppError::internal(e.to_string()))?;
        outcome
    };
    let after =
        super::authority_consent::holder_authority(state, &request.invitation.holder_account_id)
            .await?;
    if after != authority {
        return Err(crate::app_error!(
            TemporarilyUnavailable,
            "holder authority changed during admission"
        ));
    }
    outcome
        .validate_for_request(request, authority.generation, Utc::now())
        .map_err(|e| AppError::capability_denied(e.to_string()))?;
    Ok(outcome)
}

pub(crate) fn product_request(
    state: &AppState,
    invitation: CallInvitationEnvelope,
    envelope: arkret_wire::SignalEnvelope,
    device: arkret_wire::DeviceId,
) -> Result<CallInvitationAdmissionRequestBody, AppError> {
    Ok(CallInvitationAdmissionRequestBody {
        subject_actor_id: ActorId::account(invitation.holder_account_id.clone()),
        invitation,
        envelope,
        admission_phase: CallInvitationAdmissionStage::ProductDelivery,
        audience_actor_id: ActorId::service(state.service_core_id()),
        subject_device_id: device,
        nonce: nonce()?,
        focus_id: None,
        desired_media: None,
    })
}
