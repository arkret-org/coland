//! Exact caller-signed Consent submission into the PCR current unit.

use arkret_wire::EventAdmissionSubmission;
use chrono::Utc;
use coland_services::identity::SessionIdentityState;
use coland_services::{ServiceError, ServiceResult};
use coland_storage::{ConsentAdmissionOutcome, ConsentAdmissionWrite};

use super::AppState;

pub(crate) async fn holder_authority(
    state: &AppState,
    holder: &arkret_wire::AccountId,
) -> Result<coland_storage::CurrentRealmAuthority, crate::error::AppError> {
    let realm = state
        .persistence()
        .consent_holder_realm(holder)
        .await
        .map_err(|e| crate::routing::identity::consent::consent_error(e.into()))?
        .ok_or_else(|| {
            crate::app_error!(
                TemporarilyUnavailable,
                "holder PCR authority is unavailable"
            )
        })?;
    state
        .authority_commits()
        .current_authority(&realm)
        .await
        .map_err(|e| crate::routing::identity::consent::consent_error(e.into()))?
        .ok_or_else(|| {
            crate::app_error!(
                TemporarilyUnavailable,
                "holder PCR authority is unavailable"
            )
        })
}

pub(crate) async fn read_current(
    state: &AppState,
    request: &arkret_models_collaboration::consent_operations::ConsentCurrentReadRequestBody,
) -> Result<
    arkret_models_collaboration::consent_operations::ConsentCurrentReadOutcome,
    crate::error::AppError,
> {
    use arkret_models_collaboration::consent_operations::*;
    request
        .validate()
        .map_err(|e| crate::error::AppError::param_invalid(e.to_string()))?;
    let authority = holder_authority(state, &request.holder_account_id).await?;
    if authority.service_id != state.service_core_id() {
        let body = arkret_canonical::canonical_json_bytes(request)
            .map_err(|e| crate::error::AppError::internal(e.to_string()))?;
        let response = crate::routing::federation::outbox::signed_peer_request(
            state,
            authority.service_id.as_str(),
            "/_arkret/peer/consent/current",
            &body,
            16 * 1024 * 1024,
        )
        .await
        .map_err(|e| crate::app_error!(TemporarilyUnavailable, e))?;
        if !(200..300).contains(&response.status) {
            return Err(crate::app_error!(
                TemporarilyUnavailable,
                "current authority refused the holder read"
            ));
        }
        let outcome: ConsentCurrentReadOutcome = serde_json::from_slice(&response.body)
            .map_err(|e| crate::error::AppError::internal(e.to_string()))?;
        let key = crate::routing::federation::verifying_key_for_service_id(
            state,
            authority.service_id.as_str(),
            outcome.proof.verification_method.as_str(),
            true,
        )
        .await?;
        arkret_signatures::call_invitation::verify_consent_current_read(
            &outcome,
            request,
            &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                bytes: key.to_bytes().to_vec(),
            },
            Utc::now(),
        )
        .map_err(|e| crate::error::AppError::capability_denied(e.to_string()))?;
        let after = holder_authority(state, &request.holder_account_id).await?;
        if after != authority
            || outcome.governance_generation != authority.generation
            || outcome.realm_id != authority.realm_id
        {
            return Err(crate::app_error!(
                TemporarilyUnavailable,
                "holder authority changed during read"
            ));
        }
        return Ok(outcome);
    }
    let cut = state
        .persistence()
        .read_consent_current(request, &state.service_core_id())
        .await
        .map_err(|e| crate::routing::identity::consent::consent_error(e.into()))?
        .ok_or_else(|| {
            crate::app_error!(TemporarilyUnavailable, "holder current cut is unavailable")
        })?;
    let mut outcome = ConsentCurrentReadOutcome {
        request_digest: request
            .digest()
            .map_err(|e| crate::error::AppError::internal(e.to_string()))?,
        realm_id: cut.realm_id,
        governance_generation: cut.governance_generation,
        effective_stream_head: cut.effective_stream_head,
        consents: cut
            .records
            .into_iter()
            .map(|r| ConsentCurrentRow {
                selector: ConsentCurrentSelector {
                    kind: ConsentCurrentKind::Consent,
                    consent_id: r.value.consent_id.clone(),
                },
                source_stream_ref: r.commit.stream_ref.clone(),
                revision: r.view().revision,
                value: r.value,
            })
            .collect(),
        evaluated_at: cut.evaluated_at,
        expires_at: cut.evaluated_at + chrono::Duration::seconds(30),
        proof: ConsentCurrentReadProof {
            verification_method: arkret_wire::DidUrl::new(
                crate::routing::federation::federation_service_signature_key_id(
                    state.service_did().as_str(),
                ),
            )
            .map_err(|e| crate::error::AppError::internal(format!("{e}")))?,
            jws: String::new(),
        },
    };
    arkret_signatures::call_invitation::sign_consent_current_read(
        &mut outcome,
        state.notary_signing_key().as_ref(),
    )
    .map_err(|e| crate::error::AppError::internal(e.to_string()))?;
    let after = holder_authority(state, &request.holder_account_id).await?;
    if after != authority
        || outcome.realm_id != authority.realm_id
        || outcome.governance_generation != authority.generation
    {
        return Err(crate::app_error!(
            TemporarilyUnavailable,
            "holder authority changed during read"
        ));
    }
    outcome
        .validate_for_request(request, Utc::now())
        .map_err(|e| crate::error::AppError::capability_denied(e.to_string()))?;
    Ok(outcome)
}

pub(crate) async fn submit(
    state: &AppState,
    session: &SessionIdentityState,
    request: &EventAdmissionSubmission,
) -> ServiceResult<ConsentAdmissionOutcome> {
    validate_submission(request)?;
    super::authority_producer_validation::verify_self_event_producer_key(
        state,
        session,
        &request.event,
    )
    .await?;
    commit(state, request).await
}

/// The independently authenticated MIMI transport carries the exact holder
/// Event. Its accepted device is verified directly; no session is fabricated.
pub(crate) async fn submit_mimi(
    state: &AppState,
    request: &EventAdmissionSubmission,
) -> ServiceResult<ConsentAdmissionOutcome> {
    validate_submission(request)?;
    super::authority_producer_validation::verify_mimi_binding_producer(state, &request.event)
        .await?;
    commit(state, request).await
}

fn validate_submission(request: &EventAdmissionSubmission) -> ServiceResult<()> {
    request
        .validate()
        .map_err(|e| ServiceError::SchemaViolation(e.to_string()))?;
    if request.approval_signatures.is_some()
        || !matches!(
            request.event.kind,
            arkret_wire::EventKind::ConsentGrant | arkret_wire::EventKind::ConsentRevoke
        )
    {
        return Err(ServiceError::SchemaViolation(
            "invalid Consent submission".into(),
        ));
    }
    Ok(())
}

async fn commit(
    state: &AppState,
    request: &EventAdmissionSubmission,
) -> ServiceResult<ConsentAdmissionOutcome> {
    let method = arkret_wire::DidUrl::new(
        crate::routing::federation::federation_service_signature_key_id(
            state.service_did().as_str(),
        ),
    )
    .map_err(|e| ServiceError::Internal(e.to_string()))?;
    let transaction = state
        .authority_commits()
        .prepare_self_event_transaction(
            &request.event,
            &state.service_core_id(),
            method,
            state.notary_signing_key().as_ref(),
            Utc::now(),
        )
        .await?;
    let outcome = state
        .persistence()
        .admit_consent(ConsentAdmissionWrite { transaction })
        .await?;
    if let ConsentAdmissionOutcome::Committed(record) = &outcome
        && let Some(update) = &record.quarantine_update
    {
        use crate::routing::identity::device_messages::{
            ActorPrivateAccountDataOperation, ActorPrivateAccountDataUpdate,
            ActorPrivateDeviceUpdate, fanout_actor_private_update, station_device_message_sender,
        };
        let holder = request.event.actor_id.as_account_id().ok_or_else(|| {
            ServiceError::Internal("committed Consent holder is not an Account".into())
        })?;
        fanout_actor_private_update(
            state,
            holder.principal_id.as_str(),
            ActorPrivateDeviceUpdate::AccountData {
                sender: station_device_message_sender(state),
                content: ActorPrivateAccountDataUpdate {
                    operation: ActorPrivateAccountDataOperation::Put,
                    account_data_key: update.account_data_key.clone(),
                    revision: update.revision,
                    content: Some(update.payload.clone()),
                    updated_at: update.updated_at,
                },
                created_at: update.updated_at,
            },
        )
        .await;
    }
    Ok(outcome)
}
