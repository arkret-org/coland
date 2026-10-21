//! Exact caller-signed Consent submission into the PCR current unit.

use arkret_wire::EventAdmissionSubmission;
use chrono::Utc;
use coland_services::identity::SessionIdentityState;
use coland_services::{ServiceError, ServiceResult};
use coland_storage::{ConsentAdmissionOutcome, ConsentAdmissionWrite};

use super::AppState;

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

/// Local writer regression adapter; production MIMI uses native authority forwarding.
#[cfg(test)]
pub(crate) async fn submit_mimi(
    state: &AppState,
    request: &EventAdmissionSubmission,
) -> ServiceResult<ConsentAdmissionOutcome> {
    validate_submission(request)?;
    super::authority_producer_validation::verify_mimi_binding_producer(state, &request.event)
        .await?;
    commit(state, request).await
}

pub(crate) async fn submit_mimi_forward(
    state: &AppState,
    request: &EventAdmissionSubmission,
) -> ServiceResult<()> {
    validate_submission(request)?;
    // The accepting PCR verifies the original producer at its admission cut.
    // A current retry caller may use a different Device from the accepted original.
    super::authority_pcr::submit_from_host(state, request).await?;
    Ok(())
}

fn validate_submission(request: &EventAdmissionSubmission) -> ServiceResult<()> {
    request
        .validate()
        .map_err(|e| ServiceError::SchemaViolation(e.to_string()))?;
    if request.approval_signatures.is_some()
        || !matches!(request.event.kind, arkret_wire::EventKind::ConsentReplace)
    {
        return Err(ServiceError::SchemaViolation(
            "invalid Consent submission".into(),
        ));
    }
    Ok(())
}

pub(super) async fn commit(
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
    Ok(outcome)
}
