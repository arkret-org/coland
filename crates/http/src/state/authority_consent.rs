//! Exact caller-signed Consent submission into the PCR current unit.

use arkret_wire::EventAdmissionSubmission;
use chrono::Utc;
use coland_services::identity::SessionIdentityState;
use coland_services::{ServiceError, ServiceResult};
use coland_storage::{ConsentAdmissionOutcome, ConsentAdmissionWrite};

use super::AppState;

/// Immutable acceptance witness only. The ingress must separately authorize
/// today's holder before disclosing it; this never admits or forwards a write.
pub(crate) async fn accepted_original(
    state: &AppState,
    request: &EventAdmissionSubmission,
) -> ServiceResult<Option<arkret_wire::AuthoritySubmitOutcome>> {
    validate_submission(request)?;
    super::authority_self_event_unit::validate_replay_event_identity(&request.event)?;
    let Some(queued) = state
        .authority_commits()
        .queued_event(&request.event.event_id)
        .await?
    else {
        return Ok(None);
    };
    if queued.event != request.event {
        return Err(ServiceError::Conflict(
            "duplicate_conflict: Consent original differs".into(),
        ));
    }
    let commit = if let Some(commit) = queued.committed {
        Some(commit)
    } else if let Some(attempt) = queued.forward_attempt {
        if attempt.original_submission.as_ref()
            != Some(
                &arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest::Event(
                    request.clone(),
                ),
            )
        {
            return Ok(None);
        }
        attempt.accepted_commit
    } else {
        None
    };
    let Some(commit) = commit else {
        return Ok(None);
    };
    if commit.event_ref != request.event.event_id || commit.realm_id != request.event.realm_id {
        return Err(ServiceError::SchemaViolation(
            "Consent acceptance witness differs from original".into(),
        ));
    }
    Ok(Some(arkret_wire::AuthoritySubmitOutcome::Accepted {
        status: arkret_wire::AuthorityCommitStatus::Duplicate,
        commit,
    }))
}

pub(crate) async fn require_replay_holder(
    state: &AppState,
    session: &SessionIdentityState,
    request: &EventAdmissionSubmission,
) -> ServiceResult<()> {
    super::authority_forward::validate_recovery_caller(state, session, &request.event).await?;
    let account = request.event.actor_id.as_account_id().ok_or_else(|| {
        ServiceError::SchemaViolation("Consent recovery requires an Account holder".into())
    })?;
    let device = arkret_wire::DeviceId::new(
        session
            .human_device_id()
            .ok_or_else(|| {
                ServiceError::SchemaViolation(
                    "Consent recovery requires a current holder Device".into(),
                )
            })?
            .clone(),
    )
    .map_err(|e| ServiceError::SchemaViolation(e.to_string()))?;
    let admission = state
        .persistence()
        .pcr_device_admission(account, &device, Utc::now())
        .await?;
    if let Some(refusal) = ServiceError::device_admission_refusal(
        admission,
        "Consent recovery holder Device is not current",
    ) {
        return Err(refusal);
    }
    Ok(())
}

pub(crate) async fn submit(
    state: &AppState,
    session: &SessionIdentityState,
    request: &EventAdmissionSubmission,
) -> ServiceResult<ConsentAdmissionOutcome> {
    validate_submission(request)?;
    require_replay_holder(state, session, request).await?;
    if accepted_original(state, request).await?.is_some() {
        return commit(state, request).await;
    }
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
    if accepted_original(state, request).await?.is_some() {
        return commit(state, request).await;
    }
    super::authority_producer_validation::verify_mimi_binding_producer(state, &request.event)
        .await?;
    commit(state, request).await
}

pub(crate) async fn submit_mimi_forward(
    state: &AppState,
    request: &EventAdmissionSubmission,
) -> ServiceResult<()> {
    validate_submission(request)?;
    // The MIMI ingress has authenticated today's operation proof for the
    // exact holder; the historical Event's old device may now be revoked.
    if accepted_original(state, request).await?.is_some() {
        return Ok(());
    }
    super::authority_producer_validation::verify_mimi_binding_producer(state, &request.event)
        .await?;
    super::authority_pcr::require_accepted(
        super::authority_pcr::submit_from_host(state, request).await?,
    )
    .map(|_| ())
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
