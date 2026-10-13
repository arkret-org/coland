//! Private provision evidence for the subject of an ordinary grant.

use arkret_wire::{Event, EventKind};
use chrono::{DateTime, Utc};
use coland_services::{ServiceError, ServiceResult};

use super::AppState;

pub(super) async fn prepare_agent_grant_scope(
    state: &AppState,
    event: &Event,
    accepted_at: DateTime<Utc>,
) -> ServiceResult<Option<coland_storage::VerifiedAgentScopeEvidence>> {
    use arkret_models_collaboration::governance::grant_constraint::CapabilitySubject;
    if event.kind != EventKind::CapabilityGrant {
        return Ok(None);
    }
    let payload: arkret_models_collaboration::events_payloads::CapabilityGrantPayload =
        serde_json::from_value(
            serde_json::to_value(&event.payload)
                .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?,
        )
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    let CapabilitySubject::Actor(subject) = &payload.grant.subject else {
        return Ok(None);
    };
    let invalid = || {
        ServiceError::Conflict(
            coland_storage::ConflictCode::AgentRequestedScopeCommitmentInvalid.to_string(),
        )
    };
    let Some(record) = crate::routing::identity::agent_pcr::agent_record_for_actor(state, subject)
        .await
        .map_err(|_| invalid())?
    else {
        return Ok(None);
    };
    crate::routing::identity::agent_pcr::validate_effective_agent_realm_membership(
        state,
        &record,
        event.realm_id.as_str(),
        accepted_at,
    )
    .await
    .map_err(|error| match error.reason_code.as_deref() {
        Some(arkret_wire::ReasonCode::ACCOUNTABILITY_GRANT_MISSING) => ServiceError::Conflict(
            coland_storage::ConflictCode::AccountabilityGrantMissing.to_string(),
        ),
        _ => invalid(),
    })?;
    let method = arkret_wire::DidUrl::new(
        record
            .authorized_verification_method
            .clone()
            .ok_or_else(invalid)?,
    )
    .map_err(|_| invalid())?;
    let (_, authorization_ref) =
        crate::routing::identity::current_signer_evidence::current_agent_endpoint_key(
            state, subject, &method,
        )
        .await
        .map_err(|_| invalid())?;
    let guard = coland_storage::AgentEndpointGuard {
        pcr_realm_id: authorization_ref.stream_ref.realm_id().clone(),
        agent_id: subject
            .as_account_id()
            .ok_or_else(invalid)?
            .principal_id
            .clone(),
        authorization_ref,
        verification_method: method,
    };
    let evidence = state
        .qualified_agent_scope_evidence(&guard)
        .await
        .map_err(|_| invalid())?;
    if !arkret_models_collaboration::agent_scope::agent_grant_scope_within_provision(
        &evidence
            .command()
            .requested_scope_disclosure
            .requested_scope,
        &payload.grant.actions,
        &payload.grant.resources,
        &payload.grant.constraints,
    )
    .map_err(|_| invalid())?
    {
        return Err(ServiceError::Conflict(
            coland_storage::ConflictCode::AgentGrantExceedsRequestedScope.to_string(),
        ));
    }
    Ok(Some(evidence))
}
