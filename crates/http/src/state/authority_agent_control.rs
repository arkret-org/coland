//! Self admission of `ak.agent.key.revoke` (key-management.md section 3.6).
//!
//! The controller revokes one of its Agent's runtime keys with an Event
//! authored as the Agent and executed under the controller delegation. The
//! serving layer binds the authenticated session to the executing controller;
//! the Agent control unit decides the provision binding, the controller's
//! active device, accountability, a non-terminal lifecycle and the key's
//! active authorization at the Agent PCR cut, or writes nothing.

use arkret_wire::{AuthorityCommitStatus, AuthoritySubmitOutcome, EventAdmissionSubmission};
use chrono::Utc;
use coland_services::identity::SessionIdentityState;
use coland_services::{ServiceError, ServiceResult};
use coland_storage::{AgentControlAdmissionOutcome, AgentControlAdmissionWrite};

use super::AppState;

pub(super) async fn submit_self_agent_key_revoke(
    state: &AppState,
    session: &SessionIdentityState,
    request: &EventAdmissionSubmission,
) -> ServiceResult<AuthoritySubmitOutcome> {
    let event = &request.event;
    if event.kind != arkret_wire::EventKind::AgentKeyRevoke {
        return Err(ServiceError::Internal(
            "Agent key revocation admission received another Event kind".to_owned(),
        ));
    }
    arkret_schema::validate_event_for_submit(event)
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    if request.approval_signatures.is_some() {
        return Err(ServiceError::SchemaViolation(
            "an Agent key revocation carries no approval signatures".to_owned(),
        ));
    }
    let controller =
        crate::routing::identity::session_actor::validated_session_actor(state, session)
            .await
            .map_err(|error| {
                ServiceError::Conflict(format!("authenticated Account unavailable: {error}"))
            })?;
    if event.executed_by.as_ref() != Some(&controller) {
        return Err(ServiceError::Conflict(
            "an Agent key revocation is executed by the authenticated controller".to_owned(),
        ));
    }
    if let Some(original) = super::authority_self_event_unit::exact_replay(state, event).await? {
        return Ok(original);
    }
    let origin_source = super::authority_forward::prepare_control_source(state, event).await?;
    let committed_at = Utc::now();
    let method = arkret_wire::DidUrl::new(
        crate::routing::federation::federation_service_signature_key_id(
            state.service_did().as_str(),
        ),
    )
    .map_err(|error| ServiceError::Internal(error.to_string()))?;
    let transaction = state
        .authority_commits()
        .prepare_self_event_transaction(
            event,
            &state.service_core_id(),
            method,
            state.notary_signing_key().as_ref(),
            committed_at,
        )
        .await?;
    super::authority_forward::stage_control_source(state, &transaction, origin_source).await?;
    let outcome = state
        .persistence()
        .admit_agent_control_event(AgentControlAdmissionWrite {
            commit: transaction,
            queued_at: committed_at,
        })
        .await?;
    Ok(match outcome {
        AgentControlAdmissionOutcome::Committed(commit) => AuthoritySubmitOutcome::Accepted {
            status: AuthorityCommitStatus::Committed,
            commit,
        },
        AgentControlAdmissionOutcome::Duplicate(commit) => AuthoritySubmitOutcome::Accepted {
            status: AuthorityCommitStatus::Duplicate,
            commit,
        },
    })
}

#[cfg(test)]
#[path = "authority_control_exact_replay_tests.rs"]
mod exact_replay_tests;
