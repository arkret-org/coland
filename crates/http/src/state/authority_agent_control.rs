//! Controller-signed Agent key renewals, revocations and Actor Profile writes.
//!
//! The authenticated controller acts under the accepted native delegation.
//! The Agent control unit freezes the Agent PCR, controller device and
//! accountability cut, then commits the Event and its registered current
//! result together. Other delegated self Event kinds keep their own gates.

use arkret_wire::{AuthorityCommitStatus, AuthoritySubmitOutcome, EventAdmissionSubmission};
use chrono::Utc;
use coland_services::identity::SessionIdentityState;
use coland_services::{ServiceError, ServiceResult};
use coland_storage::{AgentControlAdmissionOutcome, AgentControlAdmissionWrite};

use super::AppState;

pub(super) async fn submit_self_agent_controller_event(
    state: &AppState,
    session: &SessionIdentityState,
    request: &EventAdmissionSubmission,
) -> ServiceResult<AuthoritySubmitOutcome> {
    let event = &request.event;
    if !matches!(
        event.kind,
        arkret_wire::EventKind::AgentKeyAuthorize
            | arkret_wire::EventKind::AgentKeyRevoke
            | arkret_wire::EventKind::ProfileCreate
            | arkret_wire::EventKind::ProfileUpdate
    ) {
        return Err(ServiceError::Internal(
            "Agent controller admission received another Event kind".to_owned(),
        ));
    }
    arkret_event_draft::validate_event_for_submit(event)
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    if request.approval_signatures.is_some() {
        return Err(ServiceError::SchemaViolation(
            "an Agent controller Event carries no approval signatures".to_owned(),
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
            "an Agent controller Event is executed by the authenticated controller".to_owned(),
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
    let profile = matches!(
        event.kind,
        arkret_wire::EventKind::ProfileCreate | arkret_wire::EventKind::ProfileUpdate
    );
    if !profile && event.kind != arkret_wire::EventKind::AgentKeyAuthorize {
        super::authority_forward::stage_control_source(state, &transaction, origin_source.clone())
            .await?;
    }
    let write = AgentControlAdmissionWrite {
        commit: transaction,
        queued_at: committed_at,
    };
    let outcome = if event.kind == arkret_wire::EventKind::AgentKeyAuthorize {
        state
            .persistence()
            .admit_agent_same_key_renewal(write, origin_source)
            .await?
    } else {
        state
            .persistence()
            .admit_agent_control_event_with_origin(
                write,
                if profile { origin_source } else { None },
            )
            .await?
    };
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
