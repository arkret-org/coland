//! Self admission of an Agent PCR genesis (key-management.md section 3.6.3).
//!
//! The controller submits the Agent's `ak.realm.create` it froze before its
//! provision, in a separate submission. The serving layer binds the
//! authenticated session to the executing controller and compares the
//! genesis against the create-locked values the provision prepare persisted;
//! the storage unit then reverse-looks-up the accepted provision declaration,
//! verifies the controller's active device at the controller PCR cut and
//! creates the Agent PCR, or writes nothing.

use arkret_event_draft::EventPayloadExt;
use arkret_wire::{AuthorityCommitStatus, AuthoritySubmitOutcome, EventAdmissionSubmission};
use chrono::Utc;
use coland_services::identity::SessionIdentityState;
use coland_services::{ServiceError, ServiceResult};
use coland_storage::{AgentPcrGenesisAdmissionOutcome, AgentPcrGenesisAdmissionWrite};

use super::AppState;

/// Whether `event` is an Agent PCR genesis, selected by its signed purpose.
pub(super) fn is_agent_pcr_genesis(event: &arkret_wire::Event) -> bool {
    event.kind == arkret_wire::EventKind::RealmCreate
        && event
            .payload
            .get("object")
            .and_then(|object| object.get("purpose"))
            .and_then(serde_json::Value::as_str)
            == Some("agent_control")
}

fn precondition(detail: &str) -> ServiceError {
    ServiceError::Conflict(format!(
        "{}: {detail}",
        coland_storage::ConflictCode::FailedPrecondition
    ))
}

pub(super) async fn submit_self_agent_pcr_genesis(
    state: &AppState,
    session: &SessionIdentityState,
    request: &EventAdmissionSubmission,
) -> ServiceResult<AuthoritySubmitOutcome> {
    let event = &request.event;
    arkret_event_draft::validate_event_for_submit(event)
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    if request.approval_signatures.is_some() {
        return Err(ServiceError::SchemaViolation(
            "an Agent PCR genesis carries no approval signatures".to_owned(),
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
            "an Agent PCR genesis is executed by the authenticated controller".to_owned(),
        ));
    }
    if let Some(original) = super::authority_self_event_unit::exact_replay(state, event).await? {
        return Ok(original);
    }
    let genesis = event
        .as_realm_create()
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?
        .object;
    if genesis.trust_domain.as_str() != state.config().trust_domain.as_str() {
        return Err(precondition("Agent PCR genesis names another trust domain"));
    }
    // The create-locked inception is the one the provision prepare pinned,
    // never a value the genesis supplies for itself.
    let agent_id = event.actor_id.signing_principal_id();
    let record = state
        .agent_pairings()
        .agent(agent_id.as_str())
        .await
        .map_err(|error| ServiceError::Internal(format!("Agent lookup failed: {error}")))?
        .ok_or_else(|| {
            ServiceError::Conflict(format!(
                "{}: the Agent has no accepted provision on this Station",
                coland_storage::ConflictCode::AgentPcrGenesisDeclarationMissing,
            ))
        })?;
    let pinned = crate::routing::identity::agent_pcr::agent_initial_resolution_for_record(&record)
        .map_err(|error| precondition(&error.message))?;
    if genesis.initial_resolution.as_ref() != Some(&pinned)
        || record.principal_control_realm_id != event.realm_id.as_str()
    {
        return Err(precondition(
            "Agent PCR genesis differs from the inception its provision pinned",
        ));
    }

    let origin_source = super::authority_forward::prepare_control_source(state, event).await?;
    let committed_at = Utc::now();
    let method = arkret_wire::DidUrl::new(
        crate::routing::federation::federation_service_signature_key_id(
            state.service_did().as_str(),
        ),
    )
    .map_err(|error| ServiceError::Internal(error.to_string()))?;
    let transaction = state.authority_commits().prepare_genesis_transaction(
        event,
        &state.service_core_id(),
        method,
        state.notary_signing_key().as_ref(),
        committed_at,
    )?;
    super::authority_forward::stage_control_source(state, &transaction, origin_source).await?;
    let outcome = state
        .persistence()
        .admit_agent_pcr_genesis(AgentPcrGenesisAdmissionWrite {
            commit: transaction,
            queued_at: committed_at,
        })
        .await?;
    Ok(match outcome {
        AgentPcrGenesisAdmissionOutcome::Committed(commit) => AuthoritySubmitOutcome::Accepted {
            status: AuthorityCommitStatus::Committed,
            commit,
        },
        AgentPcrGenesisAdmissionOutcome::Duplicate(commit) => AuthoritySubmitOutcome::Accepted {
            status: AuthorityCommitStatus::Duplicate,
            commit,
        },
    })
}
