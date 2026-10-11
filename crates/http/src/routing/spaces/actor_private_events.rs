//! `ak.self.actor_private_events.command.submit.v1`
//! (`POST /_arkret/self/actor-private-events`, actor-private-effects.md §2.1).
//!
//! The one submit operation for the caller-signed actor-private kinds without
//! a dedicated operation: `ak.device.push_route`, `ak.agent.action_request`,
//! `ak.agent.action_reject` and `ak.agent.draft.propose`. The authenticated
//! caller is the Event's signing actor, the kind's
//! `storage_owner.account_id_source` selects an AccountId of this Station,
//! and the registered private effect is written with the exact-retry ledger
//! in one private transaction. No RealmCommit is produced or returned.

use std::collections::BTreeSet;

use arkret_models_collaboration::events_payloads::agent::{
    AgentActionRejectPayload, AgentActionRequestPayload, AgentDraftProposePayload,
};
use arkret_models_identity::device_push_route::DevicePushRoutePayload;
use arkret_wire::{
    AccountId, ActorId, ActorPrivateEventSubmitOutcome, ActorPrivateEventSubmitRequestBody,
    DidCoreId, Event, EventKind,
};
use coland_http::error::AppError;
use coland_storage::{
    ActorPrivateEventEffect, ActorPrivateEventRefusal, ActorPrivateEventSubmission,
    ActorPrivateEventSubmitResult, AgentDraftPendingIntentCommit, AgentDraftPendingIntentRecord,
    AgentDraftPendingIntentState,
};
use salvo::prelude::*;

use super::AuthArgs;
use crate::state::AppState;
use crate::{JsonResult, json_ok};

#[handler]
#[tracing::instrument(
    skip_all,
    fields(op = "ak.self.actor_private_events.command.submit.v1")
)]
pub(super) async fn submit_actor_private_event(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<ActorPrivateEventSubmitOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = AuthArgs.authenticated_session(state, req).await?;
    crate::routing::events::require_agent_session_scope(
        &session,
        arkret_wire::ServiceOperationId::SELF_ACTOR_PRIVATE_EVENTS_COMMAND_SUBMIT_V1,
    )?;
    let body = req
        .payload()
        .await
        .map_err(|error| crate::app_error!(JsonInvalid, "unable to read request body: {error}"))?;
    let request: ActorPrivateEventSubmitRequestBody =
        serde_json::from_slice(body).map_err(|error| {
            if error.is_data() {
                AppError::schema_violation(format!("invalid request body: {error}"))
            } else {
                crate::app_error!(JsonInvalid, "invalid request body: {error}")
            }
        })?;
    request
        .validate()
        .map_err(|error| AppError::schema_violation(format!("invalid event: {error}")))?;
    let event = request.event;
    let decoded = decode_effect(&event)?;
    let owner = decoded.owner(&event)?;
    // actor-private-effects.md §2.1: the selected owner's Station stores the
    // effect; any other owner is `param_invalid` before any other admission.
    if owner.station_id != state.service_core_id() {
        return Err(AppError::param_invalid(
            "the actor-private owner AccountId belongs to another Station",
        ));
    }
    // The caller must be the exact signing actor; a delegated or foreign
    // producer is a binding refusal.
    let producer_guard = crate::state::verify_self_event_producer(state, &session, &event)
        .await
        .map_err(crate::state::actor_private_refusal)?;
    let accepted_at = chrono::Utc::now();
    let canonical_event_digest = crate::state::canonical_event_digest(&event)
        .map_err(crate::state::actor_private_refusal)?;
    let effect = admit_effect(
        state,
        &event,
        &owner,
        decoded,
        &canonical_event_digest,
        accepted_at,
    )
    .await?;
    let submission = ActorPrivateEventSubmission {
        event,
        canonical_event_digest,
        owner,
        effect,
        producer_guard: Some(producer_guard),
        accepted_at,
    };
    let result = state
        .persistence()
        .submit_actor_private_event(&submission)
        .await
        .map_err(|error| crate::state::actor_private_refusal(error.into()))?;
    match result {
        ActorPrivateEventSubmitResult::Accepted(outcome)
        | ActorPrivateEventSubmitResult::Replayed(outcome) => json_ok(outcome),
        ActorPrivateEventSubmitResult::Refused(refusal) => Err(submit_refusal(refusal)),
    }
}

/// The typed payload of one of the four admitted kinds.
enum DecodedEffect {
    PushRoute(DevicePushRoutePayload),
    ActionRequest(AgentActionRequestPayload),
    ActionReject(AgentActionRejectPayload),
    DraftPropose(AgentDraftProposePayload),
}

impl DecodedEffect {
    /// The AccountId named by the kind's `storage_owner.account_id_source`.
    fn owner(&self, event: &Event) -> Result<AccountId, AppError> {
        match self {
            Self::PushRoute(payload) => Ok(payload.scope().account_id),
            Self::ActionRequest(payload) => Ok(payload.controller_account_id.clone()),
            Self::DraftPropose(payload) => Ok(payload.controller_account_id.clone()),
            Self::ActionReject(_) => event.actor_id.as_account_id().cloned().ok_or_else(|| {
                AppError::capability_denied(
                    "an Agent rejection is signed by its controller Account",
                )
            }),
        }
    }
}

fn decode_payload<T: serde::de::DeserializeOwned>(event: &Event) -> Result<T, AppError> {
    serde_json::to_value(&event.payload)
        .and_then(serde_json::from_value)
        .map_err(|error| {
            AppError::schema_violation(format!(
                "{} payload violates its closed schema: {error}",
                event.kind.as_str()
            ))
        })
}

fn decode_effect(event: &Event) -> Result<DecodedEffect, AppError> {
    Ok(match event.kind {
        EventKind::DevicePushRoute => DecodedEffect::PushRoute(decode_payload(event)?),
        EventKind::AgentActionRequest => DecodedEffect::ActionRequest(decode_payload(event)?),
        EventKind::AgentActionReject => DecodedEffect::ActionReject(decode_payload(event)?),
        EventKind::AgentDraftPropose => DecodedEffect::DraftPropose(decode_payload(event)?),
        _ => {
            return Err(AppError::schema_violation(
                "event.kind is not submitted through the actor-private Event operation",
            ));
        }
    })
}

/// Branch admission before the private transaction: owner binding, Agent
/// controller binding and HPKE recipient binding. Expiry, CAS and create-once
/// keys are decided inside the transaction, after exact retry.
async fn admit_effect(
    state: &AppState,
    event: &Event,
    owner: &AccountId,
    decoded: DecodedEffect,
    canonical_event_digest: &[u8],
    accepted_at: chrono::DateTime<chrono::Utc>,
) -> Result<ActorPrivateEventEffect, AppError> {
    match decoded {
        DecodedEffect::PushRoute(payload) => {
            if event.actor_id.as_account_id() != Some(owner) {
                return Err(AppError::capability_denied(
                    "the push route account differs from the verified Event account",
                ));
            }
            Ok(ActorPrivateEventEffect::DevicePushRoute(payload))
        }
        DecodedEffect::ActionRequest(payload) => {
            require_agent_signer(event, &payload.agent_id)?;
            require_agent_controller(state, &payload.agent_id, owner, accepted_at).await?;
            if payload.expires_at <= payload.created_at {
                return Err(AppError::param_invalid(
                    "the action request expires_at must follow created_at",
                ));
            }
            Ok(ActorPrivateEventEffect::AgentActionRequest(payload))
        }
        DecodedEffect::ActionReject(payload) => {
            let request_id = payload.request_id.clone();
            require_agent_controller(state, &payload.agent_id, owner, accepted_at).await?;
            Ok(ActorPrivateEventEffect::AgentActionReject {
                payload,
                request_id,
            })
        }
        DecodedEffect::DraftPropose(payload) => {
            require_agent_signer(event, &payload.agent_id)?;
            require_agent_controller(state, &payload.agent_id, owner, accepted_at).await?;
            if payload.expires_at <= payload.created_at {
                return Err(AppError::param_invalid(
                    "the draft proposal expires_at must follow created_at",
                ));
            }
            require_controller_recipients(state, owner, &payload).await?;
            let record = AgentDraftPendingIntentRecord {
                controller_account_id: owner.clone(),
                agent_id: payload.agent_id.clone(),
                draft_id: payload.draft_id.clone(),
                proposed_action: payload.proposed_action.clone(),
                target: serde_json::to_value(&payload.target)
                    .map_err(|error| AppError::internal(error.to_string()))?,
                content_digest: payload.content_digest.clone(),
                content_handoff: Some(
                    serde_json::to_value(&payload.content_handoff)
                        .map_err(|error| AppError::internal(error.to_string()))?,
                ),
                canonical_event_digest: arkret_wire::Hash::new(format!(
                    "sha256:{}",
                    canonical_event_digest
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>()
                ))
                .map_err(|error| AppError::internal(error.to_string()))?,
                accepted_event_id: event.event_id.clone(),
                expires_at: payload.expires_at,
                created_at: payload.created_at,
                state: AgentDraftPendingIntentState::Available,
                consumption: None,
                expired_at: None,
            };
            Ok(ActorPrivateEventEffect::AgentDraftPropose(
                AgentDraftPendingIntentCommit { record },
            ))
        }
    }
}

/// An Agent request or proposal is signed by the Agent's own AccountId.
fn require_agent_signer(event: &Event, agent_id: &DidCoreId) -> Result<(), AppError> {
    if event
        .actor_id
        .as_account_id()
        .is_none_or(|account| &account.principal_id != agent_id)
    {
        return Err(AppError::capability_denied(
            "the Agent Event signer is not payload.agent_id",
        ));
    }
    Ok(())
}

/// The Agent is active and its current accepted controller is exactly
/// `controller`.
async fn require_agent_controller(
    state: &AppState,
    agent_id: &DidCoreId,
    controller: &AccountId,
    accepted_at: chrono::DateTime<chrono::Utc>,
) -> Result<(), AppError> {
    let record = state
        .agent_pairings()
        .agent(agent_id.as_str())
        .await
        .map_err(|error| AppError::internal(format!("Agent lookup failed: {error}")))?
        .ok_or_else(|| AppError::capability_denied("the Agent has no controller binding"))?;
    if record.state != arkret_models_collaboration::agent_operations::AgentLifecycleState::Active {
        return Err(AppError::capability_denied(
            "the Agent lifecycle is not active",
        ));
    }
    let bound = crate::routing::identity::agent_pcr::agent_controller_account(state, &record)
        .await
        .map_err(|_| AppError::capability_denied("the Agent controller binding is unavailable"))?;
    if &bound != controller {
        return Err(AppError::capability_denied(
            "the Agent controller binding differs from the named controller",
        ));
    }
    crate::routing::identity::agent_pcr::validate_agent_controller_binding(
        state,
        &record,
        accepted_at,
    )
    .await
    .map_err(|error| AppError::capability_denied(error.message))
}

/// Every HPKE recipient is a distinct, currently accepted device of the exact
/// controller AccountId, and `recipient_hpke_key_digest` is the SHA-256 of
/// that device's current `hpke_key` exactly as carried.
async fn require_controller_recipients(
    state: &AppState,
    controller: &AccountId,
    payload: &AgentDraftProposePayload,
) -> Result<(), AppError> {
    let actor = ActorId::account(controller.clone());
    let mut seen = BTreeSet::new();
    for recipient in &payload.content_handoff.recipients {
        if !seen.insert(recipient.recipient_device_id.as_str()) {
            return Err(AppError::param_invalid(
                "content_handoff recipients repeat a device",
            ));
        }
        let facet =
            crate::routing::identity::device_signing::try_resolve_device_signing_directory_facet(
                state,
                controller.principal_id.as_str(),
                recipient.recipient_device_id.as_str(),
            )
            .await
            .map_err(|error| AppError::internal(error.to_string()))?;
        let authorization = crate::routing::identity::device_signing::current_device_authorization(
            state,
            &actor,
            &recipient.recipient_device_id,
            &facet,
        )
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| {
            AppError::param_invalid(
                "a content_handoff recipient is not an accepted controller device",
            )
        })?;
        if arkret_canonical::sha256_digest(authorization.hpke_key.as_str().as_bytes())
            != recipient.recipient_hpke_key_digest.as_str()
        {
            return Err(AppError::param_invalid(
                "a content_handoff recipient_hpke_key_digest is not the device's current HPKE key",
            ));
        }
    }
    Ok(())
}

fn submit_refusal(refusal: ActorPrivateEventRefusal) -> AppError {
    match refusal {
        ActorPrivateEventRefusal::DuplicateConflict(detail) => {
            crate::app_error!(DuplicateConflict, "{detail}")
        }
        ActorPrivateEventRefusal::CasConflict => crate::app_error!(
            CasConflict,
            "expected_server_revision is not the current push route revision"
        ),
        ActorPrivateEventRefusal::FailedPrecondition(detail) => {
            crate::app_error!(FailedPrecondition, "{detail}")
        }
    }
}
