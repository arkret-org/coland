//! AKP-0008 / AKP-0009 — Agent provisioning + lifecycle surface.
//!
//! Implements the 11 agent HTTP operations gap-reported as missing
//! in coland. The handlers below stand up the cross-project HTTP contract
//! (codmin admin UI, inkson client, cotest journey vectors) ahead of the
//! deep reducer logic.
//!
//! Surfaces:
//! - `POST   /_arkret/gate/account/agent-key-pair`               —
//!   `ak.gate.account.command.pair_agent_key.v1`
//! - `POST   /_arkret/self/agents`                             —
//!   `ak.self.agent.command.provision.v1`
//! - `GET    /_arkret/self/agents`                             — `ak.self.agent.read.list.v1`
//! - `GET    /_arkret/self/agents/{id}`                        — `ak.self.agent.resource.get.v1`
//! - `POST   /_arkret/self/agents/{id}/pause`                  — `ak.self.agent.command.pause.v1`
//! - `POST   /_arkret/self/agents/{id}/resume`                 — `ak.self.agent.command.resume.v1`
//! - `POST   /_arkret/self/agents/{id}/deactivate`             —
//!   `ak.self.agent.command.deactivate.v1`
//! - `POST   /_arkret/self/agent-sidecars:ensure`              —
//!   `ak.self.agent.sidecar.command.ensure.v1`
//! - `GET    /_arkret/self/agent-sidecars[/{sidecar_id}]`      — dedicated reads
//!
//! Controller operations enforce the persisted `agent_principals.controller_principal_id`
//! binding before they mutate state or emit fan-out. Each handler appends an
//! audit-log row matching the canonical event-kind name so the existing admin /
//! federation projections stay in sync ahead of the reducer rewrite.

use std::collections::BTreeSet;

#[cfg(test)]
use arkret_identifiers::Did;
use arkret_identifiers::{BlobRef, DidCoreId, EventId, Hash, RealmId};
use arkret_models_collaboration::agent_operations::{
    AgentDeactivateRequestBody, AgentKeyPairActivationState, AgentKeyPairOutcome,
    AgentKeyPairRequestBody, AgentLifecycleOutcome, AgentLifecycleState, AgentList,
    AgentPairingBootstrap, AgentPairingResolveRequestBody, AgentPauseRequestBody, AgentPresence,
    AgentPresenceState, AgentProjection, AgentProvisionAwaitingControllerEvent,
    AgentProvisionAwaitingControllerEventStatus, AgentProvisionAwaitingDidBinding,
    AgentProvisionAwaitingDidBindingStatus, AgentProvisionAwaitingPcrGenesis,
    AgentProvisionAwaitingPcrGenesisStatus, AgentProvisionComplete, AgentProvisionCompleteStatus,
    AgentProvisionOutcome, AgentProvisionPreparePhase, AgentProvisionRequestBody, AgentReadiness,
    AgentReadinessBlocker, AgentReadinessState, AgentRenewPairingOutcome,
    AgentRenewPairingRequestBody, AgentResumeRequestBody, AgentRuntimeApprovalOutcome,
    AgentRuntimeApprovalStatusOutcome, AgentRuntimeApprovalStatusRequestBody, AgentRuntimeState,
    AgentView, KeyState,
};
use arkret_models_collaboration::agent_scope::AgentRuntimeApprovalRequestBody;
use arkret_models_collaboration::events_payloads::agent::AgentKeyScope;
use arkret_models_collaboration::governance::agent_artifacts::{GrantSnapshot, PublicKey};
use arkret_models_collaboration::governance::agent_participation::{
    AgentParticipationEntry, AgentParticipationOutcome, MAX_PARTICIPATION_REPLACE_EXPECTED_VERSION,
    ParticipationBits, ParticipationNextReplaceInput, ParticipationReplaceRequestBody,
    ParticipationScope,
};
use arkret_models_identity::validate_agent_slug;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use coland_http::error::AppError;
use coland_http::result::{JsonResult, json_ok};
use coland_services::identity::{
    AgentPairingState as AgentPrincipalRecord, SessionIdentityState as SessionRecord,
};
use ed25519_dalek::Verifier as _;
use salvo::http::StatusCode;
use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use serde_json::{Value, json};

use super::{AuthArgs, append_audit_log, now};
use crate::ids;
use crate::state::AppState;

mod dev_fanout;
use dev_fanout::{
    require_controller_principal_control_realm, submit_durable_agent_lifecycle,
    submit_provision_event,
};

mod common;
pub(crate) use common::agent_grant_within_requested_scope;
pub(crate) mod evidence;
mod lifecycle;
mod pairing;
pub(crate) use pairing::{
    accepted_active_agent_key_authorizations, accepted_agent_key_authorizations,
};
mod participation;
pub(crate) mod sidecar;

use common::*;
use lifecycle::*;
use pairing::*;
pub(crate) use participation::load_agent_participation_outcome;
use participation::*;
use sidecar::*;

const GET_AGENT_SERVICE_OPERATION: &str =
    arkret_wire::ServiceOperationId::SELF_AGENT_RESOURCE_GET_V1;
const PAIR_AGENT_KEY_SERVICE_OPERATION: &str =
    arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY_V1;

fn agent_service_signature_present(req: &Request) -> bool {
    [
        "source-service-id",
        "destination-service-id",
        "source-trust-domain",
        "destination-trust-domain",
    ]
    .into_iter()
    .any(|header| req.headers().contains_key(header))
        || (!req.headers().contains_key("authorization")
            && (req.headers().contains_key("signature-input")
                || req.headers().contains_key("signature")))
}

#[derive(Clone, Copy)]
struct VerifiedAgentServiceOperation(&'static str);

fn required_agent_service_header<'a>(req: &'a Request, name: &str) -> Result<&'a str, AppError> {
    req.headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::unauthenticated("Agent service authentication failed"))
}

fn validate_agent_service_claims(
    local_service_id: &str,
    local_service_did: &str,
    account_authority_trust_domain: &str,
    local_trust_domain: &str,
    expected_operation: &str,
    source_service_id: &str,
    destination_service_id: &str,
    source_trust_domain: &str,
    destination_trust_domain: &str,
    operation: &str,
    key_id: &str,
) -> Result<(), AppError> {
    let expected_key_id = format!("{local_service_did}#account-authority");
    if source_service_id != local_service_id
        || destination_service_id != local_service_id
        || source_trust_domain != account_authority_trust_domain
        || destination_trust_domain != local_trust_domain
        || operation != expected_operation
        || key_id != expected_key_id
    {
        return Err(AppError::unauthenticated(
            "Agent service authentication failed",
        ));
    }
    Ok(())
}

pub(super) async fn agent_projection_service_authorized(
    state: &AppState,
    req: &mut Request,
    expected_operation: &'static str,
    has_body: bool,
) -> Result<bool, AppError> {
    // The self-surface hoop verifies Service requests before session PoP.
    // Only a successful full verification can install this request-local mark.
    if let Some(verified) = req.extensions().get::<VerifiedAgentServiceOperation>() {
        return if verified.0 == expected_operation {
            Ok(true)
        } else {
            Err(AppError::unauthenticated(
                "Agent service authentication failed",
            ))
        };
    }
    // Session PoP also uses Signature headers. Service trust headers select
    // the Service branch; partial attempts never fall back to a user session.
    if !agent_service_signature_present(req) {
        return Ok(false);
    }
    if ["authorization", "dpop", "arkret-managed-device"]
        .into_iter()
        .any(|header| req.headers().contains_key(header))
    {
        return Err(AppError::unauthenticated(
            "Agent service authentication failed",
        ));
    }
    let channel = state
        .config()
        .internal_authority_channel
        .as_ref()
        .ok_or_else(|| AppError::unauthenticated("Agent service authentication failed"))?;
    let signature_input = coland_http::http_signature::parse_signature_input_header(req)
        .map_err(|_| AppError::unauthenticated("Agent service authentication failed"))?;
    validate_agent_service_claims(
        state.service_id(),
        state.service_did().as_str(),
        channel.account_authority_trust_domain().as_str(),
        state.config().trust_domain.as_str(),
        expected_operation,
        required_agent_service_header(req, "source-service-id")?,
        required_agent_service_header(req, "destination-service-id")?,
        required_agent_service_header(req, "source-trust-domain")?,
        required_agent_service_header(req, "destination-trust-domain")?,
        required_agent_service_header(req, "arkret-operation")?,
        &signature_input.key_id,
    )?;
    crate::routing::federation::verify_inbound_peer_http_signature(state, req, has_body).await?;
    req.extensions_mut()
        .insert(VerifiedAgentServiceOperation(expected_operation));
    Ok(true)
}

/// Mounted under `/_arkret/self`.
pub(super) fn protocol_router() -> Router {
    Router::new()
        .push(
            Router::with_path("agents")
                .post(provision_agent)
                .get(list_agents)
                .push(Router::with_path("{agent_id}").get(get_agent))
                .push(Router::with_path("{agent_id}/renew-pairing").post(renew_agent_pairing))
                .push(Router::with_path("{agent_id}/pause").post(pause_agent))
                .push(Router::with_path("{agent_id}/resume").post(resume_agent))
                .push(Router::with_path("{agent_id}/deactivate").post(deactivate_agent))
                .push(
                    Router::with_path("{agent_id}/participation")
                        .get(get_agent_participation)
                        .put(set_agent_participation),
                ),
        )
        .push(Router::with_path("agent-sidecars:ensure").post(ensure_sidecar))
        .push(
            Router::with_path("agent-sidecars")
                .get(list_sidecars)
                .push(Router::with_path("{sidecar_id}").get(get_sidecar)),
        )
}

/// `/_arkret/gate/account/agent-key-pair` lives under the auth router, not
/// `/_arkret/self/agents`. Registered separately in `routing::identity::auth`.
pub(crate) fn agent_key_pair_router() -> Router {
    Router::with_path("agent-key-pair").post(agent_key_pair)
}

/// Mounted under `/_arkret/open`.
pub(crate) fn open_router() -> Router {
    Router::with_path("agent-pairing")
        .push(Router::with_path("resolve").post(resolve_agent_pairing))
        .push(Router::with_path("runtime-key-requests").post(submit_agent_runtime_key_request))
        .push(
            Router::with_path("runtime-key-requests/status").post(agent_runtime_key_request_status),
        )
}

#[cfg(test)]
#[path = "agents/tests.rs"]
mod tests;

pub(crate) use pairing::{qualified_agent_scope_evidence, verify_and_retain_agent_scope_custody};
