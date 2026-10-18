#![deny(unsafe_code)]
#![recursion_limit = "512"]
#![allow(clippy::too_many_arguments, clippy::type_complexity)]

extern crate self as coland_http;

// Construct child futures outside a large enclosing poll frame.
#[inline(never)]
pub(crate) fn boxed_future<F, Fut>(make: F) -> std::pin::Pin<Box<Fut>>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future,
{
    Box::pin(make())
}

pub mod account_erasure_worker;
mod approval_admission;
pub mod authz;
pub mod canonical_body;
pub mod config;
pub mod content_encoding;
pub mod deactivation_push_fanout;
pub mod error;
pub mod failpoints;
pub mod http_signature;
pub mod ids;
mod invite_claim_admission;
#[cfg(test)]
mod invite_claim_proofs;
pub mod jws_verify;
pub mod metrics;
pub mod openapi;
pub mod openapi_routes;
mod principal_control;
pub mod push_gateway_registry;
pub mod ratelimit;
pub mod result;
pub mod routing;
pub mod runtime_settings;
pub mod security;
pub mod security_rotation_worker;
pub mod state;
mod test_material_admission;
pub mod util;
pub mod verified_profiles;
pub mod wire;
pub mod wire_validators;

pub mod webvh_validation {
    pub use crate::routing::identity::webvh_validation::{
        WebvhLogEntry, validate_log_chain, validate_rotation_authorization_for_log,
        validate_witness_policy_for_log, verify_log_and_witness_bytes, verify_log_subject,
        verify_scid_against_did, verify_webvh_log_proof,
    };
}

pub use error::AppError;
pub use result::{AppResult, EmptyOutcome, EmptyResult, JsonResult, empty_ok, json_ok};
pub use routing::{
    router, router_with_rate_limiter_and_request_size_config, router_with_rate_limiter_config,
};

#[cfg(test)]
pub(crate) fn canonical_value_digest(value: &serde_json::Value) -> Option<String> {
    arkret_canonical::canonical_sha256(value).ok()
}

#[cfg(test)]
pub(crate) fn test_actor_id(did: &arkret_identifiers::Did) -> arkret_identifiers::DidCoreId {
    arkret_identifiers::project_did_to_core_id(did)
        .expect("test did must project to an Actor core_id")
}

#[cfg(test)]
pub(crate) fn test_actor_id_str(did: &str) -> arkret_identifiers::DidCoreId {
    let did =
        arkret_identifiers::Did::new(did.to_owned()).expect("test actor must be an explicit DID");
    test_actor_id(&did)
}

#[cfg(test)]
pub(crate) fn test_account_actor(did: &arkret_identifiers::Did) -> arkret_wire::ActorId {
    arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        test_actor_id(did),
        test_event::station_id(),
    ))
}

use salvo::catcher::Catcher;
use salvo::prelude::{CatchPanic, Service};

use crate::ratelimit::RateLimiterConfig;
use crate::routing::{cors_handler_for_origin_spec, error_catcher};
use crate::state::AppState;

fn finish_service(router: salvo::Router, cors_allow_origin: Option<String>) -> Service {
    let mut service = Service::new(router);
    if let Some(origin) = cors_allow_origin {
        service = service.hoop(cors_handler_for_origin_spec(&origin));
    }
    service = service.hoop(CatchPanic::new());
    service.catcher(Catcher::default().hoop(error_catcher))
}

pub fn service(state: AppState) -> Service {
    let cors_allow_origin = state.config().cors_allow_origin.clone();
    finish_service(router(state), cors_allow_origin)
}

pub fn service_with_rate_limiter_config(
    state: AppState,
    rate_limiter_config: RateLimiterConfig,
) -> Service {
    let cors_allow_origin = state.config().cors_allow_origin.clone();
    finish_service(
        router_with_rate_limiter_config(state, rate_limiter_config),
        cors_allow_origin,
    )
}

pub fn service_with_request_size_limit(state: AppState, max_request_size_bytes: usize) -> Service {
    let cors_allow_origin = state.config().cors_allow_origin.clone();
    finish_service(
        router_with_rate_limiter_and_request_size_config(
            state,
            RateLimiterConfig::default(),
            max_request_size_bytes,
        ),
        cors_allow_origin,
    )
}

#[cfg(test)]
pub(crate) mod test_event {
    use arkret_identifiers::{DidCoreId, Hlc};
    use arkret_test_kit::proof::StructuralOnlyPayloadSigner;
    use arkret_wire::{Did, DidUrl, Event, Result, ScopeRef};
    use chrono::{DateTime, Utc};
    use serde_json::Value;

    pub(crate) fn station_id() -> DidCoreId {
        super::test_actor_id_str(
            "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:coland.local:webvh:service",
        )
    }

    pub fn raw_event(
        kind: impl Into<String>,
        scope_ref: ScopeRef,
        actor_id: DidCoreId,
        _fixture_index: u64,
        _hlc: Hlc,
        payload: Value,
    ) -> Result<Event> {
        arkret_wire::test_support::raw_event(kind, scope_ref, actor_id, station_id(), payload)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn raw_event_at(
        kind: impl Into<String>,
        scope_ref: ScopeRef,
        actor_id: DidCoreId,
        _fixture_index: u64,
        _hlc: Hlc,
        payload: Value,
        created_at: DateTime<Utc>,
    ) -> Result<Event> {
        arkret_wire::test_support::raw_event_at(
            kind,
            scope_ref,
            actor_id,
            station_id(),
            payload,
            created_at,
        )
    }

    /// Attach a proof that binds the Event digest but carries no key material.
    ///
    /// Every caller stores the result straight into durable storage and then
    /// exercises a read, query or stream path; none of them reaches admission,
    /// so no signature is ever verified and a real one would assert something
    /// the case does not establish. The name says which of the two fidelities
    /// this is, and the placeholder comes from the shared test-kit signer,
    /// whose JWS tracks the covered bytes -- a constant literal here would
    /// survive a payload edit and pin nothing.
    pub fn attach_structural_only_producer_proof(event: &mut Event, verification_method: DidUrl) {
        let signer_did = Did::new(
            verification_method
                .as_str()
                .split('#')
                .next()
                .expect("a DID URL has a subject")
                .to_owned(),
        )
        .expect("fixture verification method has a DID subject");
        let signer = StructuralOnlyPayloadSigner::new(signer_did, verification_method.clone());
        *event = arkret_test_kit::sign_structural_only_event(
            event.clone(),
            &signer,
            arkret_canonical::DigestSuite::Sha256,
        )
        .expect("structural-only fixture proof attaches")
        .expect_structural_only();
    }
}

/// Exercise only the mounted managed Device authentication hoop with an echo.
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub fn test_applet_managed_device_authentication_service(state: AppState) -> salvo::Service {
    crate::routing::identity::applet_managed_device::test_service(state)
}

/// Rebuild the production accepted PCR history without creating a Device.
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub async fn test_accepted_device_generation_commit_head(
    state: &crate::state::AppState,
    principal_id: &str,
    realm_id: &arkret_wire::RealmId,
) -> coland_services::ServiceResult<Option<arkret_wire::CommitStreamHead>> {
    crate::routing::identity::device_generation::accepted_device_generation_commit_head(
        state,
        principal_id,
        realm_id,
    )
    .await
}

/// Exercise the production current-device selector after a committed PCR unit.
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub async fn test_active_device_revocation_gate_selector(
    state: &crate::state::AppState,
    principal_id: &str,
    device_id: &str,
) -> coland_services::ServiceResult<coland_storage::DeviceRevocationGateSelector> {
    crate::routing::identity::device_generation::active_device_revocation_gate_selector(
        state,
        principal_id,
        device_id,
    )
    .await
}

/// Sign and retain the fresh `producer_device_evidence` that one forwarding
/// attempt of `event` carries (device-lifecycle §8.2.2).
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub async fn test_fresh_producer_device_evidence(
    state: &crate::state::AppState,
    event: &arkret_wire::Event,
    destination: &arkret_wire::DidCoreId,
) -> coland_services::ServiceResult<
    Option<arkret_models_identity::ForwardAccountDeviceSignerEvidence>,
> {
    let request = arkret_models_collaboration::authority_commit::PeerAuthorityForwardEventRequest {
        branch:
            arkret_models_collaboration::authority_commit::AuthorityForwardBranch::AuthorityForward,
        event_submission: arkret_wire::EventAdmissionSubmission::new(event.clone()),
        mls_genesis_material: None,
        producer_device_evidence: None,
        producer_managed_provenance: None,
        producer_agent_evidence: None,
    };
    let digest =
        arkret_models_collaboration::authority_commit::authority_forward_body_digest(&request)
            .map_err(|e| coland_services::ServiceError::SchemaViolation(e.to_string()))?;
    crate::state::fresh_producer_device_evidence(state, event, destination, &digest).await
}

/// Exercise the forwarding-Station preflight and queue boundary through the
/// same function used by the self Event route.
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub async fn test_forward_self_event(
    state: &crate::state::AppState,
    governance: &arkret_wire::DidCoreId,
    submission: arkret_wire::EventAdmissionSubmission,
) -> coland_services::ServiceResult<arkret_wire::AuthoritySubmitOutcome> {
    crate::state::forward_self_event(state, governance, submission).await
}

/// Governance-Station admission of one `authority_forward` at an explicit
/// service clock instant (device-lifecycle §8.2.2).
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub async fn test_admit_authority_forward(
    state: &crate::state::AppState,
    peer: &coland_services::authority_commit::AuthenticatedPeerContext,
    request: arkret_models_collaboration::authority_commit::PeerAuthorityForwardEventRequest,
    now: chrono::DateTime<chrono::Utc>,
) -> coland_services::ServiceResult<arkret_wire::AuthoritySubmitOutcome> {
    crate::state::admit_forwarded_event(state, peer, request, now).await
}

/// Produce a portable Agent context through the real verifier for SDK regression fixtures.
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub async fn test_verified_agent_context_fixture(
    state: &crate::state::AppState,
    actor: arkret_wire::ActorId,
    verification_method: arkret_wire::DidUrl,
    realm_id: arkret_wire::RealmId,
    recipient_account_id: arkret_wire::AccountId,
) -> Result<serde_json::Value, String> {
    let selector = crate::routing::identity::agents::evidence::AgentSignerEvidenceQuerySelector::CurrentAdmission {
        actor: actor.clone(), verification_method: verification_method.clone(),
    };
    let (root, dependencies) =
        crate::routing::identity::agents::evidence::current_authenticated_agent_signer_evidence(
            state, &selector,
        )
        .await
        .map_err(|error| format!("{error:?}"))?;
    Ok(
        serde_json::json!({"actor":actor,"verification_method":verification_method,"realm_id":realm_id,
        "recipient_account_id":recipient_account_id,"root":root,"dependencies":dependencies}),
    )
}

/// Exercise the real Agent Origin assembler, registered gate client and same-cut retention.
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub async fn test_fresh_producer_agent_evidence(
    state: &crate::state::AppState,
    event: &arkret_wire::Event,
) -> coland_services::ServiceResult<Option<arkret_models_identity::AgentProducerEvidence>> {
    crate::state::fresh_producer_agent_evidence(state, event).await
}
