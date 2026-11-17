//! Local operator adapter. This module registers no network route.
use arkret_event_draft::EventPayloadExt as _;
use arkret_models_collaboration::authority_commit::{
    PeerAuthorityForwardEventRequestBody, PeerAuthoritySubmitRequestBody,
};
use arkret_models_collaboration::governance::realm_join_intake::{
    AuthorityLocatorSource, RealmJoinCandidate, RealmJoinCandidateServiceKind,
};
use arkret_wire::{
    AuthorityCommitStatus, AuthoritySubmitResponseBody, ErrorCode, EventAdmissionSubmission,
};
use coland_services::{ServiceError, ServiceResult};

use super::AppState;

fn invalid(error: impl std::fmt::Display) -> ServiceError {
    ServiceError::protocol(ErrorCode::FailedPrecondition, error)
}

/// This local TCB operation serves Organizations without a shared session. It
/// adds no HTTP route and grants no new caller identity or remote authority.
pub async fn inspect_consent(
    state: &AppState,
    request: &arkret_models_collaboration::call_invitation::ConsentCurrentReadRequestBody,
) -> ServiceResult<arkret_models_collaboration::call_invitation::ConsentCurrentReadResponseBody> {
    request.validate().map_err(invalid)?;
    let hosting = state.service_core_id();
    if request.holder_account_id.station_id != hosting
        || request.audience_actor_id != arkret_wire::ActorId::service(hosting.clone())
    {
        return Err(invalid(
            "inspection requires this exact H Account and H Service audience",
        ));
    }
    let realm = state
        .authority_commits()
        .require_accepted_organization_hosting_account(&request.holder_account_id, &hosting)
        .await?;
    // All networking is outside the PG owner transaction. The standard owner
    // verifies the G signature, original nonce/digest, current authority and cut.
    let response = crate::routing::call_admission::read_current_for_holder(state, request)
        .await
        .map_err(|error| ServiceError::protocol(error.code, error.message))?;
    let after = state
        .authority_commits()
        .require_accepted_organization_hosting_account(&request.holder_account_id, &hosting)
        .await?;
    if after != realm || response.realm_id != realm {
        return Err(invalid("inspection crossed the immutable Org source"));
    }
    response
        .validate_for_request(request, response.governance_generation, chrono::Utc::now())
        .map_err(invalid)?;
    Ok(response)
}

pub fn read_request(bytes: &[u8]) -> ServiceResult<EventAdmissionSubmission> {
    let request: PeerAuthorityForwardEventRequestBody =
        serde_json::from_slice(bytes).map_err(invalid)?;
    // The local operator supplies the original business admission. C's peer
    // evidence is always freshly issued by H before a real peer body exists.
    request.event_submission.validate().map_err(invalid)?;
    if arkret_wire::GenesisGovernance::from_genesis(&request.event_submission.event)
        .map_err(invalid)?
        != arkret_wire::GenesisGovernance::Organization
        || request.mls_group_state_material.is_some()
        || request.content_backup_sources.is_some()
        || request.producer_agent_evidence.is_some()
        || request.successor_device_evidence.is_some()
    {
        return Err(invalid(
            "local hosting input is not the standard Organization create",
        ));
    }
    if request
        .event_submission
        .event
        .account_device_producer()
        .map_err(invalid)?
        .is_none()
    {
        request.validate().map_err(invalid)?;
    }
    Ok(request.event_submission)
}

/// All origin/resolver I/O finishes before the local source transaction.
pub async fn current_sources(
    state: &AppState,
    original: &EventAdmissionSubmission,
) -> ServiceResult<(
    Vec<serde_json::Value>,
    Vec<serde_json::Value>,
    Option<arkret_models_identity::AuthenticatedServiceResolution>,
)> {
    let event = &original.event;
    if event
        .actor_id
        .as_account_id()
        .is_none_or(|account| account.station_id != state.service_core_id())
        || event
            .as_realm_create()
            .map_err(invalid)?
            .object
            .trust_domain
            .as_str()
            != state.config().trust_domain.as_str()
    {
        return Err(invalid(
            "operator input names another hosting Station or trust domain",
        ));
    }
    let initial = event
        .as_realm_create()
        .map_err(invalid)?
        .object
        .initial_resolution
        .clone()
        .ok_or_else(|| invalid("initial resolution absent"))?;
    let (history, witnesses) =
        super::authority_organization_pcr_genesis::native_history(state, &initial.did).await?;
    let producer =
        super::authority_organization_pcr_genesis::producer_service_resolution(state, event)
            .await?;
    Ok((history.raw_entries, witnesses, producer))
}

/// Construct a sendable standard carrier only after actual H-local C current
/// preparation. No caller-supplied dynamic attestation is used as authority.
pub async fn fresh_request(
    state: &AppState,
    original: &EventAdmissionSubmission,
) -> ServiceResult<PeerAuthorityForwardEventRequestBody> {
    let evidence = if original
        .event
        .account_device_producer()
        .map_err(invalid)?
        .is_some()
    {
        let resolution =
            crate::routing::system::service_resolution::current_authenticated_service_resolution(
                state,
            )
            .await
            .map_err(|error| invalid(error.message))?;
        let (method, signing) =
            super::authority_organization_pcr_genesis::governor_signer(state).await?;
        let prepared = state
            .authority_commits()
            .prepare_organization_hosting_device(original, &state.service_core_id())
            .await?
            .ok_or_else(|| invalid("actual H-local Device source unavailable"))?;
        let attestation =
            arkret_signatures::device_projection::sign_forward_device_projection_attestation(
                prepared.device,
                method,
                signing.as_ref(),
            )
            .map_err(invalid)?;
        Some(arkret_models_identity::ForwardAccountDeviceSignerEvidence {
            device_projection_attestation: attestation,
            service_resolution: resolution,
        })
    } else {
        None
    };
    PeerAuthorityForwardEventRequestBody::new(original.clone(), None, None, evidence)
        .map_err(invalid)
}

/// Send only H's already frozen original. The result and its public source
/// are independently verified by the standard authority resolver and SDK.
pub async fn submit_original(
    state: &AppState,
    request: &PeerAuthorityForwardEventRequestBody,
) -> ServiceResult<(
    AuthoritySubmitResponseBody,
    arkret_wire::RealmAuthorityBundle,
    arkret_identity::RealmAuthorityFreshness,
    arkret_identity::RealmAuthorityKeyMap,
)> {
    let event = &request.event_submission.event;
    let governor = event
        .as_realm_create()
        .map_err(invalid)?
        .object
        .governance_station_id
        .clone();
    let body = PeerAuthoritySubmitRequestBody::AuthorityForwardEvent(request.clone());
    let bytes = arkret_canonical::canonical_json_bytes(&body).map_err(invalid)?;
    let response = crate::routing::federation::outbox::submit_authority_forward(
        state,
        governor.as_str(),
        &bytes,
    )
    .await
    .map_err(|error| ServiceError::protocol(ErrorCode::TemporarilyUnavailable, error))?;
    if response.status != 200 {
        return Err(super::authority_forward::relayed_refusal(
            response.status,
            &response.body,
        ));
    }
    let outcome = super::authority_forward::relay_governance_response(&body, response)?;
    let AuthoritySubmitResponseBody::Accepted {
        status: AuthorityCommitStatus::Committed,
        commit,
    } = &outcome
    else {
        return Err(invalid(
            "G did not return its unique original Organization result",
        ));
    };
    let (bundle, freshness, keys) = certificate(state, &request.event_submission).await?;
    if bundle.genesis_event != *event || bundle.genesis_commit != *commit {
        return Err(invalid(
            "G response differs from the independently verified original Genesis",
        ));
    }
    Ok((outcome, bundle, freshness, keys))
}

/// A positive certificate is historical evidence only. Fetch errors/404 never
/// assert non-acceptance or release the Organization's unknown first choice.
pub async fn certificate(
    state: &AppState,
    original: &EventAdmissionSubmission,
) -> ServiceResult<(
    arkret_wire::RealmAuthorityBundle,
    arkret_identity::RealmAuthorityFreshness,
    arkret_identity::RealmAuthorityKeyMap,
)> {
    let event = &original.event;
    let governor = event
        .as_realm_create()
        .map_err(invalid)?
        .object
        .governance_station_id;
    let nonce = arkret_wire::Base64UrlString::new(crate::routing::call_admission::nonce())
        .map_err(invalid)?;
    // The originally chosen G is a locator. An already completed handoff may
    // relay its successor's current assertion; the original Gen0 must still
    // be exactly the one H submitted and G acknowledged.
    let candidate = RealmJoinCandidate {
        service_kind: RealmJoinCandidateServiceKind::Station,
        service_id: governor,
        endpoint_url: None,
        source: AuthorityLocatorSource::Cache,
    };
    let located = crate::routing::realm_join::resolve_verified_authority(
        state,
        &event.realm_id,
        &[candidate],
        &nonce,
    )
    .await
    .map_err(invalid)?;
    located
        .authority
        .verify_commit(&located.bundle.genesis_commit, &located.keys)
        .map_err(invalid)?;
    let freshness = arkret_identity::RealmAuthorityFreshness::new(chrono::Utc::now(), nonce);
    Ok((located.bundle, freshness, located.keys))
}
