//! Existing peer carrier for finite Organization planned handoff admission.

use arkret_models_collaboration::authority_commit::PeerAuthorityForwardEventRequestBody;
use arkret_wire::{ActorId, AuthoritySubmitResponseBody, ErrorCode};
use coland_services::authority_commit::AuthenticatedPeerContext;
use coland_services::{ServiceError, ServiceResult};

use super::{AppState, authority_organization_pcr_genesis as native};

fn invalid(error: impl std::fmt::Display) -> ServiceError {
    ServiceError::protocol(ErrorCode::FailedPrecondition, error)
}

pub(super) async fn admit_forwarded(
    state: &AppState,
    peer: &AuthenticatedPeerContext,
    request: PeerAuthorityForwardEventRequestBody,
    origin: &coland_storage::PrincipalResolutionRecord,
) -> ServiceResult<AuthoritySubmitResponseBody> {
    request.validate().map_err(invalid)?;
    let event = &request.event_submission.event;
    if event.kind != arkret_wire::EventKind::RealmGovernanceStationChange
        || event.actor_id.as_account_id() != Some(&origin.account_id)
        || event.realm_id != origin.pcr_realm_id
    {
        return Err(invalid(
            "finite change does not bind its independently accepted Org inception",
        ));
    }
    // Genesis hosting consent and a subsequent actual producer origin are
    // distinct contracts. No declaration in this body selects the peer identity.
    let source_matches = match event.actual_signer() {
        ActorId::Service { service_id } => service_id == &peer.source_service_id,
        ActorId::Account { account_id } => account_id.station_id == peer.source_service_id,
        _ => false,
    };
    if !source_matches {
        return Err(invalid(
            "authenticated Source differs from the actual executor hosting source",
        ));
    }
    if let Some(original) = state
        .authority_commits()
        .organization_pcr_governance_change_original(&request, &peer.source_service_id)
        .await?
    {
        return Ok(original);
    }
    // Native origin and independent Service resolution complete before the PG
    // authority transaction. Retained prefixes are not refreshed by a timestamp.
    let (organization, organization_witness_records) =
        native::native_history(state, &origin.projection.did).await?;
    let producer_service_resolution = native::producer_service_resolution(state, event).await?;
    let (method, key) = native::governor_signer(state).await?;
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    // Preparation alone grants no Org authority; the one registered native PG
    // unit rechecks the finite root/quorum, producer, root/head and native cut.
    let transaction = state
        .authority_commits()
        .prepare_organization_pcr_governance_change_transaction(
            event,
            &state.service_core_id(),
            method,
            key.as_ref(),
            at,
        )
        .await?;
    state
        .authority_commits()
        .admit_organization_pcr_governance_change(
            &coland_storage::OrganizationPcrGovernanceChangeAdmissionWrite {
                transaction,
                request,
                source_service_id: peer.source_service_id.clone(),
                organization_log_entries: organization.raw_entries,
                organization_witness_records,
                producer_service_resolution,
            },
        )
        .await
}
