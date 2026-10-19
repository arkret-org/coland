//! Native PCR forwarding keeps the original device/root proof and atomic unit.

use arkret_models_collaboration::authority_commit::{
    PeerAuthorityForwardEventRequest, PeerAuthoritySubmitRequest,
};
use arkret_wire::{
    AuthorityCommitStatus, AuthoritySubmitOutcome, EventAdmissionSubmission, EventKind,
};
use coland_services::authority_commit::AuthenticatedPeerContext;
use coland_services::identity::SessionIdentityState;
use coland_services::{ServiceError, ServiceResult};

use super::AppState;

fn unavailable(detail: impl std::fmt::Display) -> ServiceError {
    ServiceError::Conflict(format!("temporarily_unavailable: native PCR {detail}"))
}

pub(crate) async fn admit_forwarded(
    state: &AppState,
    peer: &AuthenticatedPeerContext,
    request: &PeerAuthorityForwardEventRequest,
) -> ServiceResult<AuthoritySubmitOutcome> {
    request
        .validate()
        .map_err(|e| ServiceError::SchemaViolation(e.to_string()))?;
    let event = &request.event_submission.event;
    let origin = state
        .persistence()
        .principal_resolution_for_realm(&event.realm_id)
        .await?
        .ok_or_else(|| unavailable("inception is unavailable"))?;
    arkret_wire::GenesisGovernance::from_genesis(&origin.genesis_event)
        .and_then(|origin| origin.require_transferable())
        .map_err(|e| ServiceError::Conflict(e.to_string()))?;
    if !request.is_native_pcr_candidate()
        || origin.account_id.station_id != peer.source_service_id
        || event.actor_id.as_account_id() != Some(&origin.account_id)
        || event.executed_by.is_some()
        || request.event_submission.approval_signatures.is_some()
        || request.mls_genesis_material.is_some()
    {
        return Err(ServiceError::SchemaViolation(
            "native PCR forward does not bind the independently accepted holder inception".into(),
        ));
    }
    commit(state, &request.event_submission).await
}

pub(crate) async fn commit(
    state: &AppState,
    request: &EventAdmissionSubmission,
) -> ServiceResult<AuthoritySubmitOutcome> {
    let event = &request.event;
    if let Some(outcome) = super::authority_self_event_unit::exact_replay(state, event).await? {
        return Ok(outcome);
    }
    if !matches!(
        event.kind,
        EventKind::ConsentGrant
            | EventKind::ConsentRevoke
            | EventKind::RealmGovernanceStationChange
    ) {
        return Err(unavailable("registered native unit is not connected"));
    }
    if matches!(
        event.kind,
        EventKind::ConsentGrant | EventKind::ConsentRevoke
    ) {
        let (status, record) = match super::authority_consent::commit(state, request).await? {
            coland_storage::ConsentAdmissionOutcome::Committed(record) => {
                (AuthorityCommitStatus::Committed, record)
            }
            coland_storage::ConsentAdmissionOutcome::Duplicate(record) => {
                (AuthorityCommitStatus::Duplicate, record)
            }
        };
        return Ok(AuthoritySubmitOutcome::Accepted {
            status,
            commit: record.commit,
        });
    }
    let method = arkret_wire::DidUrl::new(
        crate::routing::federation::federation_service_signature_key_id(
            state.service_did().as_str(),
        ),
    )
    .map_err(|e| ServiceError::SchemaViolation(e.to_string()))?;
    let transaction = state
        .authority_commits()
        .prepare_self_event_transaction(
            event,
            &state.service_core_id(),
            method,
            state.notary_signing_key().as_ref(),
            chrono::Utc::now(),
        )
        .await?;
    match state
        .authority_commits()
        .admit_pcr_governance_change(&transaction)
        .await?
    {
        coland_storage::AuthorityCommitWriteOutcome::Committed => {
            Ok(AuthoritySubmitOutcome::Accepted {
                status: AuthorityCommitStatus::Committed,
                commit: transaction.commit,
            })
        }
        coland_storage::AuthorityCommitWriteOutcome::Duplicate => {
            super::authority_self_event_unit::exact_replay(state, event)
                .await?
                .ok_or_else(|| unavailable("duplicate original is missing"))
        }
        coland_storage::AuthorityCommitWriteOutcome::StaleAuthority(_) => {
            Err(unavailable("authority moved before acceptance"))
        }
    }
}

/// `None` means this is an ordinary Realm; its existing admission stays in force.
pub(crate) async fn submit_self(
    state: &AppState,
    session: &SessionIdentityState,
    request: &EventAdmissionSubmission,
) -> ServiceResult<Option<AuthoritySubmitOutcome>> {
    let event = &request.event;
    let Some(origin) = state
        .persistence()
        .principal_resolution_for_realm(&event.realm_id)
        .await?
    else {
        return Ok(None);
    };
    if !matches!(
        event.kind,
        EventKind::ConsentGrant
            | EventKind::ConsentRevoke
            | EventKind::RealmGovernanceStationChange
    ) {
        return Ok(None);
    }
    let actor = crate::routing::identity::session_actor::validated_session_actor(state, session)
        .await
        .map_err(|e| unavailable(e.to_string()))?;
    let producer = event
        .account_device_producer()
        .map_err(|e| ServiceError::SchemaViolation(e.to_string()))?
        .ok_or_else(|| {
            ServiceError::SchemaViolation(
                "native holder Event requires an actual Device producer".into(),
            )
        })?;
    if actor.as_account_id() != Some(&origin.account_id)
        || event.actor_id != actor
        || event.executed_by.is_some()
        || origin.account_id.station_id != state.service_core_id()
        || session.human_device_id().map(String::as_str) != Some(producer.device_id.as_str())
    {
        return Err(ServiceError::SchemaViolation(
            "native Event differs from the authenticated full holder and Device".into(),
        ));
    }
    submit_from_host(state, request).await.map(Some)
}

/// Caller authentication was checked by the registered self or MIMI ingress.
/// The native accepting unit independently verifies the original Device/root.
pub(crate) async fn submit_from_host(
    state: &AppState,
    request: &EventAdmissionSubmission,
) -> ServiceResult<AuthoritySubmitOutcome> {
    let event = &request.event;
    let origin = state
        .persistence()
        .principal_resolution_for_realm(&event.realm_id)
        .await?
        .ok_or_else(|| unavailable("holder inception is unavailable"))?;
    if origin.account_id.station_id != state.service_core_id()
        || event.actor_id.as_account_id() != Some(&origin.account_id)
        || event.executed_by.is_some()
        || request.approval_signatures.is_some()
    {
        return Err(ServiceError::SchemaViolation(
            "native PCR forward does not bind its exact hosting holder".into(),
        ));
    }
    let (_, service) = crate::routing::call_admission::holder_location(state, &origin.account_id)
        .await
        .map_err(|e| unavailable(e.to_string()))?;
    if service == state.service_core_id() {
        return commit(state, request).await;
    }
    state
        .authority_commits()
        .queue_event(event, crate::wire::now())
        .await?;
    state
        .authority_commits()
        .retain_forwarded_submission(
            event,
            &arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest::Event(
                request.clone(),
            ),
            crate::wire::now(),
        )
        .await?;
    let forward = PeerAuthoritySubmitRequest::AuthorityForwardEvent(
        PeerAuthorityForwardEventRequest::new(request.clone(), None, None)
            .map_err(|e| ServiceError::SchemaViolation(e.to_string()))?,
    );
    let bytes = arkret_canonical::canonical_json_bytes(&forward)
        .map_err(|e| ServiceError::SchemaViolation(e.to_string()))?;
    let response = crate::routing::federation::outbox::submit_authority_forward(
        state,
        service.as_str(),
        &bytes,
    )
    .await
    .map_err(unavailable)?;
    let outcome = super::authority_forward::relay_governance_response(&forward, response)?;
    let AuthoritySubmitOutcome::Accepted { commit, .. } = &outcome else {
        return Err(unavailable("did not return an accepted original"));
    };
    super::authority_forward::verify_forwarded_acknowledgement(state, &service, event, commit)
        .await?;
    state
        .authority_commits()
        .retain_forwarded_acceptance(event, commit, crate::wire::now())
        .await?;
    // This witness authorizes no replica read or private current.
    Ok(outcome)
}
