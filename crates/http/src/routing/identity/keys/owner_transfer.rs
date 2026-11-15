//! The existing peer directory's single finite successor-consent purpose.
use arkret_models_crypto::realm_owner_transfer::RealmOwnerTransferAcceptance;
use arkret_models_identity::AccountDeviceSignerEvidence;
use coland_services::{ServiceError, ServiceResult};

use super::*;

fn missing() -> ServiceError {
    ServiceError::Conflict(
        "temporarily_unavailable: owner-transfer successor source is unavailable".into(),
    )
}

/// C's factory. Its native store proves role, original scope ceiling, signature,
/// lifecycle and the final locked window; the HTTP layer never invents a key.
pub(super) async fn issue_current(
    state: &AppState,
    component: &RealmOwnerTransferAcceptance,
) -> ServiceResult<
    Option<(
        AccountDeviceSignerEvidence,
        arkret_wire::SignerEvidenceRef,
        Vec<arkret_wire::NonEmptyString>,
    )>,
> {
    component.validate().map_err(|_| missing())?;
    let account = component
        .intent
        .successor_account()
        .map_err(|_| missing())?;
    if account.station_id != state.service_core_id() {
        return Ok(None);
    }
    let Some((core, authorization)) = state
        .persistence()
        .prepare_owner_transfer_current(component)
        .await?
    else {
        return Ok(None);
    };
    let trust_algorithms = original_algorithms(state, &core, &authorization).await?;
    let service_resolution = Box::pin(
        crate::routing::system::service_resolution::current_authenticated_service_resolution(state),
    )
    .await
    .map_err(|_| missing())?;
    let attestation = arkret_signatures::device_projection::sign_device_projection_attestation(
        core,
        state
            .service_verification_method("notary-key")
            .map_err(|_| missing())?,
        state.notary_signing_key().as_ref(),
    )
    .map_err(|_| missing())?;
    let evidence = AccountDeviceSignerEvidence {
        device_projection_attestation: attestation,
        service_resolution,
    };
    let reference = match state
        .persistence()
        .retain_owner_transfer_current(&evidence, &authorization, component)
        .await
    {
        Ok(reference) => reference,
        Err(coland_storage::PersistenceError::Conflict(_)) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    verify(&evidence, component)?;
    Ok(Some((evidence, reference, trust_algorithms)))
}

/// This is the exact immutable native authorizer selected by prepare, not a
/// later directory facet. Its existing public algorithm ids retain their
/// canonical echo even though this purpose grants no prekey access.
async fn original_algorithms(
    state: &AppState,
    core: &arkret_models_crypto::DeviceProjectionAttestationCore,
    authorization: &arkret_wire::CommittedEventRef,
) -> ServiceResult<Vec<arkret_wire::NonEmptyString>> {
    let original = state
        .authority_commits()
        .committed_event(&authorization.event_id)
        .await?
        .ok_or_else(missing)?;
    if authorization.event_id != core.device_authorize_event_id
        || original.event.kind != arkret_wire::EventKind::DeviceAuthorize
        || original.event.event_id != authorization.event_id
        || original.commit.event_ref != authorization.event_id
        || original.commit.commit_id != authorization.commit_id
        || original.commit.stream_ref != authorization.stream_ref
        || original.commit.stream_position != authorization.stream_position
        || original.event.realm_id != *authorization.stream_ref.realm_id()
        || original.commit.realm_id != original.event.realm_id
        || original.event.actor_id != arkret_wire::ActorId::account(core.account_id.clone())
    {
        return Err(missing());
    }
    let payload: arkret_models_collaboration::events_payloads::DeviceAuthorizePayload =
        serde_json::from_value(json!(original.event.payload)).map_err(|_| missing())?;
    if payload.device_id != core.device_id
        || payload.device_public_key_did.as_str() != core.device_signing_key_did.as_str()
        || payload.hpke_key != core.hpke_key
        || payload.authorized_generation_ref != core.authorized_generation_ref
        || payload.not_before != core.authorization_window.not_before
        || payload.expires_at.flatten() != core.authorization_window.expires_at
    {
        return Err(missing());
    }
    let mut algorithms = payload.algorithms;
    algorithms.sort_by(|a, b| a.as_str().as_bytes().cmp(b.as_str().as_bytes()));
    algorithms.dedup_by(|a, b| a.as_str() == b.as_str());
    Ok(algorithms)
}

fn verify(
    evidence: &AccountDeviceSignerEvidence,
    component: &RealmOwnerTransferAcceptance,
) -> ServiceResult<()> {
    arkret_identity::account_device_signer_evidence::verify_owner_transfer_successor_evidence(
        evidence,
        &component.intent,
        &component.acceptance,
        crate::wire::now(),
    )
    .map_err(|_| missing())
}

/// A acquires exactly one C source through the registered directory purpose.
/// Remote rows retain C's original signed core; A independently acquires the
/// method-native C history and addresses its own complete wrapper.
pub(crate) async fn successor_evidence(
    state: &AppState,
    component: &RealmOwnerTransferAcceptance,
) -> ServiceResult<AccountDeviceSignerEvidence> {
    component.validate().map_err(|_| missing())?;
    let author = component
        .intent
        .actor_id
        .as_account_id()
        .ok_or_else(missing)?;
    if author.station_id != state.service_core_id() {
        return Err(missing());
    }
    let account = component
        .intent
        .successor_account()
        .map_err(|_| missing())?;
    let device = component
        .intent
        .successor_device(&component.acceptance)
        .map_err(|_| missing())?;
    if account.station_id == state.service_core_id() {
        return issue_current(state, component)
            .await?
            .map(|(evidence, ..)| evidence)
            .ok_or_else(missing);
    }
    let request = arkret_models_crypto::PeerKeysQueryRequestBody {
        request_id: arkret_wire::RequestId::new_v7_at(crate::wire::now().timestamp_millis() as u64),
        requester_account_id: Some(author.clone()),
        requester_actor_id: None,
        purpose: arkret_models_crypto::PeerKeysQueryPurpose::RealmOwnerTransferAcceptance,
        relationship_basis: arkret_models_crypto::PeerKeysRelationshipBasis::RealmMembership {
            realm_id: component
                .intent
                .payload_without_successor_acceptance
                .realm_id
                .clone(),
        },
        device_keys: vec![arkret_models_crypto::QueryAccountDeviceSelector {
            account_id: account.clone(),
            device_ids: vec![device.clone()],
        }],
        owner_transfer_acceptance: Some(component.clone()),
    };
    let outcome = super::proxy_peer_keys_query(state, &request, &account.station_id)
        .await
        .map_err(|_| missing())?;
    outcome
        .validate_for_request(&request)
        .map_err(|_| missing())?;
    let generation = outcome
        .device_generations
        .iter()
        .find(|entry| &entry.account_id == account)
        .ok_or_else(missing)?;
    let row = outcome
        .device_keys
        .iter()
        .find(|entry| &entry.account_id == account)
        .and_then(|entry| entry.device_keys.get(&device))
        .ok_or_else(missing)?;
    if !row.algorithms.is_empty() || !super::attested_row_is_current(row, generation) {
        return Err(missing());
    }
    let service_resolution =
        super::super::agents::evidence::fetch_service_resolution(state, &account.station_id, None)
            .await
            .map_err(|_| missing())?;
    let evidence = AccountDeviceSignerEvidence {
        device_projection_attestation: row.device_projection_attestation.clone(),
        service_resolution,
    };
    verify(&evidence, component)?;
    // Keep this complete independently assembled wrapper. Its archive address
    // is derived from these bytes by the actual keeper, never C's row ref.
    Ok(evidence)
}
