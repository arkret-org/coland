//! Original successor evidence acquisition uses the existing authenticated peer lookup.

use arkret_models_collaboration::events_payloads::realm::RealmOwnerTransferPayload;
use arkret_models_crypto::realm_owner_transfer::RealmOwnerTransferAcceptance;
use arkret_models_identity::AccountDeviceSignerEvidence;
use arkret_wire::{Event, EventKind};
use coland_services::{ServiceError, ServiceResult};
use coland_storage::OwnerTransferSuccessorSource;

use super::{AppState, temporarily_unavailable, wire_refusal};

pub(in crate::state) fn received(
    event: &Event,
    evidence: AccountDeviceSignerEvidence,
    at: chrono::DateTime<chrono::Utc>,
) -> ServiceResult<OwnerTransferSuccessorSource> {
    let payload = payload(event)?;
    let intent = payload
        .acceptance_intent(&event.scope_ref, &event.actor_id)
        .map_err(wire_refusal)?;
    arkret_identity::account_device_signer_evidence::verify_owner_transfer_successor_evidence(
        &evidence,
        &intent,
        &payload.successor_acceptance,
        at,
    )
    .map_err(|error| match error.error_code() {
        Some(arkret_wire::ErrorCode::DeviceUnauthorized) => temporarily_unavailable(
            "successor current observation is unavailable at this acceptance instant",
        ),
        code => ServiceError::protocol(
            code.unwrap_or(arkret_wire::ErrorCode::SignatureInvalid),
            error.to_string(),
        ),
    })?;
    OwnerTransferSuccessorSource::for_event(event, evidence).map_err(Into::into)
}

fn payload(event: &Event) -> ServiceResult<RealmOwnerTransferPayload> {
    if event.kind != EventKind::RealmOwnerTransfer {
        return Err(ServiceError::SchemaViolation(
            "successor evidence is confined to owner transfer".into(),
        ));
    }
    let payload: RealmOwnerTransferPayload = serde_json::from_value(serde_json::Value::Object(
        event.payload.clone().into_iter().collect(),
    ))
    .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    if payload.realm_id != event.realm_id {
        return Err(ServiceError::SchemaViolation(
            "owner transfer addresses another outer Realm".into(),
        ));
    }
    Ok(payload)
}

pub(in crate::state) async fn acquire(
    state: &AppState,
    event: &Event,
) -> ServiceResult<OwnerTransferSuccessorSource> {
    let payload = payload(event)?;
    let intent = payload
        .acceptance_intent(&event.scope_ref, &event.actor_id)
        .map_err(wire_refusal)?;
    let author = event.actor_id.as_account_id().ok_or_else(|| {
        ServiceError::SchemaViolation("owner transfer requires an Account author".into())
    })?;
    if author.station_id != state.service_core_id() {
        return Err(ServiceError::protocol(
            arkret_wire::ErrorCode::Unauthenticated,
            "only the actual author OwnStation obtains successor evidence",
        ));
    }
    let component = RealmOwnerTransferAcceptance {
        intent,
        acceptance: payload.successor_acceptance,
    };
    let evidence =
        crate::routing::identity::keys::owner_transfer_successor_evidence(state, &component)
            .await?;
    received(event, evidence, chrono::Utc::now())
}
