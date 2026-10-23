//! Prepare native evidence without making a read-side resolution authoritative.
use arkret_models_identity::{
    PrincipalResolutionProjection, PrincipalResolutionUpdatePayload,
    ResolutionMethodHistoryEvidence,
};
use arkret_wire::{AuthoritySubmitOutcome, EventAdmissionSubmission};
use coland_services::{ServiceError, ServiceResult};

use super::AppState;

pub(super) async fn commit(
    state: &AppState,
    request: &EventAdmissionSubmission,
) -> ServiceResult<AuthoritySubmitOutcome> {
    request
        .validate()
        .map_err(|e| ServiceError::SchemaViolation(e.to_string()))?;
    if request.approval_signatures.is_some() {
        return Err(ServiceError::SchemaViolation(
            "resolution update does not accept approval signatures".into(),
        ));
    }
    let event = &request.event;
    let payload: PrincipalResolutionUpdatePayload = serde_json::from_value(
        serde_json::to_value(&event.payload)
            .map_err(|e| ServiceError::SchemaViolation(e.to_string()))?,
    )
    .map_err(|e| ServiceError::SchemaViolation(e.to_string()))?;
    let projection = PrincipalResolutionProjection {
        did: payload.next.did,
        method_history_head: payload.next.method_history_head,
        version_id: payload.next.version_id,
        resolution_event_ref: event.event_id.to_string(),
        updated_at: event.created_at,
    };
    let (evidence, _) =
        crate::routing::system::principal_resolution::principal_method_history_evidence(
            state,
            &projection,
            true,
        )
        .await
        .map_err(|e| {
            ServiceError::protocol(
                arkret_wire::ErrorCode::DidMethodSuccessorInvalid,
                e.to_string(),
            )
        })?;
    let ResolutionMethodHistoryEvidence::WebvhLog {
        log_entries,
        witness_records,
        ..
    } = evidence
    else {
        return Err(ServiceError::protocol(
            arkret_wire::ErrorCode::DidMethodSuccessorInvalid,
            "resolution successor requires native WebVH history",
        ));
    };
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
    state
        .persistence()
        .admit_principal_resolution_update(coland_storage::PrincipalResolutionUpdateWrite {
            transaction,
            log_entries,
            witness_records,
        })
        .await
}
