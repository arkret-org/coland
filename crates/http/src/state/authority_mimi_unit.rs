//! Service-authored MIMI Events, using the durable Service identity and native unit.
use arkret_wire::{ActorId, Event, EventAdmissionSubmission, EventKind, ScopeRef};
use coland_services::{ServiceError, ServiceResult};
use coland_storage::SelfProducerCommitGuard;

use super::AppState;
use super::authority_self_event_unit::{
    AdmittedProducer, SelfEventUnitEffects, commit_event_unit_with_idempotency,
};

pub(crate) async fn author_mimi_event<K: arkret_event_draft::EventSpec>(
    state: &AppState,
    scope: ScopeRef,
    payload: K::Payload,
) -> ServiceResult<Event> {
    if !matches!(K::KIND, EventKind::MessageCreate) {
        return Err(ServiceError::SchemaViolation(
            "unsupported MIMI service Event".into(),
        ));
    }
    let (_, method) = state
        .current_service_receipt_binding()
        .await
        .map_err(ServiceError::internal)?;
    let actor = ActorId::service(state.service_core_id());
    let created_at = chrono::Utc::now();
    let mut draft = arkret_event_draft::TypedEventDraft::<K>::new(scope, actor, payload)
        .map_err(|e| ServiceError::SchemaViolation(e.to_string()))?
        .author_with_digest_suite(created_at, arkret_canonical::DigestSuite::Sha256)
        .map_err(|e| ServiceError::SchemaViolation(e.to_string()))?;
    let signer = arkret_signatures::Ed25519PayloadSigner::new(
        state.notary_signing_key().as_ref().clone(),
        state.service_did(),
        method,
    );
    arkret_signatures::sign_event(
        &mut draft,
        &signer,
        arkret_signatures::SignEventOptions::new().with_created_at(created_at),
    )
    .map_err(|e| ServiceError::SchemaViolation(e.to_string()))?;
    Ok(draft.into_event())
}

pub(crate) async fn commit_mimi_event(
    state: &AppState,
    event: Event,
    guard: SelfProducerCommitGuard,
    idempotency: Option<coland_services::events::IdempotentResponse>,
) -> ServiceResult<arkret_wire::AuthoritySubmitResponseBody> {
    commit_event_unit_with_idempotency(
        state,
        &EventAdmissionSubmission::new(event),
        AdmittedProducer::Local(Box::new(guard)),
        SelfEventUnitEffects::default(),
        idempotency,
    )
    .await
}
