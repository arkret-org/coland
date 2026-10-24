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
    if !matches!(
        K::KIND,
        EventKind::MessageCreate | EventKind::SelfModerationReport
    ) {
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

pub(crate) async fn mimi_reporter_device_guard(
    state: &AppState,
    body: &arkret_models_collaboration::mimi_operations::MimiReportAbuseRequestBody,
) -> ServiceResult<coland_storage::DeviceRevocationGateSelector> {
    let account = body
        .reporter_authority
        .actor_id
        .as_account_id()
        .ok_or_else(|| ServiceError::Conflict("MIMI reporter must be a full Account".into()))?;
    let bytes = body
        .reporter_authority_binding_bytes()
        .map_err(|e| ServiceError::SchemaViolation(e.to_string()))?;
    let signature = &body.reporter_authority.proof;
    if signature.payload_digest
        != body
            .payload_digest()
            .map_err(|e| ServiceError::SchemaViolation(e.to_string()))?
        || signature.created_at > chrono::Utc::now() + chrono::Duration::seconds(30)
        || chrono::Utc::now() - signature.created_at > chrono::Duration::minutes(5)
        || body.reporter_authority.expires_at <= chrono::Utc::now()
        || body.reporter_authority.expires_at > signature.created_at + chrono::Duration::minutes(5)
        || !match &signature.audience {
            arkret_wire::Audience::Single(value) => value == state.service_id(),
            arkret_wire::Audience::Multiple(values) => {
                values.iter().any(|value| value == state.service_id())
            }
        }
    {
        return Err(ServiceError::Conflict(
            "MIMI reporter proof binding or validity window invalid".into(),
        ));
    }
    let proof = arkret_wire::PayloadProof {
        kind: "detached_jws".into(),
        verification_method: signature.verification_method.clone(),
        payload_digest: signature.payload_digest.clone(),
        created_at: signature.created_at,
        domain: Some(signature.domain.as_str().to_owned()),
        audience: Some(signature.audience.clone()),
        proof_purpose: None,
        jws: signature.jws.clone(),
    };
    let (key, guard) = super::authority_producer_validation::account_device_producer_key(
        state,
        account,
        &proof.verification_method,
    )
    .await?;
    arkret_signatures::verify_ed25519_detached_jws_payload_proof(&proof, &bytes, &key)
        .map_err(|e| ServiceError::Conflict(format!("MIMI reporter proof invalid: {e}")))?;
    match guard {
        SelfProducerCommitGuard::HumanDevice(selector)
        | SelfProducerCommitGuard::HumanDeviceEvidence { selector, .. } => Ok(selector),
        _ => Err(ServiceError::Conflict(
            "MIMI reporter device authority unavailable".into(),
        )),
    }
}

pub(crate) async fn commit_mimi_event(
    state: &AppState,
    event: Event,
    guard: SelfProducerCommitGuard,
    idempotency: Option<coland_services::events::IdempotentResponse>,
) -> ServiceResult<arkret_wire::AuthoritySubmitResponseBody> {
    let payload: serde_json::Value = serde_json::to_value(&event.payload)
        .map_err(|e| ServiceError::SchemaViolation(e.to_string()))?;
    let franking_replay_nonce = if event.kind == EventKind::SelfModerationReport {
        let payload: arkret_models_collaboration::events_payloads::moderation::ModerationReportPayload =
            serde_json::from_value(payload).map_err(|e| ServiceError::SchemaViolation(e.to_string()))?;
        payload
            .franking_proof
            .map(|proof| coland_storage::FrankingReplayNonceCommit {
                realm_id: event.realm_id.to_string(),
                received_by: proof.received_by,
                replay_nonce: proof.replay_nonce,
                report_event_id: event.event_id.to_string(),
                consumed_at: chrono::Utc::now(),
            })
    } else {
        None
    };
    commit_event_unit_with_idempotency(
        state,
        &EventAdmissionSubmission::new(event),
        AdmittedProducer::Local(Box::new(guard)),
        SelfEventUnitEffects {
            franking_replay_nonce,
            mls: None,
        },
        idempotency,
    )
    .await
}
