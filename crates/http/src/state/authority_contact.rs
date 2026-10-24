//! Guarded admission of the five `ak.contact.*` Event kinds.
//!
//! contact-and-direct-conversation.md sections 2 and 3.1: the holder's exact
//! signed Contact Event is admitted by the current governing Station of the
//! holder's PCR in one PostgreSQL transaction together with its successor
//! `RealmCommit`, the holder-private Contact row (request-slot CAS, lineage
//! head and scopes) and the frozen completion intent from which the source
//! receipts, lineage and current proofs are later signed. The row CAS and the
//! slot transcript are recomputed from the row that transaction locks; any
//! failure leaves zero writes. Contact kinds are not reducer inputs, so no
//! in-process projection is consulted or advanced.

use arkret_models_collaboration::contact_operations::ContactProducerSigner;
use arkret_wire::{
    AuthorityCommitStatus, AuthoritySubmitResponseBody, Event, EventAdmissionSubmission,
};
use coland_services::identity::SessionIdentityState;
use coland_services::{ServiceError, ServiceResult};
use coland_storage::SelfProducerCommitGuard;

use super::AppState;

/// The holder's verified producer: the guard the accepting transaction
/// rechecks and the exact key/method descriptor frozen into every Contact
/// carrier of this Event.
pub(crate) struct ContactProducer {
    pub(crate) guard: SelfProducerCommitGuard,
    pub(crate) signer: ContactProducerSigner,
}

/// Verify the Contact Event's producer against the authenticated session.
///
/// A controller-device signature on behalf of an owned Agent (`executed_by`)
/// needs the Agent's authenticated native delegation locator, which this
/// Station does not yet freeze at admission; that branch stays closed.
pub(crate) async fn verify_contact_producer(
    state: &AppState,
    session: &SessionIdentityState,
    event: &Event,
) -> ServiceResult<ContactProducer> {
    if !is_contact_kind(&event.kind) {
        return Err(ServiceError::SchemaViolation(
            "Contact admission received another Event kind".to_owned(),
        ));
    }
    let (guard, key) =
        super::authority_producer_validation::verify_self_event_producer_key(state, session, event)
            .await?;
    let key = key
        .ed25519_bytes()
        .map_err(|error| ServiceError::Conflict(format!("Contact producer key: {error}")))?;
    let proof = event
        .producer_proof
        .as_ref()
        .ok_or_else(|| ServiceError::SchemaViolation("Contact Event has no producer".into()))?;
    let signer = ContactProducerSigner::direct(
        proof.verification_method.clone(),
        arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(key))
            .map_err(|error| ServiceError::Internal(error.to_string()))?,
    )
    .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    Ok(ContactProducer { guard, signer })
}

fn is_contact_kind(kind: &arkret_wire::EventKind) -> bool {
    matches!(
        kind,
        arkret_wire::EventKind::ContactRequested
            | arkret_wire::EventKind::ContactAccepted
            | arkret_wire::EventKind::ContactRejected
            | arkret_wire::EventKind::ContactScopeUpdate
            | arkret_wire::EventKind::ContactTombstone
    )
}

/// Admit one producer-verified Contact Event with its Contact effect.
///
/// `projection` carries the planned row and the completion intent whose
/// acceptance time is `accepted_at`; the covering Commit is signed at the same
/// instant.
pub(crate) async fn commit_contact_event_unit(
    state: &AppState,
    submission: &EventAdmissionSubmission,
    guard: SelfProducerCommitGuard,
    projection: coland_services::events::CommitContactProjection,
    accepted_at: chrono::DateTime<chrono::Utc>,
) -> ServiceResult<AuthoritySubmitResponseBody> {
    submission
        .validate()
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    let event = &submission.event;
    if !is_contact_kind(&event.kind) {
        return Err(ServiceError::SchemaViolation(
            "Contact admission received another Event kind".to_owned(),
        ));
    }
    if submission.approval_signatures.is_some() {
        return Err(ServiceError::SchemaViolation(
            "a Contact Event carries no approval signatures".to_owned(),
        ));
    }
    let intent = projection.completion_intent.as_ref().ok_or_else(|| {
        ServiceError::Internal("a Contact Event commits with its completion intent".to_owned())
    })?;
    if intent.plan.event != *event || intent.accepted_at()? != accepted_at {
        return Err(ServiceError::Internal(
            "Contact completion intent does not bind the admitted Event".to_owned(),
        ));
    }
    if let Some(outcome) = super::authority_self_event_unit::exact_replay(state, event).await? {
        return Ok(outcome);
    }
    let method = arkret_wire::DidUrl::new(
        crate::routing::federation::federation_service_signature_key_id(
            state.service_did().as_str(),
        ),
    )
    .map_err(|error| ServiceError::Internal(error.to_string()))?;
    let transaction = state
        .authority_commits()
        .prepare_self_event_transaction(
            event,
            &state.service_core_id(),
            method,
            state.notary_signing_key().as_ref(),
            accepted_at,
        )
        .await?;
    let envelope = serde_json::to_value(event)
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    let canonical_bytes = arkret_canonical::canonical_json_bytes(
        &event
            .digest_payload()
            .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?,
    )
    .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    let canonical_digest = event
        .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    let command = coland_services::events::CommitAcceptedEventCommand {
        verified_media_participant: None,
        authority_commit: transaction.clone(),
        self_producer_guard: Some(guard),
        applet_producer_guard: None,
        widget_token_gate: None,
        agent_grant_scope_evidence: None,
        forwarded_producer_evidence: None,
        forwarded_agent_producer: None,
        agent_deployment_ceiling:
            arkret_models_collaboration::governance::agent_participation::ParticipationBits::ALL,
        event: coland_storage::CanonicalEventRecord {
            event_id: event.event_id.to_string(),
            actor_id: event.actor_id.to_string(),
            realm_id: Some(event.realm_id.to_string()),
            kind: event.kind.as_str().to_owned(),
            schema_id: arkret_wire::SchemaId::EVENT_V1.to_owned(),
            digest_suite: arkret_canonical::DigestSuite::Sha256,
            canonical_digest,
            canonical_bytes,
            envelope,
            received_at: accepted_at,
        },
        parent_membership_admission: None,
        contact_projection: Some(projection),

        device_revocation_transition: None,
        device_revocation_gate: None,
        projections: Vec::new(),
        idempotency: None,
        deliveries: Vec::new(),
        realm_fanout_source: None,
    };
    if let Err(error) = state.events().commit_accepted_event(command).await {
        if let Some(outcome) = super::authority_self_event_unit::exact_replay(state, event).await? {
            return Ok(outcome);
        }
        return Err(error);
    }
    Ok(AuthoritySubmitResponseBody::Accepted {
        status: AuthorityCommitStatus::Committed,
        commit: transaction.commit,
    })
}
