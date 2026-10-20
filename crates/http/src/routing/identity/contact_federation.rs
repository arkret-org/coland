//! Cross-Station contact fact delivery (spec
//! `contact-and-direct-conversation.md` §2 / §4.1).
//!
//! Contact facts (`ak.contact.requested` / `accepted` / `rejected` /
//! `tombstoned`) are principal-scoped and cross-Realm. When the issuer and the
//! target holder live on different Stations, the issuer-side server
//! federates the signed fact to the target holder's server via
//! `ak.peer.contacts.command.submit.v1` (`POST /_arkret/peer/contacts`); the recipient
//! projects the original signed envelope into the target holder's contact
//! projection without re-signing it.
//!
//! Surfaces:
//! - sender: [`prepare_peer_contact_carrier`] — prepare a verified outbound route for the exact
//!   recipient Station; the self operation commits its delivery atomically.
//! - receiver: [`peer_contacts_submit`] — accept a delivered fact and project it into the local
//!   target holder's contact projection.

use arkret_canonical as canonical;
use arkret_identifiers::Hash;
use arkret_models_collaboration::contact_operations::{
    BilateralContinuityCheckpoint, BilateralContinuityCheckpointCore,
    BilateralContinuityCheckpointProposal, BilateralContinuityCheckpointSignature,
    CONTACT_CONTINUITY_CONTEXT, ContactContinuityEvidence, ContactCurrentProof, ContactPeer,
    ContactProducerSigner, ContactRound, ContactRoundEvidenceBundle, ContactScope,
    ContactScopeUpdatePayload, GlareConcurrencyAttestation, NormalResponseAcceptanceReceipt,
    PeerContactControlKind, PeerContactControlReceipt, PeerContactControlReceiptDomain,
    PeerContactControlSubmitOutcome, PeerContactEventSubmitOutcome, PeerContactMirrorReceipt,
    PeerContactMirrorReceiptDomain, PeerContactOutcome, PeerContactSubmitOutcome,
    PeerContactSubmitRequestBody, RejectAcceptanceReceipt, RequestAcceptanceReceipt,
    bilateral_checkpoint_digest, bilateral_continuity_root_basis_digest,
    bilateral_prefix_accumulator,
};
use arkret_models_collaboration::events_payloads::contact::{
    ContactAcceptedPayload, ContactRejectedPayload, ContactRequestedPayload,
    ContactTombstonedPayload,
};
use arkret_models_collaboration::governance::peer_contact::{
    ContactIntroductionEvidence, PeerContactAddress,
};
use arkret_wire::{AccountId, Did, DidUrl, Event, IdempotencyKey, ProtocolSignature};
use coland_http::error::AppError;
use coland_http::result::{JsonResult, json_ok};
use coland_services::identity::ContactRecord;
use salvo::prelude::*;
use serde_json::{Value, json};
use uuid::Uuid;

fn event_digest_for_frozen_claim(event: &Event, claim: &Hash) -> Result<Hash, AppError> {
    let digest_suite = claim
        .digest_suite()
        .map_err(|error| AppError::internal(format!("Contact digest suite: {error}")))?;
    Hash::new(
        event
            .event_digest_with_digest_suite(digest_suite)
            .map_err(|error| AppError::internal(format!("Contact Event digest: {error}")))?,
    )
    .map_err(|error| AppError::internal(format!("Contact Event digest invalid: {error}")))
}

/// The source-signed receipt freezes the exact producer method and public key
/// that passed its authority admission. The receiving Station must still
/// verify the original Event proof with that key before projecting the fact.
async fn verify_peer_contact_event_producer(
    state: &AppState,
    delivery: &PeerContactSubmitRequestBody,
    event: &Event,
    source_id: &str,
) -> Result<(), AppError> {
    let (holder, signer): (&ContactPeer, &ContactProducerSigner) = match delivery {
        PeerContactSubmitRequestBody::Request {
            request_receipt, ..
        } => (
            &request_receipt.core.holder,
            &request_receipt.core.producer_signer,
        ),
        PeerContactSubmitRequestBody::Response {
            response_receipt, ..
        } => (
            &response_receipt.request_receipt.core.peer,
            &response_receipt.producer_signer,
        ),
        PeerContactSubmitRequestBody::Reject { reject_receipt, .. } => (
            &reject_receipt.request_receipt.core.peer,
            &reject_receipt.producer_signer,
        ),
        PeerContactSubmitRequestBody::ScopeUpdate { lineage, .. }
        | PeerContactSubmitRequestBody::Tombstone { lineage, .. } => {
            (&lineage.issuer, &lineage.producer_signer)
        }
        _ => {
            return Err(super::super::events::peer::schema_violation(
                "Contact control carrier has no original Event producer",
            ));
        }
    };
    let history = if matches!(holder, ContactPeer::Agent { .. }) {
        let did = arkret_identity::contact_producer_identity::agent_contact_identity_did(
            event, holder, signer,
        )
        .map_err(|error| super::super::events::peer::schema_violation(error.to_string()))?;
        Some(
            state
                .dids()
                .verified_webvh_history(&did)
                .await
                .map_err(|error| match error {
                    coland_services::identity::PinnedDidResolutionError::HistoryUnverifiable(_) => {
                        super::super::events::peer::schema_violation(format!(
                            "Contact Agent native history invalid: {error}"
                        ))
                    }
                    _ => crate::app_error!(
                        TemporarilyUnavailable,
                        format!("Contact Agent native history unavailable: {error}")
                    ),
                })?,
        )
    } else {
        None
    };
    verify_exact_contact_event_producer(event, holder, signer, source_id, history.as_ref())
}

fn verify_exact_contact_event_producer(
    event: &Event,
    holder: &ContactPeer,
    signer: &ContactProducerSigner,
    source_id: &str,
    agent_history: Option<&arkret_identity::VerifiedDidWebvhLog>,
) -> Result<(), AppError> {
    signer.validate_for_event(event, holder).map_err(|error| {
        super::super::events::peer::schema_violation(format!(
            "Contact producer descriptor does not bind Event: {error}"
        ))
    })?;
    if holder.delivery_station_id().as_str() != source_id
        || event.actor_id.route_service_id().as_str() != source_id
    {
        return Err(super::super::events::peer::schema_violation(
            "Contact producer holder is hosted by another Station",
        ));
    }
    if matches!(holder, ContactPeer::Agent { .. }) {
        let history = agent_history.ok_or_else(|| {
            crate::app_error!(
                FailedPrecondition,
                "Agent Contact producer history is unavailable",
            )
        })?;
        arkret_identity::contact_producer_identity::validate_agent_contact_native_history(
            event, holder, signer, history,
        )
        .map_err(|error| super::super::events::peer::schema_violation(error.to_string()))?;
    }
    event
        .validate_for_contact_history_structural()
        .map_err(|error| super::super::events::peer::schema_violation(error.to_string()))?;
    arkret_schema::validate_event_wire_schema(event)
        .map_err(|error| super::super::events::peer::schema_violation(error.to_string()))?;
    let suite = event
        .event_id
        .event_digest()
        .digest_suite()
        .map_err(|error| super::super::events::peer::schema_violation(error.to_string()))?;
    event
        .verify_event_id_matches_content_with_digest_suite(suite)
        .map_err(|error| super::super::events::peer::schema_violation(error.to_string()))?;
    let proof = event.producer_proof.as_ref().ok_or_else(|| {
        super::super::events::peer::schema_violation("Contact Event has no producer proof")
    })?;
    proof
        .validate_production()
        .map_err(|error| super::super::events::peer::schema_violation(error.to_string()))?;
    // The descriptor binds the exact producer method; the proof's own signing
    // time is covered by the JWS and is not required to equal the Event's
    // declared `created_at` (contact-and-direct-conversation.md, Contact
    // producer projection).
    if &proof.verification_method != signer.verification_method() {
        return Err(super::super::events::peer::schema_violation(
            "Contact producer method differs from source descriptor",
        ));
    }
    let producer = event.executed_by.as_ref().unwrap_or(&event.actor_id);
    let did = arkret_identity::verification_method_did(signer.verification_method().as_str())
        .map_err(|error| super::super::events::peer::schema_violation(error.to_string()))?;
    if arkret_wire::project_did_to_core_id(&did)
        .map_err(|error| super::super::events::peer::schema_violation(error.to_string()))?
        != *producer.signing_principal_id()
    {
        return Err(super::super::events::peer::schema_violation(
            "Contact producer method belongs to another principal",
        ));
    }
    let key = arkret_signatures::proof::PublicKeyMaterial::Ed25519Raw {
        bytes: signer
            .public_key_bytes()
            .map_err(|error| super::super::events::peer::schema_violation(error.to_string()))?
            .to_vec(),
    };
    let bytes = arkret_signatures::EventProofBuilder::new()
        .envelope_bytes(event)
        .map_err(|error| super::super::events::peer::schema_violation(error.to_string()))?;
    arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
        proof,
        &bytes,
        &event.actor_id,
        &key,
        suite,
    )
    .map_err(|error| {
        super::super::events::peer::schema_violation(format!(
            "Contact original Event producer proof is invalid: {error}"
        ))
    })
}

use super::now;
use crate::state::AppState;

const HEADER_SOURCE_SERVICE_ID: &str = "source-service-id";

pub(crate) fn peer_router() -> Router {
    Router::new().push(Router::with_path("contacts").post(peer_contacts_submit))
}

/// Enqueue the exact typed `ak.peer.contacts.command.submit.v1` carrier for a
/// remote Station. Same-server delivery is a no-op because the local
/// Contact projection was already committed by the self operation.
pub(crate) async fn enqueue_peer_contact_carrier(
    state: &AppState,
    recipient_id: &str,
    delivery: &PeerContactSubmitRequestBody,
) -> Result<bool, AppError> {
    let Some(prepared) = prepare_peer_contact_carrier(state, recipient_id, delivery).await? else {
        return Ok(false);
    };
    state
        .federation()
        .enqueue_delivery(
            coland_services::federation::EnqueueFederationDeliveryCommand { delivery: prepared },
        )
        .await
        .map_err(|error| AppError::internal(format!("contact delivery enqueue: {error}")))?;
    Ok(true)
}

pub(crate) async fn prepare_peer_contact_carrier(
    state: &AppState,
    recipient_id: &str,
    delivery: &PeerContactSubmitRequestBody,
) -> Result<Option<coland_services::federation::FederationDeliveryRecord>, AppError> {
    if recipient_id == state.service_id() {
        return Ok(None);
    }
    let (_, contact_address) = peer_contact_delivery_address(delivery);
    contact_address.validate_shape().map_err(|error| {
        AppError::param_invalid(format!("invalid contact delivery address: {error}"))
    })?;
    if contact_address.delivery_station_id().as_str() != recipient_id {
        return Err(AppError::param_invalid(
            "contact_address recipient Station does not match delivery destination",
        ));
    }
    let resolver = state
        .service_route_resolver()
        .map_err(|error| AppError::internal(error.to_owned()))?;
    let entry = resolver
        .resolve_carrier(
            &contact_address.service_resolution,
            contact_address.delivery_station_id(),
            "station",
            chrono::Utc::now(),
        )
        .await
        .map_err(|error| {
            crate::app_error!(
                FailedPrecondition,
                format!("recipient service has no verified route: {error}"),
            )
        })?;
    let peer_url = entry.base_url().to_owned();
    let (idempotency_key, _) = peer_contact_delivery_address(delivery);
    let payload_bytes = canonical::canonical_json_bytes(&delivery)
        .map_err(|error| AppError::internal(format!("contact delivery canonicalize: {error}")))?;
    let payload_json = String::from_utf8(payload_bytes)
        .map_err(|error| AppError::internal(format!("contact delivery utf8: {error}")))?;
    Ok(Some(
        coland_services::federation::FederationDeliveryRecord {
            id: Uuid::new_v4().to_string(),
            peer_id: contact_address.delivery_station_id().clone(),
            peer_url: Some(peer_url.trim_end_matches('/').to_owned()),
            endpoint: "/_arkret/peer/contacts".to_owned(),
            idempotency_key: idempotency_key.to_owned(),
            payload_json,
            coalescing_key: None,
            coalescing_position: None,
            realm_fanout: None,
            created_at: now().timestamp(),
        },
    ))
}

fn peer_contact_delivery_address(
    delivery: &PeerContactSubmitRequestBody,
) -> (&str, &PeerContactAddress) {
    match delivery {
        PeerContactSubmitRequestBody::Request {
            idempotency_key,
            contact_address,
            ..
        }
        | PeerContactSubmitRequestBody::Response {
            idempotency_key,
            contact_address,
            ..
        }
        | PeerContactSubmitRequestBody::Reject {
            idempotency_key,
            contact_address,
            ..
        }
        | PeerContactSubmitRequestBody::ScopeUpdate {
            idempotency_key,
            contact_address,
            ..
        }
        | PeerContactSubmitRequestBody::Tombstone {
            idempotency_key,
            contact_address,
            ..
        }
        | PeerContactSubmitRequestBody::ProofRefresh {
            idempotency_key,
            contact_address,
            ..
        }
        | PeerContactSubmitRequestBody::GlareFinalize {
            idempotency_key,
            contact_address,
            ..
        }
        | PeerContactSubmitRequestBody::ContinuityCheckpoint {
            idempotency_key,
            contact_address,
            ..
        } => (idempotency_key.as_str(), contact_address),
    }
}

#[salvo::oapi::endpoint(operation_id = "ak.peer.contacts.command.submit", tags("identity"))]
#[tracing::instrument(skip_all, fields(op = "ak.peer.contacts.command.submit.v1"))]
async fn peer_contacts_submit(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<PeerContactSubmitOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    super::super::events::peer::validate_peer_request(state, req, true).await?;
    let delivery = req
        .parse_json::<PeerContactSubmitRequestBody>()
        .await
        .map_err(|_| {
            AppError::json_invalid("invalid ak.peer.contacts.command.submit.v1 request body")
        })?;
    let (_, carried_address) = peer_contact_delivery_address(&delivery);
    carried_address.validate_shape().map_err(|error| {
        super::super::events::peer::schema_violation(format!(
            "invalid contact_address shape: {error}"
        ))
    })?;
    let source_id = req
        .headers()
        .get(HEADER_SOURCE_SERVICE_ID)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            super::super::events::peer::schema_violation("source-service-id header is required")
        })?
        .to_owned();
    cache_contact_assertion_history(state, &delivery).await?;
    if let Some(outcome) = handle_contact_control_request(state, &delivery, &source_id).await? {
        return json_ok(outcome);
    }
    let (fact_kind, signed_event, contact_address) = match &delivery {
        PeerContactSubmitRequestBody::Request {
            signed_event,
            request_receipt,
            introduction_evidence,
            contact_address,
            ..
        } => {
            request_receipt.core.validate().map_err(|error| {
                super::super::events::peer::schema_violation(format!(
                    "invalid Contact request receipt: {error}"
                ))
            })?;
            if request_receipt.core.request_event_ref != signed_event.event_id
                || request_receipt.core.holder.contact_actor_id() != signed_event.actor_id
                || request_receipt.core.issuer_id.as_str() != source_id
                || request_receipt.core.request_digest()
                    != event_digest_for_frozen_claim(
                        signed_event,
                        &request_receipt.core.request_digest(),
                    )?
            {
                return Err(super::super::events::peer::schema_violation(
                    "Contact request receipt does not bind signed_event",
                ));
            }
            super::account::validate_request_receipt_cryptography(
                state,
                request_receipt,
                "request_receipt",
            )?;
            validate_contact_introduction_evidence_digest(
                &serde_json::to_value(&signed_event.payload).map_err(|error| {
                    AppError::internal(format!("Contact request payload encode: {error}"))
                })?,
                introduction_evidence,
            )?;
            (
                arkret_wire::event_kind_str::CONTACT_REQUESTED,
                signed_event,
                contact_address,
            )
        }
        PeerContactSubmitRequestBody::Response {
            signed_event,
            response_receipt,
            contact_address,
            ..
        } => {
            response_receipt
                .request_receipt
                .core
                .validate()
                .map_err(|error| {
                    super::super::events::peer::schema_violation(format!(
                        "invalid Contact response request receipt: {error}"
                    ))
                })?;
            if response_receipt.response_event_ref != signed_event.event_id
                || response_receipt.issuer_id.as_str() != source_id
                || response_receipt.response_digest()
                    != event_digest_for_frozen_claim(
                        signed_event,
                        &response_receipt.response_digest(),
                    )?
            {
                return Err(super::super::events::peer::schema_violation(
                    "Contact response receipt does not bind signed_event",
                ));
            }
            super::account::validate_request_receipt_cryptography(
                state,
                &response_receipt.request_receipt,
                "response_receipt.request_receipt",
            )?;
            verify_contact_evidence_signature(
                state,
                &source_id,
                &response_receipt.signature,
                &response_receipt
                    .canonical_signing_bytes()
                    .map_err(|error| {
                        AppError::internal(format!("Contact response receipt transcript: {error}"))
                    })?,
                "response_receipt",
            )?;
            (
                arkret_wire::event_kind_str::CONTACT_ACCEPTED,
                signed_event,
                contact_address,
            )
        }
        PeerContactSubmitRequestBody::Reject {
            signed_event,
            reject_receipt,
            contact_address,
            ..
        } => {
            reject_receipt
                .request_receipt
                .core
                .validate()
                .map_err(|error| {
                    super::super::events::peer::schema_violation(format!(
                        "invalid Contact reject request receipt: {error}"
                    ))
                })?;
            if reject_receipt.reject_event_ref != signed_event.event_id
                || reject_receipt.issuer_id.as_str() != source_id
                || reject_receipt.reject_digest()
                    != event_digest_for_frozen_claim(signed_event, &reject_receipt.reject_digest())?
            {
                return Err(super::super::events::peer::schema_violation(
                    "Contact reject receipt does not bind signed_event",
                ));
            }
            super::account::validate_request_receipt_cryptography(
                state,
                &reject_receipt.request_receipt,
                "reject_receipt.request_receipt",
            )?;
            verify_contact_evidence_signature(
                state,
                &source_id,
                &reject_receipt.signature,
                &reject_receipt.canonical_signing_bytes().map_err(|error| {
                    AppError::internal(format!("Contact reject receipt transcript: {error}"))
                })?,
                "reject_receipt",
            )?;
            (
                arkret_wire::event_kind_str::CONTACT_REJECTED,
                signed_event,
                contact_address,
            )
        }
        PeerContactSubmitRequestBody::ScopeUpdate {
            signed_event,
            lineage,
            current_proof,
            contact_address,
            ..
        } => {
            validate_contact_lineage_carrier(
                state,
                &source_id,
                signed_event,
                lineage,
                current_proof,
                false,
            )?;
            (
                arkret_wire::event_kind_str::CONTACT_SCOPE_UPDATE,
                signed_event,
                contact_address,
            )
        }
        PeerContactSubmitRequestBody::Tombstone {
            signed_event,
            lineage,
            current_proof,
            contact_address,
            ..
        } => {
            validate_contact_lineage_carrier(
                state,
                &source_id,
                signed_event,
                lineage,
                current_proof,
                true,
            )?;
            (
                arkret_wire::event_kind_str::CONTACT_TOMBSTONE,
                signed_event,
                contact_address,
            )
        }
        PeerContactSubmitRequestBody::ProofRefresh { .. }
        | PeerContactSubmitRequestBody::GlareFinalize { .. }
        | PeerContactSubmitRequestBody::ContinuityCheckpoint { .. } => {
            unreachable!("control carrier branches are handled before Event carrier projection")
        }
    };
    if signed_event.kind.as_str() != fact_kind {
        return Err(super::super::events::peer::schema_violation(
            "Contact carrier branch does not match signed_event.kind",
        ));
    }
    let issuer_core_id = contact_event_issuer_core_id(&delivery)
        .expect("Event branch excludes Contact control carriers");
    if issuer_core_id != signed_event.actor_id {
        return Err(super::super::events::peer::cross_domain_replay(
            "Contact carrier issuer does not match signed_event.actor_id",
        ));
    }
    verify_peer_contact_event_producer(state, &delivery, signed_event, &source_id).await?;
    let issuer = issuer_core_id.signing_principal_id().to_string();
    let recipient_id = contact_address.delivery_station_id().as_str();
    if recipient_id != state.service_id() {
        return Err(super::super::events::peer::cross_domain_replay(
            "contact_address recipient Station does not match this service",
        ));
    }
    let payload_value = serde_json::to_value(&signed_event.payload)
        .map_err(|error| AppError::internal(format!("contact payload encode failed: {error}")))?;
    let subject_core_id = contact_event_subject_core_id(signed_event)?;
    if contact_address.recipient.contact_actor_id() != subject_core_id {
        return Err(super::super::events::peer::cross_domain_replay(
            "contact_address.recipient does not match the signed Contact recipient",
        ));
    }
    let subject_id = subject_core_id.signing_principal_id().to_string();
    if let Some(current_proof) = match &delivery {
        PeerContactSubmitRequestBody::Response { current_proof, .. } => current_proof.as_ref(),
        PeerContactSubmitRequestBody::ScopeUpdate { current_proof, .. }
        | PeerContactSubmitRequestBody::Tombstone { current_proof, .. } => Some(current_proof),
        _ => None,
    } {
        if current_proof.issuer_id.as_str() != source_id
            || current_proof.peer.contact_actor_id() != subject_core_id
            || current_proof.head_event_ref != signed_event.event_id
            || current_proof.head_digest()
                != event_digest_for_frozen_claim(signed_event, &current_proof.head_digest())?
            || !current_proof
                .accepted_commit_event_ids
                .contains(&signed_event.event_id)
            || current_proof.complete_through == 0
            || current_proof.fresh_until <= now()
        {
            return Err(super::super::events::peer::schema_violation(
                "Contact carrier current proof does not bind the exact signed Event",
            ));
        }
        verify_contact_evidence_signature(
            state,
            &source_id,
            &current_proof.signature,
            &current_proof.canonical_signing_bytes().map_err(|error| {
                AppError::internal(format!("Contact current proof transcript: {error}"))
            })?,
            "carrier_current_proof",
        )?;
    }

    // Originating Station of this delivery: the peer end of the
    // projected contact row (the issuer) is hosted there. `validate_peer_request`
    // above already verified this header is a present, well-formed DID, so we
    // record it on the projection as the contact's `peer_id` — that is
    // the requester_id's/accepter's home server, NOT this service. inkson reads it
    // off a pending_incoming row as the `requester_id` to address the
    // reverse `respond` delivery back to the originator.
    // Project the issuer's exact signed envelope; peer transport never
    // re-signs or rewrites the Contact fact.
    let (request_receipt, response_receipt, reject_receipt, carrier_current_proof) = match &delivery
    {
        PeerContactSubmitRequestBody::Request {
            request_receipt, ..
        } => (Some(request_receipt), None, None, None),
        PeerContactSubmitRequestBody::Response {
            response_receipt,
            current_proof,
            ..
        } => (None, Some(response_receipt), None, current_proof.as_ref()),
        PeerContactSubmitRequestBody::ScopeUpdate { current_proof, .. }
        | PeerContactSubmitRequestBody::Tombstone { current_proof, .. } => {
            (None, None, None, Some(current_proof))
        }
        PeerContactSubmitRequestBody::Reject { reject_receipt, .. } => {
            (None, None, Some(reject_receipt), None)
        }
        PeerContactSubmitRequestBody::ProofRefresh { .. }
        | PeerContactSubmitRequestBody::GlareFinalize { .. }
        | PeerContactSubmitRequestBody::ContinuityCheckpoint { .. } => unreachable!(),
    };
    if let Some(request_receipt) = request_receipt {
        let canonical_event_bytes =
            canonical::canonical_json_bytes(&signed_event).map_err(|error| {
                AppError::internal(format!("Contact mirror canonical Event: {error}"))
            })?;
        let request_digest =
            event_digest_for_frozen_claim(signed_event, &request_receipt.core.request_digest())?
                .to_string();
        state
            .persistence()
            .put_contact_verified_mirror(&coland_storage::ContactVerifiedMirrorRecord {
                target_holder_principal_id: subject_id.clone(),
                request_event_id: signed_event.event_id.to_string(),
                request_digest,
                canonical_event_bytes,
                source_receipt: request_receipt.clone(),
                issuer_id: source_id.clone(),
                verified_at: now(),
            })
            .await
            .map_err(|error| {
                AppError::internal(format!("persist Contact verified mirror: {error}"))
            })?;
    }
    let outcome = project_delivered_contact_fact(
        state,
        fact_kind,
        &issuer_core_id,
        &subject_core_id,
        &payload_value,
        signed_event.event_id.as_str(),
        request_receipt,
        response_receipt,
        reject_receipt,
        carrier_current_proof,
        Some(&source_id),
    )
    .await?;

    super::append_audit_log(
        state,
        Some(&subject_id),
        "peer.contacts.submit",
        json!({
            "fact_kind": fact_kind,
            "issuer_id": issuer,
            "subject_id": subject_id,
            "status": outcome,
        }),
        outcome,
    )
    .await;
    let outcome = if outcome == "duplicate" {
        PeerContactOutcome::Duplicate
    } else {
        PeerContactOutcome::Accepted
    };
    if matches!(delivery, PeerContactSubmitRequestBody::Request { .. }) {
        let request_digest = contact_control_request_digest(&delivery)?;
        if let Some(replayed) = replayed_contact_event_outcome(
            state,
            &subject_core_id,
            &issuer_core_id,
            &request_digest,
        )
        .await?
        {
            return json_ok(replayed);
        }
    }
    let mirror_receipt = sign_contact_mirror_receipt(state, &delivery, signed_event, outcome)?;
    if matches!(delivery, PeerContactSubmitRequestBody::Request { .. }) {
        persist_request_mirror_receipt(state, &issuer_core_id, &subject_core_id, &mirror_receipt)
            .await?;
        enqueue_glare_finalize_if_ready(state, &subject_core_id, &issuer_core_id).await?;
    }
    let result_kind = match &delivery {
        PeerContactSubmitRequestBody::Request { .. } => {
            arkret_models_collaboration::contact_operations::ContactResultKind::Request
        }
        PeerContactSubmitRequestBody::Response { .. } => {
            arkret_models_collaboration::contact_operations::ContactResultKind::Response
        }
        PeerContactSubmitRequestBody::Reject { .. } => {
            arkret_models_collaboration::contact_operations::ContactResultKind::Reject
        }
        PeerContactSubmitRequestBody::ScopeUpdate { .. } => {
            arkret_models_collaboration::contact_operations::ContactResultKind::ScopeUpdate
        }
        PeerContactSubmitRequestBody::Tombstone { .. } => {
            arkret_models_collaboration::contact_operations::ContactResultKind::Tombstone
        }
        PeerContactSubmitRequestBody::ProofRefresh { .. }
        | PeerContactSubmitRequestBody::GlareFinalize { .. }
        | PeerContactSubmitRequestBody::ContinuityCheckpoint { .. } => unreachable!(),
    };
    let current_proof = if matches!(
        result_kind,
        arkret_models_collaboration::contact_operations::ContactResultKind::Response
            | arkret_models_collaboration::contact_operations::ContactResultKind::ScopeUpdate
            | arkret_models_collaboration::contact_operations::ContactResultKind::Tombstone
    ) {
        let record = state
            .contacts()
            .contact_any(&subject_core_id, &issuer_core_id)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
            .ok_or_else(|| AppError::internal("projected Contact row disappeared"))?;
        record.contact_round_evidence.and_then(|bundle| {
            bundle
                .current_proofs
                .into_iter()
                .find(|proof| proof.peer.contact_actor_id() == issuer_core_id)
        })
    } else {
        None
    };
    if matches!(
        result_kind,
        arkret_models_collaboration::contact_operations::ContactResultKind::ScopeUpdate
            | arkret_models_collaboration::contact_operations::ContactResultKind::Tombstone
    ) && current_proof.is_none()
    {
        return Err(crate::app_error!(
            FailedPrecondition,
            "accepted Contact lineage carrier has no recipient current proof",
        ));
    }
    let response = PeerContactSubmitOutcome::Event(PeerContactEventSubmitOutcome {
        result_kind,
        status: outcome,
        mirror_receipt,
        current_proof,
        retry_after_ms: None,
    });
    if matches!(delivery, PeerContactSubmitRequestBody::Request { .. }) {
        persist_contact_event_outcome(state, &subject_core_id, &issuer_core_id, &response).await?;
    }
    json_ok(response)
}

/// Resolve every service assertion in this closed carrier at its own signed
/// evidence time before the existing exact-issuer and transcript checks. This
/// supplies historical keys for signatures whose method was rotated after
/// the source fact was accepted.
async fn cache_contact_assertion_history(
    state: &AppState,
    delivery: &PeerContactSubmitRequestBody,
) -> Result<(), AppError> {
    let mut signatures = Vec::new();
    match delivery {
        PeerContactSubmitRequestBody::Request {
            request_receipt,
            current_proof,
            ..
        } => {
            signatures.push(&request_receipt.signature);
            signatures.extend(current_proof.iter().map(|proof| &proof.signature));
        }
        PeerContactSubmitRequestBody::Response {
            response_receipt,
            current_proof,
            ..
        } => {
            signatures.push(&response_receipt.request_receipt.signature);
            signatures.push(&response_receipt.signature);
            signatures.extend(current_proof.iter().map(|proof| &proof.signature));
        }
        PeerContactSubmitRequestBody::Reject { reject_receipt, .. } => {
            signatures.push(&reject_receipt.request_receipt.signature);
            signatures.push(&reject_receipt.signature);
        }
        PeerContactSubmitRequestBody::ScopeUpdate {
            lineage,
            current_proof,
            ..
        }
        | PeerContactSubmitRequestBody::Tombstone {
            lineage,
            current_proof,
            ..
        } => {
            signatures.push(&lineage.signature);
            signatures.push(&current_proof.signature);
        }
        PeerContactSubmitRequestBody::ProofRefresh {
            prior_mirror_receipt,
            current_proof,
            ..
        } => {
            signatures.push(&prior_mirror_receipt.signature);
            signatures.push(&current_proof.signature);
        }
        PeerContactSubmitRequestBody::GlareFinalize {
            request_receipts,
            remote_mirror_receipt,
            glare_concurrency_attestation,
            ..
        } => {
            signatures.extend(request_receipts.iter().map(|receipt| &receipt.signature));
            signatures.push(&remote_mirror_receipt.signature);
            signatures.push(&glare_concurrency_attestation.signature);
        }
        PeerContactSubmitRequestBody::ContinuityCheckpoint { proposal, .. } => {
            signatures.push(&proposal.proposer_signature.signature);
        }
    }
    cache_contact_assertion_signatures(state, signatures).await
}

/// The receiver's signatures on a peer Contact outcome must use their own
/// evidence-time assertion methods too. Outbox retries may consume the same
/// durable response after the peer has rotated its service key.
pub(crate) async fn cache_contact_outcome_assertion_history(
    state: &AppState,
    outcome: &PeerContactSubmitOutcome,
) -> Result<(), AppError> {
    let mut signatures = Vec::new();
    match outcome {
        PeerContactSubmitOutcome::Event(event) => {
            signatures.push(&event.mirror_receipt.signature);
            signatures.extend(event.current_proof.iter().map(|proof| &proof.signature));
        }
        PeerContactSubmitOutcome::Control(PeerContactControlSubmitOutcome::ProofRefresh {
            control_receipt,
            current_proof,
            ..
        }) => {
            signatures.push(&control_receipt.signature);
            signatures.push(&current_proof.signature);
        }
        PeerContactSubmitOutcome::Control(PeerContactControlSubmitOutcome::GlareFinalize {
            control_receipt,
            glare_concurrency_attestation,
            current_proof,
            ..
        }) => {
            signatures.push(&control_receipt.signature);
            signatures.push(&glare_concurrency_attestation.signature);
            signatures.extend(current_proof.iter().map(|proof| &proof.signature));
        }
        PeerContactSubmitOutcome::Control(
            PeerContactControlSubmitOutcome::ContinuityCheckpoint {
                control_receipt,
                checkpoint,
                ..
            },
        ) => {
            signatures.push(&control_receipt.signature);
            signatures.extend(checkpoint.signatures.iter().map(|part| &part.signature));
        }
        PeerContactSubmitOutcome::ControlDeferred(deferred) => {
            signatures.push(&deferred.control_receipt.signature);
        }
    }
    cache_contact_assertion_signatures(state, signatures).await
}

pub(crate) async fn cache_contact_assertion_signatures(
    state: &AppState,
    signatures: Vec<&ProtocolSignature>,
) -> Result<(), AppError> {
    for signature in signatures {
        let method = signature.verification_method.as_str();
        let did = method
            .rsplit_once('#')
            .and_then(|(did, fragment)| (!fragment.is_empty()).then_some(did))
            .and_then(|did| Did::new(did.to_owned()).ok())
            .ok_or_else(|| {
                super::super::events::peer::schema_violation(
                    "Contact assertion verification method is not a DID URL",
                )
            })?;
        let pinned = state
            .dids()
            .resolve_webvh_state_at(&did, signature.created_at)
            .await
            .map_err(|error| {
                crate::app_error!(
                    TemporarilyUnavailable,
                    format!("Contact historical assertion state unavailable: {error}")
                )
            })?;
        let document: arkret_models_identity::service_identity::ServiceDidDocument =
            serde_json::from_value(pinned.document).map_err(|error| {
                super::super::events::peer::schema_violation(format!(
                    "Contact historical service DID is invalid: {error}"
                ))
            })?;
        let selected = document
            .verification_method
            .iter()
            .find(|candidate| {
                candidate.id == method
                    && candidate.controller == did
                    && document.assertion_method.contains(&candidate.id)
            })
            .ok_or_else(|| {
                super::super::events::peer::schema_violation(
                    "Contact method was not an assertionMethod at evidence time",
                )
            })?;
        let bytes = arkret_canonical::decode_ed25519_multibase(&selected.public_key_multibase)
            .map_err(|error| {
                super::super::events::peer::schema_violation(format!(
                    "Contact assertion key is invalid: {error}"
                ))
            })?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes).map_err(|error| {
            super::super::events::peer::schema_violation(format!(
                "Contact assertion key is invalid: {error}"
            ))
        })?;
        if !state.install_historical_contact_assertion_key(method, signature.created_at, key) {
            return Err(super::super::events::peer::schema_violation(
                "Contact assertion history changed at one signed evidence time",
            ));
        }
    }
    Ok(())
}

fn contact_event_issuer_core_id(
    delivery: &PeerContactSubmitRequestBody,
) -> Option<arkret_wire::ActorId> {
    match delivery {
        PeerContactSubmitRequestBody::Request {
            request_receipt, ..
        } => Some(request_receipt.core.holder.contact_actor_id()),
        PeerContactSubmitRequestBody::Response { signed_event, .. }
        | PeerContactSubmitRequestBody::Reject { signed_event, .. } => {
            Some(signed_event.actor_id.clone())
        }
        PeerContactSubmitRequestBody::ScopeUpdate { lineage, .. }
        | PeerContactSubmitRequestBody::Tombstone { lineage, .. } => {
            Some(lineage.issuer.contact_actor_id())
        }
        PeerContactSubmitRequestBody::ProofRefresh { .. }
        | PeerContactSubmitRequestBody::GlareFinalize { .. }
        | PeerContactSubmitRequestBody::ContinuityCheckpoint { .. } => None,
    }
}

/// Resolve the Contact subject from the signed carrier Event itself.
///
/// The Event Envelope binds its own `kind` to its own `payload`, so the
/// closed Contact fact type is selected by the same signed value that carries
/// the payload bytes; a caller cannot pair one fact kind with another fact's
/// payload.
fn contact_event_subject_core_id(signed_event: &Event) -> Result<arkret_wire::ActorId, AppError> {
    let payload = serde_json::to_value(&signed_event.payload)
        .map_err(|error| AppError::internal(format!("contact payload encode failed: {error}")))?;
    let subject = match signed_event.kind {
        arkret_wire::EventKind::ContactRequested => {
            serde_json::from_value::<ContactRequestedPayload>(payload)
                .map(|payload| payload.peer.contact_actor_id().clone())
        }
        arkret_wire::EventKind::ContactAccepted => {
            serde_json::from_value::<ContactAcceptedPayload>(payload)
                .map(|payload| payload.peer.contact_actor_id().clone())
        }
        arkret_wire::EventKind::ContactRejected => {
            serde_json::from_value::<ContactRejectedPayload>(payload)
                .map(|payload| payload.peer.contact_actor_id().clone())
        }
        arkret_wire::EventKind::ContactScopeUpdate => {
            serde_json::from_value::<ContactScopeUpdatePayload>(payload)
                .map(|payload| payload.peer.contact_actor_id().clone())
        }
        arkret_wire::EventKind::ContactTombstone => {
            serde_json::from_value::<ContactTombstonedPayload>(payload)
                .map(|payload| payload.peer.contact_actor_id().clone())
        }
        _ => unreachable!("caller admits only Contact fact kinds"),
    }
    .map_err(|error| {
        super::super::events::peer::schema_violation(format!(
            "signed Contact payload is invalid: {error}"
        ))
    })?;
    Ok(subject)
}

async fn replayed_contact_event_outcome(
    state: &AppState,
    holder: &arkret_wire::ActorId,
    peer: &arkret_wire::ActorId,
    request_digest: &Hash,
) -> Result<Option<PeerContactSubmitOutcome>, AppError> {
    let record = state
        .contacts()
        .contact_any(holder, peer)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    Ok(record.and_then(|record| {
        record
            .control_outcomes
            .iter()
            .find_map(|outcome| match outcome {
                PeerContactSubmitOutcome::Event(event)
                    if event.mirror_receipt.request_digest == *request_digest =>
                {
                    Some(outcome.clone())
                }
                _ => None,
            })
    }))
}

async fn persist_contact_event_outcome(
    state: &AppState,
    holder: &arkret_wire::ActorId,
    peer: &arkret_wire::ActorId,
    outcome: &PeerContactSubmitOutcome,
) -> Result<(), AppError> {
    let contacts = state.contacts();
    let mut record = contacts
        .contact_any(holder, peer)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::internal("projected Contact row disappeared"))?;
    let outcome_digest = super::account::canonical_contact_digest(outcome)?;
    let already_stored = record.control_outcomes.iter().any(|stored| {
        super::account::canonical_contact_digest(stored)
            .is_ok_and(|digest| digest == outcome_digest)
    });
    if !already_stored {
        let expected_updated_at = record.updated_at;
        record.control_outcomes.push(outcome.clone());
        advance_contact_revision(&mut record, expected_updated_at);
        save_contact_cas(contacts, expected_updated_at, record).await?;
    }
    Ok(())
}

async fn handle_contact_control_request(
    state: &AppState,
    request: &PeerContactSubmitRequestBody,
    source_id: &str,
) -> Result<Option<PeerContactSubmitOutcome>, AppError> {
    match request {
        PeerContactSubmitRequestBody::ProofRefresh {
            prior_mirror_receipt,
            current_proof,
            contact_address,
            ..
        } => {
            if contact_address.delivery_station_id().as_str() != state.service_id() {
                return Err(super::super::events::peer::cross_domain_replay(
                    "contact_address recipient Station does not match this service",
                ));
            }
            let outcome = finalize_contact_proof_refresh(
                state,
                request,
                source_id,
                prior_mirror_receipt,
                current_proof,
                contact_address,
            )
            .await?;
            Ok(Some(outcome))
        }
        PeerContactSubmitRequestBody::GlareFinalize {
            contact_round_id,
            contact_round,
            request_receipts,
            remote_mirror_receipt,
            glare_concurrency_attestation,
            contact_address,
            ..
        } => {
            if contact_address.delivery_station_id().as_str() != state.service_id() {
                return Err(super::super::events::peer::cross_domain_replay(
                    "contact_address recipient Station does not match this service",
                ));
            }
            let outcome = finalize_glare_contact_round(
                state,
                request,
                source_id,
                contact_round_id,
                contact_round,
                request_receipts,
                remote_mirror_receipt,
                glare_concurrency_attestation,
                contact_address,
            )
            .await?;
            Ok(Some(outcome))
        }
        PeerContactSubmitRequestBody::ContinuityCheckpoint {
            proposal,
            contact_address,
            ..
        } => {
            if contact_address.delivery_station_id().as_str() != state.service_id() {
                return Err(super::super::events::peer::cross_domain_replay(
                    "contact_address recipient Station does not match this service",
                ));
            }
            let outcome = finalize_continuity_checkpoint(
                state,
                request,
                source_id,
                proposal,
                contact_address,
            )
            .await?;
            Ok(Some(outcome))
        }
        _ => Ok(None),
    }
}

fn uncheckpointed_bundle(bundle: &ContactRoundEvidenceBundle) -> ContactRoundEvidenceBundle {
    let mut bundle = bundle.clone();
    bundle.continuity_checkpoint = None;
    bundle
}

fn continuity_invalid(message: impl Into<String>) -> AppError {
    crate::app_error!(ContinuityInvalid, message)
}

fn contact_bundle_digest(bundle: &ContactRoundEvidenceBundle) -> Result<Hash, AppError> {
    bilateral_continuity_root_basis_digest(&uncheckpointed_bundle(bundle))
        .map_err(|error| AppError::internal(format!("Contact basis digest: {error}")))
}

fn latest_continuity_checkpoint(record: &ContactRecord) -> Option<BilateralContinuityCheckpoint> {
    record
        .contact_round_evidence
        .as_ref()
        .and_then(|bundle| bundle.continuity_checkpoint.clone())
        .or_else(|| {
            record
                .contact_round_evidence_history
                .iter()
                .find_map(|bundle| bundle.continuity_checkpoint.clone())
        })
}

fn participant_authority_pair(
    state: &AppState,
    record: &ContactRecord,
    local_principal_id: &str,
) -> Result<[AccountId; 2], AppError> {
    let (local_actor, peer_actor) =
        if record.requester_id.signing_principal_id().as_str() == local_principal_id {
            (&record.requester_id, &record.target_id)
        } else if record.target_id.signing_principal_id().as_str() == local_principal_id {
            (&record.target_id, &record.requester_id)
        } else {
            return Err(AppError::internal(
                "Contact record does not contain the local principal",
            ));
        };
    let local_account_id = local_actor.as_account_id().cloned().ok_or_else(|| {
        AppError::internal("Contact continuity local participant is not an account actor")
    })?;
    let peer_account_id = peer_actor.as_account_id().cloned().ok_or_else(|| {
        AppError::internal("Contact continuity peer participant is not an account actor")
    })?;
    if local_account_id.station_id.as_str() != state.service_id() {
        return Err(AppError::internal(
            "Contact continuity local account is not hosted by this Station",
        ));
    }
    let mut pair = [local_account_id, peer_account_id];
    pair.sort();
    Ok(pair)
}

/// Build the unique next checkpoint core from durable accepted history. The
/// newest sixteen predecessor rounds remain explicit; the oldest available
/// contiguous prefix is compacted. Re-running against unchanged history is
/// byte-identical.
pub(crate) fn next_continuity_checkpoint_core(
    state: &AppState,
    record: &ContactRecord,
    local_principal_id: &str,
) -> Result<BilateralContinuityCheckpointCore, AppError> {
    let index = record
        .contact_round_evidence_history
        .len()
        .saturating_sub(1)
        .min(16);
    let boundary = record
        .contact_round_evidence_history
        .get(index)
        .ok_or_else(|| {
            crate::app_error!(
                FailedPrecondition,
                "Contact continuity has no terminal prefix to compact"
            )
        })?;
    checkpoint_core_at_boundary(
        state,
        record,
        local_principal_id,
        &boundary.contact_round_id,
    )
}

fn checkpoint_core_at_boundary(
    state: &AppState,
    record: &ContactRecord,
    local_principal_id: &str,
    boundary: &Hash,
) -> Result<BilateralContinuityCheckpointCore, AppError> {
    let current = record.contact_round_evidence.as_ref().ok_or_else(|| {
        crate::app_error!(FailedPrecondition, "Contact round evidence is unavailable",)
    })?;
    if record.contact_round_evidence_history.is_empty() {
        return Err(crate::app_error!(
            FailedPrecondition,
            "Contact continuity has no terminal prefix to compact",
        ));
    }
    let previous = latest_continuity_checkpoint(record);
    if let Some(previous) = &previous {
        previous.validate_contact_shape().map_err(|error| {
            continuity_invalid(format!("durable continuity checkpoint is invalid: {error}"))
        })?;
    }
    let tail_to_keep = record
        .contact_round_evidence_history
        .iter()
        .position(|entry| &entry.contact_round_id == boundary)
        .ok_or_else(|| continuity_invalid("checkpoint prefix boundary is not accepted history"))?;
    let extension_newest_to_oldest = &record.contact_round_evidence_history[tail_to_keep..];
    let covered_through = extension_newest_to_oldest
        .first()
        .expect("non-empty history slice")
        .contact_round_id
        .clone();
    let extension_digests = extension_newest_to_oldest
        .iter()
        .rev()
        .map(contact_bundle_digest)
        .collect::<Result<Vec<_>, _>>()?;
    let (root_basis, previous_accumulator, covered_prefix_count, sequence) =
        if let Some(previous) = &previous {
            (
                previous.core.root_basis.clone(),
                Some(&previous.core.prefix_accumulator_root),
                previous
                    .core
                    .covered_prefix_count
                    .checked_add(extension_digests.len() as u64)
                    .ok_or_else(|| AppError::internal("continuity prefix count overflow"))?,
                previous
                    .core
                    .sequence
                    .checked_add(1)
                    .ok_or_else(|| AppError::internal("continuity sequence overflow"))?,
            )
        } else {
            let root = extension_newest_to_oldest
                .last()
                .expect("non-empty history slice");
            if root.previous_terminal_contact_round_id.is_some() {
                return Err(crate::app_error!(
                    FailedPrecondition,
                    "Contact continuity root is unavailable",
                ));
            }
            let root = Box::new(uncheckpointed_bundle(root));
            (root, None, extension_digests.len() as u64, 1)
        };
    let participants = participant_authority_pair(state, record, local_principal_id)?;
    let current_pair = match &current.contact_round {
        ContactRound::Normal {
            sorted_pair_member_ids,
            ..
        }
        | ContactRound::Glare {
            sorted_pair_member_ids,
            ..
        } => sorted_pair_member_ids,
    };
    if current_pair[0] != arkret_wire::ActorId::account(participants[0].clone())
        || current_pair[1] != arkret_wire::ActorId::account(participants[1].clone())
    {
        return Err(continuity_invalid(
            "Contact participant authority pair changed",
        ));
    }
    let prefix_accumulator_root =
        bilateral_prefix_accumulator(previous_accumulator, &extension_digests)
            .map_err(|error| AppError::internal(error.to_string()))?;
    Ok(BilateralContinuityCheckpointCore {
        context: CONTACT_CONTINUITY_CONTEXT.to_owned(),
        participants,
        root_basis,
        covered_through_contact_round_id: covered_through,
        prefix_accumulator_root,
        covered_prefix_count,
        sequence,
        previous_checkpoint_digest: previous.map(|checkpoint| checkpoint.checkpoint_digest),
    })
}

pub(crate) fn create_continuity_checkpoint_proposal(
    state: &AppState,
    record: &ContactRecord,
    local_principal_id: &str,
) -> Result<BilateralContinuityCheckpointProposal, AppError> {
    let core = next_continuity_checkpoint_core(state, record, local_principal_id)?;
    let checkpoint_digest = bilateral_checkpoint_digest(&core)
        .map_err(|error| AppError::internal(error.to_string()))?;
    let local_signer = core
        .participants
        .iter()
        .find(|participant| {
            participant.principal_id.as_str() == local_principal_id
                && participant.station_id.as_str() == state.service_id()
        })
        .cloned()
        .ok_or_else(|| AppError::internal("checkpoint has no local proposer authority"))?;
    let unsigned = BilateralContinuityCheckpointProposal {
        core,
        checkpoint_digest,
        proposer_signature: BilateralContinuityCheckpointSignature {
            signer: local_signer.clone(),
            signature: placeholder_contact_signature(state, now())?,
        },
    };
    let proposer_signature = sign_checkpoint_participant(
        state,
        local_signer,
        &unsigned
            .signing_bytes()
            .map_err(|error| AppError::internal(error.to_string()))?,
    )?;
    Ok(BilateralContinuityCheckpointProposal {
        proposer_signature,
        ..unsigned
    })
}

pub(crate) fn checkpoint_tail(
    record: &ContactRecord,
    boundary: &Hash,
) -> Result<Vec<ContactRoundEvidenceBundle>, AppError> {
    let current = record
        .contact_round_evidence
        .as_ref()
        .ok_or_else(|| continuity_invalid("checkpoint current round unavailable"))?;
    let mut tail = vec![uncheckpointed_bundle(current)];
    for predecessor in &record.contact_round_evidence_history {
        if tail
            .last()
            .and_then(|bundle| bundle.previous_terminal_contact_round_id.as_ref())
            == Some(boundary)
        {
            break;
        }
        tail.push(uncheckpointed_bundle(predecessor));
    }
    if tail.len() > 64
        || tail
            .last()
            .and_then(|bundle| bundle.previous_terminal_contact_round_id.as_ref())
            != Some(boundary)
    {
        return Err(continuity_invalid(
            "checkpoint tail does not terminate at the accepted boundary",
        ));
    }
    Ok(tail)
}

pub(crate) fn committed_continuity_evidence(
    record: &ContactRecord,
) -> Option<ContactContinuityEvidence> {
    let checkpoint = latest_continuity_checkpoint(record)?;
    let mut tail =
        checkpoint_tail(record, &checkpoint.core.covered_through_contact_round_id).ok()?;
    tail.first_mut()?.continuity_checkpoint = Some(checkpoint.clone());
    arkret_models_collaboration::contact_operations::validate_recontact_continuity(
        &tail[0],
        &tail[1..],
    )
    .ok()?;
    Some(ContactContinuityEvidence {
        checkpoint,
        uncompressed_tail_entries: tail,
    })
}

fn prune_history_to_checkpoint(
    record: &mut ContactRecord,
    checkpoint: &BilateralContinuityCheckpoint,
) -> Result<(), AppError> {
    let boundary = &checkpoint.core.covered_through_contact_round_id;
    let boundary_index = record
        .contact_round_evidence_history
        .iter()
        .position(|bundle| &bundle.contact_round_id == boundary)
        .ok_or_else(|| {
            continuity_invalid(
                "continuity checkpoint boundary is absent from durable Contact history",
            )
        })?;
    // History is newest-to-oldest. Keep only the explicit tail newer than the
    // checkpoint boundary; the boundary and everything older are represented
    // exclusively by the signed accumulator.
    record
        .contact_round_evidence_history
        .truncate(boundary_index);
    // Checkpoint attachments are unsigned carrier metadata. The new current
    // bundle owns the committed checkpoint; retained predecessors must not
    // keep an older checkpoint that conflicts with this bounded tail.
    for predecessor in &mut record.contact_round_evidence_history {
        predecessor.continuity_checkpoint = None;
    }
    Ok(())
}

pub(crate) fn complete_same_service_checkpoint(
    state: &AppState,
    proposal: &BilateralContinuityCheckpointProposal,
) -> Result<BilateralContinuityCheckpoint, AppError> {
    let peer_signer = proposal
        .core
        .participants
        .iter()
        .find(|participant| *participant != &proposal.proposer_signature.signer)
        .cloned()
        .ok_or_else(|| AppError::internal("same-service checkpoint peer authority missing"))?;
    if peer_signer.station_id.as_str() != state.service_id() {
        return Err(AppError::internal(
            "same-service checkpoint selected a remote authority",
        ));
    }
    let mut signatures = [
        proposal.proposer_signature.clone(),
        sign_checkpoint_participant(
            state,
            peer_signer,
            &proposal
                .signing_bytes()
                .map_err(|error| AppError::internal(error.to_string()))?,
        )?,
    ];
    signatures.sort_by(|left, right| left.signer.cmp(&right.signer));
    let checkpoint = BilateralContinuityCheckpoint {
        core: proposal.core.clone(),
        checkpoint_digest: proposal.checkpoint_digest.clone(),
        signatures,
    };
    checkpoint
        .validate_contact_shape()
        .map_err(|error| AppError::internal(format!("same-service checkpoint: {error}")))?;
    Ok(checkpoint)
}

pub(crate) async fn install_checkpoint_with_result(
    state: &AppState,
    holder: &arkret_wire::ActorId,
    peer: &arkret_wire::ActorId,
    checkpoint: &BilateralContinuityCheckpoint,
    result: coland_services::jobs::IdempotencyState,
) -> Result<bool, AppError> {
    let contacts = state.contacts();
    let mut record = contacts
        .contact_any(holder, peer)
        .await
        .map_err(|e| AppError::internal(e.to_string()))?
        .ok_or_else(|| continuity_invalid("checkpoint Contact disappeared"))?;
    let peer_account = peer
        .as_account_id()
        .ok_or_else(|| continuity_invalid("checkpoint peer is not an Account"))?;
    if record
        .peer_host_id
        .as_ref()
        .is_some_and(|id| id != &peer_account.station_id)
        || (peer_account.station_id != state.service_core_id() && record.peer_host_id.is_none())
    {
        return Err(continuity_invalid("checkpoint peer service changed"));
    }
    let already_installed = latest_continuity_checkpoint(&record)
        .is_some_and(|old| old.checkpoint_digest == checkpoint.checkpoint_digest);
    if !already_installed {
        let expected = checkpoint_core_at_boundary(
            state,
            &record,
            holder.signing_principal_id().as_str(),
            &checkpoint.core.covered_through_contact_round_id,
        )?;
        if expected != checkpoint.core {
            return Err(continuity_invalid("checkpoint frozen prefix changed"));
        }
        record
            .contact_round_evidence
            .as_mut()
            .ok_or_else(|| continuity_invalid("checkpoint current missing"))?
            .continuity_checkpoint = Some(checkpoint.clone());
        prune_history_to_checkpoint(&mut record, checkpoint)?;
    }
    let previous = record.updated_at;
    advance_contact_revision(&mut record, previous);
    contacts
        .save_contact_with_result(previous, record, result)
        .await
        .map_err(|e| AppError::internal(e.to_string()))
}

pub(crate) async fn accept_outbound_continuity_checkpoint_outcome(
    state: &AppState,
    request: &PeerContactSubmitRequestBody,
    outcome: &PeerContactSubmitOutcome,
    peer_id: &str,
) -> Result<(), AppError> {
    let PeerContactSubmitRequestBody::ContinuityCheckpoint {
        proposal,
        contact_address,
        idempotency_key,
    } = request
    else {
        return Err(AppError::internal(
            "outbound continuity outcome paired with another request kind",
        ));
    };
    let PeerContactSubmitOutcome::Control(PeerContactControlSubmitOutcome::ContinuityCheckpoint {
        status,
        control_receipt,
        checkpoint,
    }) = outcome
    else {
        return Err(AppError::internal(
            "outbound continuity request returned another outcome kind",
        ));
    };
    if !matches!(
        status,
        PeerContactOutcome::Accepted | PeerContactOutcome::Duplicate
    ) || control_receipt.request_kind != PeerContactControlKind::ContinuityCheckpoint
        || control_receipt.outcome != *status
        || control_receipt.issuer_id.as_str() != peer_id
        || control_receipt.recipient_id.as_str() != peer_id
        || control_receipt.result_digest
            != Some(super::account::canonical_contact_digest(checkpoint)?)
        || checkpoint.checkpoint_digest != proposal.checkpoint_digest
        || canonical::canonical_json_bytes(&checkpoint.core)
            .map_err(|error| AppError::internal(error.to_string()))?
            != canonical::canonical_json_bytes(&proposal.core)
                .map_err(|error| AppError::internal(error.to_string()))?
    {
        return Err(continuity_invalid(
            "peer continuity outcome does not bind the proposal",
        ));
    }
    if control_receipt.request_digest != super::account::canonical_contact_digest(request)? {
        return Err(continuity_invalid(
            "checkpoint receipt names another request",
        ));
    }
    verify_contact_evidence_signature(
        state,
        peer_id,
        &control_receipt.signature,
        &contact_control_receipt_signing_bytes(control_receipt)?,
        "continuity_checkpoint.control_receipt",
    )?;
    checkpoint
        .validate_contact_shape()
        .map_err(|error| continuity_invalid(format!("peer checkpoint invalid: {error}")))?;
    let signing_bytes = checkpoint
        .signing_bytes()
        .map_err(|error| AppError::internal(error.to_string()))?;
    for signature in &checkpoint.signatures {
        verify_contact_service_signature_bytes(
            state,
            signature.signer.station_id.as_str(),
            &signature.signature,
            &signing_bytes,
            "continuity_checkpoint.signature",
        )?;
    }
    let local_actor = arkret_wire::ActorId::account(proposal.proposer_signature.signer.clone());
    let remote_actor = contact_address.recipient.contact_actor_id();
    let original =
        arkret_models_collaboration::contact_operations::ContactContinuityCheckpointRequestBody {
            idempotency_key: idempotency_key.clone(),
            peer: contact_address.recipient.clone(),
        };
    if let Some(completed) = super::account::contact_checkpoint::completed_request(
        state,
        &proposal.proposer_signature.signer,
        &original,
    )
    .await?
    {
        if completed.checkpoint_digest != proposal.checkpoint_digest {
            return Err(continuity_invalid(
                "completed checkpoint changed its frozen core",
            ));
        }
        return Ok(());
    }
    let plan = super::account::contact_checkpoint::frozen_outbound_plan(state, request).await?;
    let outcome = plan.outcome(checkpoint.clone())?;
    let result = plan.result_record(&outcome)?;
    if state
        .jobs()
        .scoped_idempotency_record(
            &result.authenticated_actor,
            &result.operation_id,
            &result.idempotency_key,
        )
        .await
        .map_err(|e| AppError::internal(e.to_string()))?
        .is_some()
    {
        return Ok(());
    }
    if !install_checkpoint_with_result(state, &local_actor, &remote_actor, checkpoint, result)
        .await?
    {
        return Err(crate::app_error!(
            TemporarilyUnavailable,
            "checkpoint changed during acceptance"
        ));
    }
    Ok(())
}

fn sign_checkpoint_participant(
    state: &AppState,
    signer: AccountId,
    signing_bytes: &[u8],
) -> Result<BilateralContinuityCheckpointSignature, AppError> {
    Ok(BilateralContinuityCheckpointSignature {
        signer,
        signature: sign_contact_evidence_bytes(state, now(), signing_bytes)?,
    })
}

async fn finalize_continuity_checkpoint(
    state: &AppState,
    request: &PeerContactSubmitRequestBody,
    source_id: &str,
    proposal: &BilateralContinuityCheckpointProposal,
    contact_address: &PeerContactAddress,
) -> Result<PeerContactSubmitOutcome, AppError> {
    proposal.validate_shape().map_err(|error| {
        super::super::events::peer::schema_violation(format!(
            "invalid continuity checkpoint proposal: {error}"
        ))
    })?;
    if proposal.proposer_signature.signer.station_id.as_str() != source_id {
        return Err(super::super::events::peer::cross_domain_replay(
            "checkpoint proposer service does not match Source-Service-ID",
        ));
    }
    verify_contact_service_signature_bytes(
        state,
        source_id,
        &proposal.proposer_signature.signature,
        &proposal
            .signing_bytes()
            .map_err(|error| AppError::internal(error.to_string()))?,
        "continuity_checkpoint.proposer_signature",
    )?;
    let local_actor = contact_address.recipient.contact_actor_id();
    let remote_actor = arkret_wire::ActorId::account(proposal.proposer_signature.signer.clone());
    let contacts = state.contacts();
    let mut record = contacts
        .contact_any(&local_actor, &remote_actor)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| {
            crate::app_error!(
                FailedPrecondition,
                "checkpoint Contact lineage is unavailable",
            )
        })?;
    if record.peer_host_id.as_ref().map(|value| value.as_str()) != Some(source_id) {
        return Err(super::super::events::peer::cross_domain_replay(
            "checkpoint source service does not match durable Contact peer",
        ));
    }
    let request_digest = contact_control_request_digest(request)?;
    if let Some(outcome) = replayed_contact_control_outcome(
        &record,
        &request_digest,
        PeerContactControlKind::ContinuityCheckpoint,
    ) {
        return Ok(outcome);
    }
    let expected_core = checkpoint_core_at_boundary(
        state,
        &record,
        local_actor.signing_principal_id().as_str(),
        &proposal.core.covered_through_contact_round_id,
    )?;
    if bilateral_checkpoint_digest(&expected_core)
        .map_err(|error| AppError::internal(error.to_string()))?
        != proposal.checkpoint_digest
        || canonical::canonical_json_bytes(&expected_core)
            .map_err(|error| AppError::internal(error.to_string()))?
            != canonical::canonical_json_bytes(&proposal.core)
                .map_err(|error| AppError::internal(error.to_string()))?
    {
        return Err(continuity_invalid(
            "continuity checkpoint proposal does not match durable history",
        ));
    }
    if let Some(existing) = latest_continuity_checkpoint(&record)
        && existing.core.sequence == proposal.core.sequence
        && existing.checkpoint_digest != proposal.checkpoint_digest
    {
        return Err(continuity_invalid(
            "continuity checkpoint fork at the same sequence",
        ));
    }
    let local_signer = proposal
        .core
        .participants
        .iter()
        .find(|participant| participant.station_id.as_str() == state.service_id())
        .cloned()
        .ok_or_else(|| {
            super::super::events::peer::cross_domain_replay(
                "checkpoint has no local participant authority",
            )
        })?;
    let mut signatures = [
        proposal.proposer_signature.clone(),
        sign_checkpoint_participant(
            state,
            local_signer,
            &proposal
                .signing_bytes()
                .map_err(|error| AppError::internal(error.to_string()))?,
        )?,
    ];
    signatures.sort_by(|left, right| left.signer.cmp(&right.signer));
    let checkpoint = BilateralContinuityCheckpoint {
        core: proposal.core.clone(),
        checkpoint_digest: proposal.checkpoint_digest.clone(),
        signatures,
    };
    checkpoint
        .validate_contact_shape()
        .map_err(|error| AppError::internal(format!("completed checkpoint invalid: {error}")))?;
    let expected_updated_at = record.updated_at;
    let current = record.contact_round_evidence.as_mut().ok_or_else(|| {
        crate::app_error!(
            FailedPrecondition,
            "checkpoint current Contact evidence is unavailable",
        )
    })?;
    current.continuity_checkpoint = Some(checkpoint.clone());
    let result_digest = super::account::canonical_contact_digest(&checkpoint)?;
    let control_receipt = sign_contact_control_receipt(
        state,
        request,
        PeerContactControlKind::ContinuityCheckpoint,
        PeerContactOutcome::Accepted,
        Some(result_digest),
    )?;
    let outcome =
        PeerContactSubmitOutcome::Control(PeerContactControlSubmitOutcome::ContinuityCheckpoint {
            status: PeerContactOutcome::Accepted,
            control_receipt,
            checkpoint: checkpoint.clone(),
        });
    record.control_outcomes.push(outcome.clone());
    prune_history_to_checkpoint(&mut record, &checkpoint)?;
    advance_contact_revision(&mut record, expected_updated_at);
    save_contact_cas(contacts, expected_updated_at, record).await?;
    Ok(outcome)
}

pub(crate) fn validate_mirror_receipt_cryptography(
    state: &AppState,
    receipt: &PeerContactMirrorReceipt,
    expected_service_id: &str,
    field: &str,
) -> Result<(), AppError> {
    if receipt.issuer_id.as_str() != expected_service_id
        || receipt.recipient_id.as_str() != expected_service_id
        || !matches!(
            receipt.outcome,
            PeerContactOutcome::Accepted | PeerContactOutcome::Duplicate
        )
    {
        return Err(super::super::events::peer::cross_domain_replay(format!(
            "{field} issuer, recipient, or authoritative outcome is invalid"
        )));
    }
    let signing_bytes = receipt
        .canonical_signing_bytes()
        .map_err(|error| AppError::internal(format!("{field} transcript failed: {error}")))?;
    verify_contact_service_signature_bytes(
        state,
        expected_service_id,
        &receipt.signature,
        &signing_bytes,
        field,
    )
}

async fn validate_proof_refresh_evidence(
    state: &AppState,
    source_id: &str,
    prior_mirror_receipt: &PeerContactMirrorReceipt,
    current_proof: &ContactCurrentProof,
    contact_address: &PeerContactAddress,
) -> Result<(), AppError> {
    validate_mirror_receipt_cryptography(
        state,
        prior_mirror_receipt,
        state.service_id(),
        "prior_mirror_receipt",
    )?;
    let signing_bytes = current_proof
        .canonical_signing_bytes()
        .map_err(|error| AppError::internal(format!("current_proof transcript failed: {error}")))?;
    verify_contact_service_signature_bytes(
        state,
        source_id,
        &current_proof.signature,
        &signing_bytes,
        "current_proof",
    )?;
    let local_subject = contact_address.recipient.contact_actor_id();
    if current_proof.terminal
        || current_proof.issuer_id.as_str() != source_id
        || current_proof.peer.contact_actor_id() != local_subject
        || current_proof.head_event_ref != prior_mirror_receipt.signed_event_ref
        || current_proof.head_digest() != prior_mirror_receipt.signed_event_digest()
        || !current_proof
            .accepted_commit_event_ids
            .contains(&current_proof.head_event_ref)
        || current_proof.complete_through == 0
        || current_proof.fresh_until <= now()
    {
        return Err(super::super::events::peer::schema_violation(
            "Contact proof-refresh proof does not bind the mirrored immutable fact",
        ));
    }
    let contacts = state
        .contacts()
        .contacts_for_actor(&local_subject)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let durable_match = contacts.iter().any(|record| {
        let remote_is_requester = record.target_id == local_subject
            && record
                .requester_id
                .as_account_id()
                .is_some_and(|account| account.station_id.as_str() == source_id);
        let remote_is_target = record.requester_id == local_subject
            && record
                .target_id
                .as_account_id()
                .is_some_and(|account| account.station_id.as_str() == source_id);
        matches!(record.status.as_str(), "accepted" | "pending")
            && record.peer_host_id.as_ref().map(|value| value.as_str()) == Some(source_id)
            && record.contact_round_id.as_ref().map(|value| value.as_str())
                == Some(current_proof.contact_round_id.as_str())
            && (remote_is_requester || remote_is_target)
            && (record.request_receipts.iter().any(|stored| {
                stored.core.request_event_ref == current_proof.head_event_ref
                    && stored.core.request_digest() == current_proof.head_digest()
            }) || (remote_is_requester
                && record
                    .request_event_ref
                    .as_ref()
                    .map(|value| value.as_str())
                    == Some(current_proof.head_event_ref.as_str()))
                || (remote_is_target
                    && record
                        .response_event_ref
                        .as_ref()
                        .map(|value| value.as_str())
                        == Some(current_proof.head_event_ref.as_str())))
    });
    if !durable_match {
        return Err(crate::app_error!(
            FailedPrecondition,
            "proof_refresh durable Contact round/head evidence is unavailable",
        ));
    }
    Ok(())
}

async fn finalize_contact_proof_refresh(
    state: &AppState,
    request: &PeerContactSubmitRequestBody,
    source_id: &str,
    prior_mirror_receipt: &PeerContactMirrorReceipt,
    current_proof: &ContactCurrentProof,
    contact_address: &PeerContactAddress,
) -> Result<PeerContactSubmitOutcome, AppError> {
    let contacts = state.contacts();
    let local_subject = contact_address.recipient.contact_actor_id();
    let mut record = contacts
        .contacts_for_actor(&local_subject)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .into_iter()
        .find(|record| {
            (record.target_id == local_subject
                && record
                    .requester_id
                    .as_account_id()
                    .is_some_and(|account| account.station_id.as_str() == source_id))
                || (record.requester_id == local_subject
                    && record
                        .target_id
                        .as_account_id()
                        .is_some_and(|account| account.station_id.as_str() == source_id))
        })
        .ok_or_else(|| {
            crate::app_error!(
                FailedPrecondition,
                "proof-refresh Contact round is unavailable",
            )
        })?;
    let request_digest = contact_control_request_digest(request)?;
    if let Some(outcome) = replayed_contact_control_outcome(
        &record,
        &request_digest,
        PeerContactControlKind::ProofRefresh,
    ) {
        return Ok(outcome);
    }
    validate_proof_refresh_evidence(
        state,
        source_id,
        prior_mirror_receipt,
        current_proof,
        contact_address,
    )
    .await?;
    if record.peer_host_id.as_ref().map(|value| value.as_str()) != Some(source_id) {
        return Err(super::super::events::peer::cross_domain_replay(
            "proof-refresh source service does not match durable Contact peer",
        ));
    }
    let mut bundle = record.contact_round_evidence.clone().ok_or_else(|| {
        crate::app_error!(
            FailedPrecondition,
            "proof-refresh Contact round evidence is unavailable",
        )
    })?;
    if bundle.contact_round_id != current_proof.contact_round_id
        || bundle.glare_concurrency_attestations.is_none()
    {
        return Err(super::super::events::peer::schema_violation(
            "proof-refresh does not bind the durable glare contact_round",
        ));
    }
    if bundle.current_proofs.iter().any(|proof| {
        proof.peer == current_proof.peer
            && (proof.fresh_until >= current_proof.fresh_until
                || proof.complete_through > current_proof.complete_through)
    }) {
        return Err(super::super::events::peer::schema_violation(
            "proof-refresh must advance the issuer's durable freshness/completeness proof",
        ));
    }
    bundle
        .current_proofs
        .retain(|proof| proof.peer != current_proof.peer);
    bundle.current_proofs.push(current_proof.clone());
    bundle.current_proofs.sort_by(|left, right| {
        left.peer
            .contact_actor_id()
            .cmp(&right.peer.contact_actor_id())
    });
    let pair_has_both_current_proofs = bundle.current_proofs.len() == 2
        && bundle.current_proofs.iter().all(|proof| {
            proof.contact_round_id == bundle.contact_round_id
                && !proof.terminal
                && proof.complete_through > 0
                && proof.fresh_until > now()
        });
    if pair_has_both_current_proofs {
        record.status = "accepted".to_owned();
        record.request_receipts.clear();
        record.request_mirror_receipts.clear();
    }
    let expected_updated_at = record.updated_at;
    record.contact_round_evidence = Some(bundle);
    advance_contact_revision(&mut record, expected_updated_at);
    let result_digest = super::account::canonical_contact_digest(current_proof)?;
    let control_receipt = sign_contact_control_receipt(
        state,
        request,
        PeerContactControlKind::ProofRefresh,
        PeerContactOutcome::Accepted,
        Some(result_digest),
    )?;
    let outcome =
        PeerContactSubmitOutcome::Control(PeerContactControlSubmitOutcome::ProofRefresh {
            status: PeerContactOutcome::Accepted,
            control_receipt,
            current_proof: current_proof.clone(),
        });
    record.control_outcomes.push(outcome.clone());
    save_contact_cas(contacts, expected_updated_at, record).await?;
    Ok(outcome)
}

#[allow(clippy::too_many_arguments)]
fn validate_glare_finalize_evidence(
    state: &AppState,
    source_id: &str,
    contact_round_id: &Hash,
    contact_round: &ContactRound,
    request_receipts: &[RequestAcceptanceReceipt; 2],
    remote_mirror_receipt: &PeerContactMirrorReceipt,
    attestation: &GlareConcurrencyAttestation,
    contact_address: &PeerContactAddress,
) -> Result<(), AppError> {
    validate_mirror_receipt_cryptography(
        state,
        remote_mirror_receipt,
        state.service_id(),
        "remote_mirror_receipt",
    )?;
    for (index, receipt) in request_receipts.iter().enumerate() {
        super::account::validate_request_receipt_cryptography(
            state,
            receipt,
            &format!("request_receipts[{index}]"),
        )?;
    }
    let addressed_subject = contact_address.recipient.contact_actor_id();
    if attestation.issuer_id.as_str() != source_id
        || attestation.peer_id != addressed_subject
        || attestation.subject_id == addressed_subject
    {
        return Err(super::super::events::peer::schema_violation(
            "glare_concurrency_attestation participant coordinates are invalid",
        ));
    }
    let signing_bytes = attestation.canonical_signing_bytes().map_err(|error| {
        AppError::internal(format!(
            "glare_concurrency_attestation transcript failed: {error}"
        ))
    })?;
    verify_contact_service_signature_bytes(
        state,
        source_id,
        &attestation.signature,
        &signing_bytes,
        "glare_concurrency_attestation",
    )?;

    contact_round
        .validate_canonical_order()
        .map_err(|error| super::super::events::peer::schema_violation(error.to_string()))?;
    let local_subject_actor = request_receipts
        .iter()
        .find(|receipt| receipt.core.issuer_id.as_str() == state.service_id())
        .map(|receipt| receipt.core.holder.contact_actor_id().clone())
        .ok_or_else(|| {
            super::super::events::peer::schema_violation(
                "glare request receipts have no local-service subject",
            )
        })?;
    if local_subject_actor != addressed_subject {
        return Err(super::super::events::peer::cross_domain_replay(
            "glare contact_address.recipient does not match the local receipt holder",
        ));
    }
    let expected_contact_round = ContactRound::glare_from_request_receipts(request_receipts)
        .map_err(|error| super::super::events::peer::schema_violation(error.to_string()))?;
    let ContactRound::Glare {
        requests: [first, second],
        ..
    } = &expected_contact_round
    else {
        unreachable!("glare constructor returns the glare branch")
    };
    if super::account::canonical_contact_digest(contact_round)?
        != super::account::canonical_contact_digest(&expected_contact_round)?
    {
        return Err(super::super::events::peer::schema_violation(
            "glare contact_round does not match the exact request receipts",
        ));
    }
    if &self::contact_round_id(&expected_contact_round)? != contact_round_id
        || attestation.request_receipt_digests
            != [
                first.request_acceptance_receipt_digest.clone(),
                second.request_acceptance_receipt_digest.clone(),
            ]
        || !attestation
            .observed_commit_event_ids
            .contains(&first.request_event_ref)
        || !attestation
            .observed_commit_event_ids
            .contains(&second.request_event_ref)
        || attestation.complete_through == 0
    {
        return Err(super::super::events::peer::schema_violation(
            "glare contact_round/attestation digest or frontier coordinates are invalid",
        ));
    }
    let source_receipt = request_receipts
        .iter()
        .find(|receipt| receipt.core.issuer_id.as_str() == source_id)
        .ok_or_else(|| {
            super::super::events::peer::schema_violation(
                "glare request receipts have no source-service receipt",
            )
        })?;
    let local_receipt = request_receipts
        .iter()
        .find(|receipt| receipt.core.issuer_id.as_str() == state.service_id())
        .ok_or_else(|| {
            super::super::events::peer::schema_violation(
                "glare request receipts have no local-service counterpart receipt",
            )
        })?;
    if source_receipt.core.holder.contact_actor_id() != attestation.subject_id
        || source_receipt.core.peer.contact_actor_id() != addressed_subject
        || local_receipt.core.holder.contact_actor_id() != addressed_subject
        || local_receipt.core.peer.contact_actor_id() != attestation.subject_id
        || remote_mirror_receipt.signed_event_ref != source_receipt.core.request_event_ref
        || remote_mirror_receipt.signed_event_digest() != source_receipt.core.request_digest()
    {
        return Err(super::super::events::peer::schema_violation(
            "glare receipts, mirror, and participant request coordinates do not cross-bind",
        ));
    }
    Ok(())
}

fn verify_contact_service_signature_bytes(
    state: &AppState,
    expected_service_id: &str,
    signature: &ProtocolSignature,
    signing_bytes: &[u8],
    evidence_field: &str,
) -> Result<(), AppError> {
    // Checkpoint transcripts include a domain prefix; verify the exact SDK
    // bytes rather than parsing and reserializing them as a JSON value.
    super::account::verify_contact_service_signature_bytes(
        state,
        expected_service_id,
        signature,
        signing_bytes,
        evidence_field,
    )
}

#[allow(clippy::too_many_arguments)]
async fn finalize_glare_contact_round(
    state: &AppState,
    request: &PeerContactSubmitRequestBody,
    source_id: &str,
    contact_round_id: &Hash,
    contact_round: &ContactRound,
    request_receipts: &[RequestAcceptanceReceipt; 2],
    remote_mirror_receipt: &PeerContactMirrorReceipt,
    remote_attestation: &GlareConcurrencyAttestation,
    contact_address: &PeerContactAddress,
) -> Result<PeerContactSubmitOutcome, AppError> {
    let local_holder = request_receipts
        .iter()
        .find(|receipt| receipt.core.issuer_id.as_str() == state.service_id())
        .map(|receipt| receipt.core.holder.contact_actor_id())
        .ok_or_else(|| {
            super::super::events::peer::schema_violation(
                "glare request receipts have no local-service holder",
            )
        })?;
    let remote_holder = request_receipts
        .iter()
        .find(|receipt| receipt.core.issuer_id.as_str() == source_id)
        .map(|receipt| receipt.core.holder.contact_actor_id())
        .ok_or_else(|| {
            super::super::events::peer::schema_violation(
                "glare request receipts have no remote-service holder",
            )
        })?;
    let contacts = state.contacts();
    let mut record = contacts
        .contact_any(&local_holder, &remote_holder)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| {
            crate::app_error!(
                FailedPrecondition,
                "glare Contact request slot is unavailable",
            )
        })?;
    let request_digest = contact_control_request_digest(request)?;
    if let Some(outcome) = replayed_contact_control_outcome(
        &record,
        &request_digest,
        PeerContactControlKind::GlareFinalize,
    ) {
        return Ok(outcome);
    }
    validate_glare_finalize_evidence(
        state,
        source_id,
        contact_round_id,
        contact_round,
        request_receipts,
        remote_mirror_receipt,
        remote_attestation,
        contact_address,
    )?;
    if record.status != "pending" || record.contact_round_evidence.is_some() {
        return Err(AppError::conflict(
            "Contact request slot is already consumed",
        ));
    }

    let retained_receipts = record.request_receipts.clone();
    let retained = retained_receipts
        .iter()
        .map(super::account::canonical_contact_digest)
        .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
    let submitted = request_receipts
        .iter()
        .map(super::account::canonical_contact_digest)
        .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
    if retained.len() != 2 || retained != submitted {
        return Err(crate::app_error!(
            FailedPrecondition,
            "glare Contact request receipts are not durably complete",
        ));
    }
    let local_request = request_receipts
        .iter()
        .find(|receipt| receipt.core.holder.contact_actor_id() == local_holder)
        .ok_or_else(|| {
            super::super::events::peer::schema_violation(
                "glare receipts have no local-holder request",
            )
        })?;
    let Some(counterpart_mirror) = record
        .request_mirror_receipts
        .iter()
        .find(|receipt| {
            receipt.issuer_id.as_str() == source_id
                && receipt.signed_event_ref == local_request.core.request_event_ref
                && receipt.signed_event_digest() == local_request.core.request_digest()
                && matches!(
                    receipt.outcome,
                    PeerContactOutcome::Accepted | PeerContactOutcome::Duplicate
                )
        })
        .cloned()
    else {
        let control_receipt = sign_contact_control_receipt(
            state,
            request,
            PeerContactControlKind::GlareFinalize,
            PeerContactOutcome::Deferred,
            None,
        )?;
        return Ok(PeerContactSubmitOutcome::ControlDeferred(
            arkret_models_collaboration::contact_operations::PeerContactControlDeferredOutcome {
                status: PeerContactOutcome::Deferred,
                request_kind: PeerContactControlKind::GlareFinalize,
                control_receipt,
                retry_after_ms: Some(1_000),
            },
        ));
    };
    validate_mirror_receipt_cryptography(
        state,
        &counterpart_mirror,
        source_id,
        "counterpart_mirror_receipt",
    )?;

    let remote_request_ref = request_receipts
        .iter()
        .find(|receipt| receipt.core.holder.contact_actor_id() == remote_holder)
        .map(|receipt| receipt.core.request_event_ref.clone())
        .ok_or_else(|| {
            super::super::events::peer::schema_violation(
                "glare receipts have no remote-holder request",
            )
        })?;
    let (observed_commit_event_ids, complete_through) = glare_slot_observation(
        &record,
        &local_holder,
        &remote_holder,
        local_request,
        &remote_request_ref,
    )?;
    let mut request_refs = request_receipts
        .iter()
        .map(|receipt| receipt.core.request_event_ref.clone())
        .collect::<Vec<_>>();
    request_refs.sort_by(|left, right| left.as_str().as_bytes().cmp(right.as_str().as_bytes()));
    let ordered_digests: [Hash; 2] = request_refs
        .iter()
        .map(|event_ref| {
            request_receipts
                .iter()
                .find(|receipt| &receipt.core.request_event_ref == event_ref)
                .ok_or_else(|| {
                    super::super::events::peer::schema_violation(
                        "glare frontier does not bind exact request receipts",
                    )
                })
                .and_then(super::account::canonical_contact_digest)
        })
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| AppError::internal("glare receipt digest cardinality invalid"))?;
    let checkpoint = glare_unconsumed_slot_checkpoint(
        &local_holder,
        &remote_holder,
        contact_round_id,
        &ordered_digests,
        &observed_commit_event_ids,
        complete_through,
    )?;
    let observed_at = now();
    let mut local_attestation = GlareConcurrencyAttestation {
        subject_id: local_holder.clone(),
        issuer_id: state.service_core_id(),
        peer_id: remote_holder.clone(),
        request_receipt_digests: ordered_digests,
        observed_commit_event_ids: observed_commit_event_ids.clone(),
        complete_through,
        unconsumed_slot_checkpoint: checkpoint,
        observed_at,
        signature: placeholder_contact_signature(state, observed_at)?,
    };
    local_attestation.signature = sign_contact_assertion_evidence_bytes(
        state,
        observed_at,
        &local_attestation
            .canonical_signing_bytes()
            .map_err(|error| {
                AppError::internal(format!(
                    "local glare attestation transcript failed: {error}"
                ))
            })?,
    )
    .await?;

    let fresh_until = observed_at + chrono::Duration::minutes(10);
    let mut local_current_proof = ContactCurrentProof {
        contact_round_id: contact_round_id.clone(),
        issuer_id: state.service_core_id(),
        peer: local_request.core.peer.clone(),
        terminal: false,
        head_event_ref: local_request.core.request_event_ref.clone(),
        accepted_commit_event_ids: observed_commit_event_ids,
        complete_through: 1,
        fresh_until,
        signature: placeholder_contact_signature(state, observed_at)?,
    };
    local_current_proof.signature = sign_contact_assertion_evidence_bytes(
        state,
        observed_at,
        &local_current_proof
            .canonical_signing_bytes()
            .map_err(|error| {
                AppError::internal(format!(
                    "local Contact current proof transcript failed: {error}"
                ))
            })?,
    )
    .await?;

    let mut attestations = [remote_attestation.clone(), local_attestation.clone()];
    attestations.sort_by(|left, right| left.issuer_id.cmp(&right.issuer_id));
    let previous_terminal_contact_round_id = request_receipts
        .iter()
        .filter_map(|receipt| receipt.core.previous_terminal_contact_round_id.clone())
        .next();
    let partial_bundle = ContactRoundEvidenceBundle {
        contact_round_id: contact_round_id.clone(),
        previous_terminal_contact_round_id,
        contact_round: contact_round.clone(),
        request_receipts: request_receipts.to_vec(),
        normal_response_receipt: None,
        glare_concurrency_attestations: Some(attestations),
        // The receiver can author only its own current proof here. The peer's
        // proof arrives through the registered proof-refresh carrier; until
        // then this durable bundle remains tentative and cannot authorize a
        // Direct Conversation founding unit.
        current_proofs: vec![local_current_proof.clone()],
        continuity_checkpoint: None,
    };
    let expected_updated_at = record.updated_at;
    record.contact_round_id = Some(contact_round_id.clone());
    record.contact_round_evidence = Some(partial_bundle);
    record.updated_at = observed_at.max(expected_updated_at + chrono::Duration::microseconds(1));
    let result_digest = super::account::canonical_contact_digest(&json!({
        "glare_concurrency_attestation": local_attestation,
        "current_proof": local_current_proof,
    }))?;
    let control_receipt = sign_contact_control_receipt(
        state,
        request,
        PeerContactControlKind::GlareFinalize,
        PeerContactOutcome::Accepted,
        Some(result_digest),
    )?;
    let outcome =
        PeerContactSubmitOutcome::Control(PeerContactControlSubmitOutcome::GlareFinalize {
            status: PeerContactOutcome::Accepted,
            control_receipt,
            glare_concurrency_attestation: local_attestation,
            current_proof: Some(local_current_proof),
        });
    record.control_outcomes.push(outcome.clone());
    save_contact_cas(contacts, expected_updated_at, record).await?;
    Ok(outcome)
}

fn contact_control_request_digest(
    request: &PeerContactSubmitRequestBody,
) -> Result<Hash, AppError> {
    Hash::new(
        canonical::canonical_sha256(request)
            .map_err(|error| AppError::internal(format!("Contact control digest: {error}")))?,
    )
    .map_err(|error| AppError::internal(format!("Contact control digest invalid: {error}")))
}

fn replayed_contact_control_outcome(
    record: &ContactRecord,
    request_digest: &Hash,
    request_kind: PeerContactControlKind,
) -> Option<PeerContactSubmitOutcome> {
    record.control_outcomes.iter().find_map(|outcome| {
        let receipt = match outcome {
            PeerContactSubmitOutcome::Control(PeerContactControlSubmitOutcome::ProofRefresh {
                control_receipt,
                ..
            }) if request_kind == PeerContactControlKind::ProofRefresh => control_receipt,
            PeerContactSubmitOutcome::Control(PeerContactControlSubmitOutcome::GlareFinalize {
                control_receipt,
                ..
            }) if request_kind == PeerContactControlKind::GlareFinalize => control_receipt,
            PeerContactSubmitOutcome::Control(
                PeerContactControlSubmitOutcome::ContinuityCheckpoint {
                    control_receipt, ..
                },
            ) if request_kind == PeerContactControlKind::ContinuityCheckpoint => control_receipt,
            _ => return None,
        };
        (receipt.request_digest == *request_digest).then(|| outcome.clone())
    })
}

fn placeholder_contact_signature(
    state: &AppState,
    created_at: chrono::DateTime<chrono::Utc>,
) -> Result<ProtocolSignature, AppError> {
    Ok(ProtocolSignature {
        verification_method: DidUrl::new(
            crate::routing::federation::federation_service_signature_key_id(
                state.service_did().as_str(),
            ),
        )
        .map_err(|error| AppError::internal(format!("service key id invalid: {error}")))?,
        created_at,
        jws: "AA".to_owned(),
    })
}

fn sign_contact_evidence_bytes(
    state: &AppState,
    created_at: chrono::DateTime<chrono::Utc>,
    signing_bytes: &[u8],
) -> Result<ProtocolSignature, AppError> {
    let jws = super::account::contact_detached_jws(&state.notary_signing_key(), signing_bytes)?;
    Ok(ProtocolSignature {
        verification_method: DidUrl::new(
            crate::routing::federation::federation_service_signature_key_id(
                state.service_did().as_str(),
            ),
        )
        .map_err(|error| AppError::internal(format!("service key id invalid: {error}")))?,
        created_at,
        jws,
    })
}

async fn sign_contact_assertion_evidence_bytes(
    state: &AppState,
    created_at: chrono::DateTime<chrono::Utc>,
    signing_bytes: &[u8],
) -> Result<ProtocolSignature, AppError> {
    let (method, key) = super::account::contact_assertion_signer(state, created_at).await?;
    Ok(ProtocolSignature {
        verification_method: method,
        created_at,
        jws: super::account::contact_detached_jws(&key, signing_bytes)?,
    })
}

/// The local direction's terminal acknowledgement of a verified remote
/// tombstone (contact-and-direct-conversation.md section 3): it names the
/// shared source tombstone head and retains the local direction's last
/// confirmed version, read from this Station's own committed direction head.
/// Without that committed local material no completeness proof is signed.
pub(crate) async fn terminal_ack_contact_current_proof(
    state: &AppState,
    row: &ContactRecord,
    local_holder: &arkret_wire::ActorId,
    peer: ContactPeer,
    source: &ContactCurrentProof,
) -> Result<ContactCurrentProof, AppError> {
    let (local_head, complete_through) =
        super::account::local_direction_current(state, row, local_holder)
            .await?
            .ok_or_else(|| {
                crate::app_error!(
                    TemporarilyUnavailable,
                    "local Contact direction history is incomplete for terminal acknowledgement"
                )
            })?;
    let issued_at = now();
    let (method, key) = super::account::contact_assertion_signer(state, issued_at).await?;
    ContactCurrentProof::sign_with(
        source.contact_round_id.clone(),
        state.service_core_id(),
        peer,
        true,
        source.head_event_ref.clone(),
        coland_domain::identity::contact_event_prefix([&local_head, &source.head_event_ref]),
        complete_through,
        issued_at + chrono::Duration::minutes(10),
        |bytes| {
            Ok(ProtocolSignature {
                verification_method: method.clone(),
                created_at: issued_at,
                jws: super::account::contact_detached_jws(&key, bytes)
                    .map_err(|error| arkret_wire::WireError::Protocol(error.to_string()))?,
            })
        },
    )
    .map_err(|error| AppError::internal(error.to_string()))
}

fn normal_contact_round(
    receipt: &RequestAcceptanceReceipt,
) -> Result<(ContactRound, Hash), AppError> {
    let mut participants = [
        receipt.core.holder.contact_actor_id().clone(),
        receipt.core.peer.contact_actor_id().clone(),
    ];
    participants.sort();
    let contact_round = ContactRound::Normal {
        sorted_pair_member_ids: participants,
        request_event_ref: receipt.core.request_event_ref.clone(),
        request_acceptance_receipt_digest: super::account::canonical_contact_digest(receipt)?,
    };
    let contact_round_id = contact_round_id(&contact_round)?;
    Ok((contact_round, contact_round_id))
}

fn validate_contact_lineage_carrier(
    state: &AppState,
    source_id: &str,
    event: &Event,
    lineage: &arkret_models_collaboration::contact_operations::ContactLineage,
    current_proof: &arkret_models_collaboration::contact_operations::ContactCurrentProof,
    terminal: bool,
) -> Result<(), AppError> {
    if lineage.event_ref != event.event_id
        || lineage.issuer.contact_actor_id() != event.actor_id
        || lineage.contact_round_id != current_proof.contact_round_id
        || current_proof.head_event_ref != event.event_id
        || terminal != lineage.terminal.unwrap_or(false)
    {
        return Err(super::super::events::peer::schema_violation(
            "Contact lineage/current proof does not bind signed_event",
        ));
    }
    match &event.kind {
        arkret_wire::EventKind::ContactScopeUpdate => {
            let payload = serde_json::from_value::<ContactScopeUpdatePayload>(
                serde_json::to_value(&event.payload).map_err(|error| {
                    AppError::internal(format!("Contact scope payload encode: {error}"))
                })?,
            )
            .map_err(|_| {
                super::super::events::peer::schema_violation(
                    "invalid ak.contact.scope.update payload",
                )
            })?;
            if lineage.peer != payload.peer
                || lineage.contact_round_id != payload.contact_round_id
                || lineage.version != payload.version
                || lineage.predecessor_event_ref.as_ref() != Some(&payload.predecessor_event_ref)
                || lineage.granted_to_peer_scopes != payload.granted_to_peer_scopes
            {
                return Err(super::super::events::peer::schema_violation(
                    "Contact scope lineage does not bind the signed payload",
                ));
            }
        }
        arkret_wire::EventKind::ContactTombstone => {
            let payload = serde_json::from_value::<ContactTombstonedPayload>(
                serde_json::to_value(&event.payload).map_err(|error| {
                    AppError::internal(format!("Contact tombstone payload encode: {error}"))
                })?,
            )
            .map_err(|_| {
                super::super::events::peer::schema_violation("invalid ak.contact.tombstone payload")
            })?;
            if lineage.peer != payload.peer
                || lineage.contact_round_id != payload.contact_round_id
                || lineage.version != payload.version
                || lineage.predecessor_event_ref.as_ref() != Some(&payload.predecessor_event_ref)
                || !lineage.granted_to_peer_scopes.is_empty()
            {
                return Err(super::super::events::peer::schema_violation(
                    "Contact tombstone lineage does not bind the signed payload",
                ));
            }
        }
        _ => {
            return Err(super::super::events::peer::schema_violation(
                "Contact lineage carrier has an invalid Event kind",
            ));
        }
    }
    let mut signing_value = serde_json::to_value(lineage)
        .map_err(|error| AppError::internal(format!("Contact lineage encode: {error}")))?;
    signing_value
        .as_object_mut()
        .ok_or_else(|| AppError::internal("Contact lineage must encode as an object"))?
        .remove("signature");
    let signing_bytes = canonical::canonical_json_bytes(&signing_value)
        .map_err(|error| AppError::internal(format!("Contact lineage transcript: {error}")))?;
    verify_contact_evidence_signature(
        state,
        source_id,
        &lineage.signature,
        &signing_bytes,
        "carrier_lineage",
    )?;
    Ok(())
}

fn sign_contact_mirror_receipt(
    state: &AppState,
    request: &PeerContactSubmitRequestBody,
    event: &Event,
    outcome: PeerContactOutcome,
) -> Result<PeerContactMirrorReceipt, AppError> {
    let request_digest = Hash::new(
        canonical::canonical_sha256(request)
            .map_err(|error| AppError::internal(format!("Contact request digest: {error}")))?,
    )
    .map_err(|error| AppError::internal(format!("Contact request digest invalid: {error}")))?;
    let signed_event_digest = event.event_id.event_digest();
    if event_digest_for_frozen_claim(event, &signed_event_digest)? != signed_event_digest {
        return Err(super::super::events::peer::schema_violation(
            "Contact EventId does not match its canonical digest",
        ));
    }
    let received_at = now();
    let issuer = arkret_identifiers::DidCoreId::new(state.service_id().clone())
        .map_err(|error| AppError::internal(format!("service DID invalid: {error}")))?;
    let verification_method = DidUrl::new(
        crate::routing::federation::federation_service_signature_key_id(
            state.service_did().as_str(),
        ),
    )
    .map_err(|error| AppError::internal(format!("service verification method invalid: {error}")))?;
    let signing_bytes = canonical::canonical_json_bytes(&json!({
            "domain": arkret_wire::DomainSeparationId::PEER_CONTACT_MIRROR_RECEIPT_V1,
        "request_digest": request_digest,
        "signed_event_ref": event.event_id,
        "outcome": outcome,
        "recipient_id": issuer,
        "received_at": arkret_canonical::format_timestamp_canonical(received_at),
        "issuer_id": issuer,
    }))
    .map_err(|error| AppError::internal(format!("Contact mirror receipt canonicalize: {error}")))?;
    let jws = super::account::contact_detached_jws(&state.notary_signing_key(), &signing_bytes)?;
    Ok(PeerContactMirrorReceipt {
        domain: PeerContactMirrorReceiptDomain::V1,
        request_digest,
        signed_event_ref: event.event_id.clone(),
        outcome,
        recipient_id: issuer.clone(),
        received_at,
        issuer_id: issuer,
        signature: ProtocolSignature {
            verification_method,
            created_at: received_at,
            jws,
        },
    })
}

pub(crate) async fn persist_request_mirror_receipt(
    state: &AppState,
    holder: &arkret_wire::ActorId,
    peer: &arkret_wire::ActorId,
    receipt: &PeerContactMirrorReceipt,
) -> Result<(), AppError> {
    let contacts = state.contacts();
    let mut record = contacts
        .contact_any(holder, peer)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| {
            crate::app_error!(
                FailedPrecondition,
                "Contact request slot is unavailable for mirror receipt",
            )
        })?;
    let binds_retained_request = record.request_receipts.iter().any(|stored| {
        stored.core.request_event_ref == receipt.signed_event_ref
            && stored.core.request_digest() == receipt.signed_event_digest()
    });
    if !binds_retained_request {
        return Err(super::super::events::peer::schema_violation(
            "mirror receipt does not bind a retained Contact request receipt",
        ));
    }
    let receipt_digest = super::account::canonical_contact_digest(receipt)?;
    let already_stored = record.request_mirror_receipts.iter().any(|stored| {
        super::account::canonical_contact_digest(stored)
            .is_ok_and(|digest| digest == receipt_digest)
    });
    if !already_stored {
        let expected_updated_at = record.updated_at;
        record.request_mirror_receipts.push(receipt.clone());
        advance_contact_revision(&mut record, expected_updated_at);
        save_contact_cas(contacts, expected_updated_at, record).await?;
    }
    Ok(())
}

/// Continue the sender half of the Contact glare protocol from durable state.
///
/// This is deliberately called from both places that can complete the four
/// prerequisite receipts: the inbound reverse-request handler and the durable
/// outbox response handler. Only the holder whose canonically first request
/// Event is retained is allowed to originate `glare_finalize`, so two servers
/// never elect themselves from local arrival order. The idempotency key and
/// signed attestation are derived from the stable persisted row; replay after
/// lease expiry therefore reconstructs byte-identical carrier JSON.
pub(crate) async fn enqueue_glare_finalize_if_ready(
    state: &AppState,
    holder: &arkret_wire::ActorId,
    peer: &arkret_wire::ActorId,
) -> Result<bool, AppError> {
    let Some(record) = state
        .contacts()
        .contact_any(holder, peer)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
    else {
        return Ok(false);
    };
    if record.status != "pending"
        || record.contact_round_evidence.is_some()
        || record.request_receipts.len() != 2
    {
        return Ok(false);
    }
    let Some(peer_id) = record.peer_host_id.as_ref().map(|value| value.as_str()) else {
        return Ok(false);
    };
    let mut receipts = record.request_receipts.clone();
    receipts.sort_by(|left, right| {
        arkret_models_collaboration::contact_operations::compare_contact_request_event_refs(
            &left.core.request_event_ref,
            &right.core.request_event_ref,
        )
    });
    if receipts[0].core.holder.contact_actor_id() != *holder
        || receipts[0].core.peer.contact_actor_id() != *peer
        || receipts[1].core.holder.contact_actor_id() != *peer
        || receipts[1].core.peer.contact_actor_id() != *holder
    {
        // The other holder is the unique canonical glare initiator, or the
        // retained receipts do not form the exact reverse-request pair.
        return Ok(false);
    }
    let request_receipts: [RequestAcceptanceReceipt; 2] = receipts
        .try_into()
        .map_err(|_| AppError::internal("glare request receipt cardinality invalid"))?;
    let local_request = &request_receipts[0];
    let Some(remote_mirror_receipt) = record
        .request_mirror_receipts
        .iter()
        .find(|receipt| {
            receipt.issuer_id.as_str() == peer_id
                && receipt.signed_event_ref == local_request.core.request_event_ref
                && receipt.signed_event_digest() == local_request.core.request_digest()
                && matches!(
                    receipt.outcome,
                    PeerContactOutcome::Accepted | PeerContactOutcome::Duplicate
                )
        })
        .cloned()
    else {
        return Ok(false);
    };
    validate_mirror_receipt_cryptography(
        state,
        &remote_mirror_receipt,
        peer_id,
        "glare_remote_mirror_receipt",
    )?;
    let (observed_commit_event_ids, complete_through) = glare_slot_observation(
        &record,
        holder,
        peer,
        local_request,
        &request_receipts[1].core.request_event_ref,
    )?;

    let (contact_round_id, contact_round, receipt_digests) = derive_glare_basis(&request_receipts)?;
    let observed_at = record.updated_at;
    let checkpoint = glare_unconsumed_slot_checkpoint(
        holder,
        peer,
        &contact_round_id,
        &receipt_digests,
        &observed_commit_event_ids,
        complete_through,
    )?;
    let mut attestation = GlareConcurrencyAttestation {
        subject_id: holder.clone(),
        issuer_id: state.service_core_id(),
        peer_id: peer.clone(),
        request_receipt_digests: receipt_digests,
        observed_commit_event_ids,
        complete_through,
        unconsumed_slot_checkpoint: checkpoint,
        observed_at,
        signature: placeholder_contact_signature(state, observed_at)?,
    };
    attestation.signature = sign_contact_assertion_evidence_bytes(
        state,
        observed_at,
        &attestation.canonical_signing_bytes().map_err(|error| {
            AppError::internal(format!("glare attestation transcript failed: {error}"))
        })?,
    )
    .await?;
    // The signed reverse request supplies the full recipient AccountId. A
    // service route supplies transport coordinates only; the carrier keeps
    // that exact principal and the receiver revalidates it independently.
    let recipient = request_receipts[1].core.holder.clone();
    let route = crate::routing::federation::resolved_peer_route(
        state,
        peer_id,
        PeerContactAddress::RECIPIENT_SERVICE_KIND,
        false,
    )
    .await
    .map_err(|error| {
        crate::app_error!(
            FailedPrecondition,
            format!("glare recipient route: {error}"),
        )
    })?;
    let contact_address = PeerContactAddress::for_recipient(
        recipient,
        arkret_models_identity::ServiceResolutionCarrier::ResolutionUrl {
            resolution_url: format!(
                "{}{}",
                route.base_url(),
                arkret_models_identity::canonical_service_resolution_path(route.service_id())
                    .trim_start_matches('/'),
            ),
        },
    );
    let delivery = PeerContactSubmitRequestBody::GlareFinalize {
        idempotency_key: IdempotencyKey::new(format!("peer-contact-glare:{contact_round_id}"))
            .map_err(|error| AppError::internal(error.to_string()))?,
        contact_round_id,
        contact_round,
        request_receipts,
        remote_mirror_receipt,
        glare_concurrency_attestation: attestation,
        contact_address,
    };
    enqueue_peer_contact_carrier(state, peer_id, &delivery).await
}

fn derive_glare_basis(
    request_receipts: &[RequestAcceptanceReceipt; 2],
) -> Result<(Hash, ContactRound, [Hash; 2]), AppError> {
    let contact_round = ContactRound::glare_from_request_receipts(request_receipts)
        .map_err(|error| super::super::events::peer::schema_violation(error.to_string()))?;
    let ContactRound::Glare { requests, .. } = &contact_round else {
        unreachable!("glare constructor returns the glare branch")
    };
    let receipt_digests = requests
        .each_ref()
        .map(|request| request.request_acceptance_receipt_digest.clone());
    let contact_round_id = contact_round_id(&contact_round)?;
    Ok((contact_round_id, contact_round, receipt_digests))
}

/// The glare observation of `subject`'s own request slot toward `peer`
/// (contact-and-direct-conversation.md section 2): the slot must still stand
/// exactly at the CAS that accepted `own_request` (`pending_unconsumed`), and
/// the observed Commit prefix is the slot's durable accepted Event prefix
/// plus the concurrent `peer_request_ref`. Returns that prefix and the slot's
/// `complete_through` sequence.
fn glare_slot_observation(
    record: &ContactRecord,
    subject: &arkret_wire::ActorId,
    peer: &arkret_wire::ActorId,
    own_request: &RequestAcceptanceReceipt,
    peer_request_ref: &arkret_wire::EventId,
) -> Result<(Vec<arkret_wire::EventId>, u64), AppError> {
    let slot = record
        .request_slot_states
        .iter()
        .find(|state| &state.owner_id == subject && &state.peer_id == peer)
        .ok_or_else(|| {
            crate::app_error!(
                FailedPrecondition,
                "glare local request slot is unavailable",
            )
        })?;
    if slot.accepted_sequence != own_request.core.slot_version
        || !slot
            .accepted_event_refs
            .contains(&own_request.core.request_event_ref)
    {
        return Err(AppError::conflict(
            "Contact request slot is already consumed",
        ));
    }
    Ok((
        slot.prefix_with(std::slice::from_ref(peer_request_ref)),
        slot.accepted_sequence,
    ))
}

fn contact_round_id(contact_round: &ContactRound) -> Result<Hash, AppError> {
    contact_round.validate_canonical_order().map_err(|error| {
        super::super::events::peer::schema_violation(format!("Contact round order: {error}"))
    })?;
    Hash::new(
        canonical::domain_prefixed_canonical_sha256("ak.contact.round.v1", contact_round)
            .map_err(|error| AppError::internal(format!("Contact round digest: {error}")))?,
    )
    .map_err(|error| AppError::internal(format!("Contact round digest: {error}")))
}

fn glare_unconsumed_slot_checkpoint(
    subject_id: &arkret_wire::ActorId,
    peer_id: &arkret_wire::ActorId,
    contact_round_id: &Hash,
    request_receipt_digests: &[Hash; 2],
    observed_commit_event_ids: &[arkret_identifiers::EventId],
    complete_through: u64,
) -> Result<Hash, AppError> {
    let transcript = json!({
        "subject_id": subject_id,
        "peer_id": peer_id,
        "contact_round_id": contact_round_id,
        "request_receipt_digests": request_receipt_digests,
        "observed_commit_event_ids": observed_commit_event_ids,
        "complete_through": complete_through,
        "slot_state": "pending_unconsumed",
    });
    Hash::new(
        canonical::domain_prefixed_canonical_sha256(
            arkret_wire::DomainSeparationId::CONTACT_GLARE_UNCONSUMED_SLOT_V1,
            &transcript,
        )
        .map_err(|error| AppError::internal(format!("glare checkpoint encode: {error}")))?,
    )
    .map_err(|error| AppError::internal(format!("glare checkpoint digest: {error}")))
}

pub(crate) async fn accept_outbound_contact_control_outcome(
    state: &AppState,
    request: &PeerContactSubmitRequestBody,
    outcome: &PeerContactSubmitOutcome,
    peer_id: &str,
) -> Result<(), AppError> {
    match (request, outcome) {
        (
            PeerContactSubmitRequestBody::GlareFinalize {
                contact_round_id,
                contact_round,
                request_receipts,
                remote_mirror_receipt,
                glare_concurrency_attestation: local_attestation,
                contact_address,
                ..
            },
            PeerContactSubmitOutcome::Control(PeerContactControlSubmitOutcome::GlareFinalize {
                status: PeerContactOutcome::Accepted | PeerContactOutcome::Duplicate,
                control_receipt,
                glare_concurrency_attestation: remote_attestation,
                current_proof: Some(remote_proof),
            }),
        ) => {
            validate_outbound_control_receipt(
                state,
                request,
                control_receipt,
                PeerContactControlKind::GlareFinalize,
                peer_id,
                Some(super::account::canonical_contact_digest(&json!({
                    "glare_concurrency_attestation": remote_attestation,
                    "current_proof": remote_proof,
                }))?),
            )?;
            let (derived_contact_round_id, derived_basis, receipt_digests) =
                derive_glare_basis(request_receipts)?;
            if &derived_contact_round_id != contact_round_id
                || serde_json::to_value(&derived_basis)
                    .map_err(|error| AppError::internal(format!("glare contact_round: {error}")))?
                    != serde_json::to_value(contact_round).map_err(|error| {
                        AppError::internal(format!("glare contact_round: {error}"))
                    })?
                || remote_attestation.issuer_id.as_str() != peer_id
                || remote_attestation.subject_id != contact_address.recipient.contact_actor_id()
                || remote_attestation.peer_id != local_attestation.subject_id
                || local_attestation.peer_id != remote_attestation.subject_id
                || remote_attestation.request_receipt_digests != receipt_digests
                || remote_proof.contact_round_id != *contact_round_id
                || remote_proof.issuer_id.as_str() != peer_id
                || remote_proof.peer.contact_actor_id() != local_attestation.subject_id
                || remote_proof.terminal
                || remote_proof.fresh_until <= now()
            {
                return Err(super::super::events::peer::schema_violation(
                    "glare finalize outcome does not bind the outbound request",
                ));
            }
            let remote_request = request_receipts
                .iter()
                .find(|receipt| {
                    receipt.core.holder.contact_actor_id()
                        == contact_address.recipient.contact_actor_id()
                })
                .ok_or_else(|| {
                    super::super::events::peer::schema_violation(
                        "glare finalize has no remote-holder request receipt",
                    )
                })?;
            if remote_proof.head_event_ref != remote_request.core.request_event_ref
                || remote_proof.head_digest() != remote_request.core.request_digest()
                || !remote_proof
                    .accepted_commit_event_ids
                    .contains(&remote_proof.head_event_ref)
                || remote_attestation.complete_through == 0
                || !request_receipts.iter().all(|receipt| {
                    // The peer's slot prefix must have observed both requests;
                    // it may also hold that slot's earlier accepted Events.
                    remote_attestation
                        .observed_commit_event_ids
                        .contains(&receipt.core.request_event_ref)
                })
            {
                return Err(super::super::events::peer::schema_violation(
                    "glare finalize outcome proof/frontier is incomplete",
                ));
            }
            verify_contact_evidence_signature(
                state,
                peer_id,
                &remote_attestation.signature,
                &remote_attestation
                    .canonical_signing_bytes()
                    .map_err(|error| {
                        AppError::internal(format!("remote glare attestation transcript: {error}"))
                    })?,
                "remote_glare_attestation",
            )?;
            verify_contact_evidence_signature(
                state,
                peer_id,
                &remote_proof.signature,
                &remote_proof.canonical_signing_bytes().map_err(|error| {
                    AppError::internal(format!("remote Contact current proof transcript: {error}"))
                })?,
                "remote_current_proof",
            )?;

            let local_holder = request_receipts
                .iter()
                .find(|receipt| receipt.core.issuer_id == local_attestation.issuer_id)
                .map(|receipt| receipt.core.holder.contact_actor_id())
                .ok_or_else(|| {
                    super::super::events::peer::schema_violation(
                        "glare finalize has no local-holder identity",
                    )
                })?;
            let remote_holder = request_receipts
                .iter()
                .find(|receipt| receipt.core.issuer_id == remote_attestation.issuer_id)
                .map(|receipt| receipt.core.holder.contact_actor_id())
                .ok_or_else(|| {
                    super::super::events::peer::schema_violation(
                        "glare finalize has no remote-holder identity",
                    )
                })?;
            let contacts = state.contacts();
            let mut record = contacts
                .contact_any(&local_holder, &remote_holder)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?
                .ok_or_else(|| {
                    crate::app_error!(
                        FailedPrecondition,
                        "outbound glare Contact slot is unavailable",
                    )
                })?;
            if record.peer_host_id.as_ref().map(|value| value.as_str()) != Some(peer_id) {
                return Err(super::super::events::peer::cross_domain_replay(
                    "glare outcome service does not match durable Contact peer",
                ));
            }
            let local_request = request_receipts
                .iter()
                .find(|receipt| receipt.core.holder.contact_actor_id() == local_holder)
                .ok_or_else(|| {
                    super::super::events::peer::schema_violation(
                        "glare finalize has no local-holder request receipt",
                    )
                })?;
            let mut bundle = if let Some(bundle) = record.contact_round_evidence.clone() {
                if bundle.contact_round_id != *contact_round_id
                    || bundle.glare_concurrency_attestations.is_none()
                {
                    return Err(AppError::conflict(
                        "outbound glare outcome conflicts with durable Contact round",
                    ));
                }
                bundle
            } else {
                let observed_at = now();
                let mut accepted_commit_event_ids = request_receipts
                    .iter()
                    .map(|receipt| receipt.core.request_event_ref.clone())
                    .collect::<Vec<_>>();
                accepted_commit_event_ids
                    .sort_by(|left, right| left.as_str().as_bytes().cmp(right.as_str().as_bytes()));
                let mut local_proof = ContactCurrentProof {
                    contact_round_id: contact_round_id.clone(),
                    issuer_id: state.service_core_id(),
                    peer: contact_address.recipient.clone(),
                    terminal: false,
                    head_event_ref: local_request.core.request_event_ref.clone(),
                    accepted_commit_event_ids,
                    complete_through: 1,
                    fresh_until: observed_at + chrono::Duration::minutes(10),
                    signature: placeholder_contact_signature(state, observed_at)?,
                };
                local_proof.signature = sign_contact_assertion_evidence_bytes(
                    state,
                    observed_at,
                    &local_proof.canonical_signing_bytes().map_err(|error| {
                        AppError::internal(format!("local Contact proof transcript: {error}"))
                    })?,
                )
                .await?;
                let mut attestations = [local_attestation.clone(), remote_attestation.clone()];
                attestations.sort_by(|left, right| left.subject_id.cmp(&right.subject_id));
                ContactRoundEvidenceBundle {
                    contact_round_id: contact_round_id.clone(),
                    previous_terminal_contact_round_id: request_receipts.iter().find_map(
                        |receipt| receipt.core.previous_terminal_contact_round_id.clone(),
                    ),
                    contact_round: contact_round.clone(),
                    request_receipts: request_receipts.to_vec(),
                    normal_response_receipt: None,
                    glare_concurrency_attestations: Some(attestations),
                    current_proofs: vec![local_proof],
                    continuity_checkpoint: None,
                }
            };
            let local_proof = bundle
                .current_proofs
                .iter()
                .find(|proof| {
                    proof.peer.contact_actor_id() == contact_address.recipient.contact_actor_id()
                })
                .cloned()
                .ok_or_else(|| {
                    crate::app_error!(
                        FailedPrecondition,
                        "durable local Contact proof is unavailable",
                    )
                })?;
            bundle
                .current_proofs
                .retain(|proof| proof.peer != remote_proof.peer);
            bundle.current_proofs.push(remote_proof.clone());
            bundle.current_proofs.sort_by(|left, right| {
                left.peer
                    .contact_actor_id()
                    .cmp(&right.peer.contact_actor_id())
            });
            let outcome_digest = super::account::canonical_contact_digest(outcome)?;
            let outcome_stored = record.control_outcomes.iter().any(|stored| {
                super::account::canonical_contact_digest(stored)
                    .is_ok_and(|digest| digest == outcome_digest)
            });
            if !outcome_stored || record.status != "accepted" {
                let expected_updated_at = record.updated_at;
                record.contact_round_id = Some(contact_round_id.clone());
                record.status = "accepted".to_owned();
                record.request_receipts.clear();
                record.request_mirror_receipts.clear();
                record.contact_round_evidence = Some(bundle);
                if !outcome_stored {
                    record.control_outcomes.push(outcome.clone());
                }
                advance_contact_revision(&mut record, expected_updated_at);
                save_contact_cas(contacts, expected_updated_at, record).await?;
            }

            let proof_digest = super::account::canonical_contact_digest(&local_proof)?;
            let idempotency_key = IdempotencyKey::new(format!(
                "contact-proof-refresh:{contact_round_id}:{proof_digest}"
            ))
            .map_err(|error| {
                AppError::internal(format!("proof-refresh idempotency key invalid: {error}"))
            })?;
            let delivery = PeerContactSubmitRequestBody::ProofRefresh {
                idempotency_key,
                prior_mirror_receipt: remote_mirror_receipt.clone(),
                current_proof: local_proof,
                contact_address: contact_address.clone(),
            };
            enqueue_peer_contact_carrier(state, peer_id, &delivery).await?;
            Ok(())
        }
        (
            PeerContactSubmitRequestBody::ProofRefresh { current_proof, .. },
            PeerContactSubmitOutcome::Control(PeerContactControlSubmitOutcome::ProofRefresh {
                status: PeerContactOutcome::Accepted | PeerContactOutcome::Duplicate,
                control_receipt,
                current_proof: returned_proof,
            }),
        ) => {
            if super::account::canonical_contact_digest(current_proof)?
                != super::account::canonical_contact_digest(returned_proof)?
            {
                return Err(super::super::events::peer::schema_violation(
                    "proof-refresh outcome changed the submitted current proof",
                ));
            }
            validate_outbound_control_receipt(
                state,
                request,
                control_receipt,
                PeerContactControlKind::ProofRefresh,
                peer_id,
                Some(super::account::canonical_contact_digest(returned_proof)?),
            )
        }
        _ => Err(super::super::events::peer::schema_violation(
            "Contact control outcome does not match the outbound request branch",
        )),
    }
}

pub(crate) async fn accept_outbound_contact_event_outcome(
    state: &AppState,
    request: &PeerContactSubmitRequestBody,
    outcome: &PeerContactEventSubmitOutcome,
    peer_id: &str,
) -> Result<(), AppError> {
    let (signed_event, contact_address, sent_proof, expected_kind, terminal) = match request {
        PeerContactSubmitRequestBody::Response {
            signed_event,
            contact_address,
            current_proof,
            ..
        } => (
            signed_event,
            contact_address,
            current_proof.as_ref(),
            arkret_models_collaboration::contact_operations::ContactResultKind::Response,
            false,
        ),
        PeerContactSubmitRequestBody::ScopeUpdate {
            signed_event,
            contact_address,
            current_proof,
            ..
        } => (
            signed_event,
            contact_address,
            Some(current_proof),
            arkret_models_collaboration::contact_operations::ContactResultKind::ScopeUpdate,
            false,
        ),
        PeerContactSubmitRequestBody::Tombstone {
            signed_event,
            contact_address,
            current_proof,
            ..
        } => (
            signed_event,
            contact_address,
            Some(current_proof),
            arkret_models_collaboration::contact_operations::ContactResultKind::Tombstone,
            true,
        ),
        _ => {
            return Err(super::super::events::peer::schema_violation(
                "Contact Event outcome does not match an evidence-bearing carrier",
            ));
        }
    };
    if outcome.result_kind != expected_kind
        || !matches!(
            outcome.status,
            PeerContactOutcome::Accepted | PeerContactOutcome::Duplicate
        )
        || outcome.mirror_receipt.signed_event_ref != signed_event.event_id
        || outcome.mirror_receipt.signed_event_digest()
            != event_digest_for_frozen_claim(
                signed_event,
                &outcome.mirror_receipt.signed_event_digest(),
            )?
    {
        return Err(super::super::events::peer::schema_violation(
            "Contact Event outcome does not bind the outbound signed Event",
        ));
    }
    validate_mirror_receipt_cryptography(
        state,
        &outcome.mirror_receipt,
        peer_id,
        "outbound_contact_mirror_receipt",
    )?;
    let Some(returned_proof) = outcome.current_proof.as_ref() else {
        if expected_kind
            == arkret_models_collaboration::contact_operations::ContactResultKind::Response
            && sent_proof.is_none()
        {
            return Ok(());
        }
        return Err(super::super::events::peer::schema_violation(
            "Contact Event outcome is missing the recipient current proof",
        ));
    };
    let sent_proof = sent_proof.ok_or_else(|| {
        super::super::events::peer::schema_violation(
            "Contact Event carrier cannot absorb a proof without its source proof",
        )
    })?;
    if returned_proof.issuer_id.as_str() != peer_id
        || returned_proof.peer.contact_actor_id() != signed_event.actor_id
        || returned_proof.contact_round_id != sent_proof.contact_round_id
        || returned_proof.terminal != terminal
        || returned_proof.complete_through == 0
        || returned_proof.fresh_until <= now()
    {
        return Err(super::super::events::peer::schema_violation(
            "recipient Contact current proof does not bind the addressed direction",
        ));
    }
    verify_contact_evidence_signature(
        state,
        peer_id,
        &returned_proof.signature,
        &returned_proof.canonical_signing_bytes().map_err(|error| {
            AppError::internal(format!("recipient Contact proof transcript: {error}"))
        })?,
        "outbound_contact_current_proof",
    )?;
    let local_core_id = contact_event_issuer_core_id(request).ok_or_else(|| {
        super::super::events::peer::schema_violation(
            "Contact Event outcome has no signed local issuer coordinate",
        )
    })?;
    if local_core_id != signed_event.actor_id {
        return Err(super::super::events::peer::cross_domain_replay(
            "Contact Event outcome local DID does not match signed_event.actor_id",
        ));
    }
    let contacts = state.contacts();
    let mut record = contacts
        .contact_any(
            &local_core_id,
            &contact_address.recipient.contact_actor_id(),
        )
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::internal("outbound Contact projection disappeared"))?;
    // A non-terminal recipient proof covers the opposite directional head,
    // not the source Event just delivered. Only tombstones share one head.
    let expected_head = if terminal {
        Some(&signed_event.event_id)
    } else if returned_proof.peer.contact_actor_id() == record.target_id {
        record.request_event_ref.as_ref()
    } else if returned_proof.peer.contact_actor_id() == record.requester_id {
        record.response_event_ref.as_ref()
    } else {
        None
    };
    if expected_head != Some(&returned_proof.head_event_ref)
        || !returned_proof
            .accepted_commit_event_ids
            .contains(&returned_proof.head_event_ref)
    {
        return Err(super::super::events::peer::schema_violation(
            "recipient Contact current proof does not bind its directional head",
        ));
    }
    let mut bundle = record.contact_round_evidence.clone().ok_or_else(|| {
        crate::app_error!(
            FailedPrecondition,
            "outbound Contact projection has no contact_round evidence",
        )
    })?;
    if bundle.contact_round_id != returned_proof.contact_round_id {
        return Err(super::super::events::peer::schema_violation(
            "recipient Contact proof names another contact_round",
        ));
    }
    let returned_proof_digest = super::account::canonical_contact_digest(returned_proof)?;
    for proof in &bundle.current_proofs {
        if proof.peer == returned_proof.peer
            && super::account::canonical_contact_digest(proof)? == returned_proof_digest
        {
            return Ok(());
        }
    }
    let expected_updated_at = record.updated_at;
    bundle
        .current_proofs
        .retain(|proof| proof.peer != returned_proof.peer);
    bundle.current_proofs.push(returned_proof.clone());
    bundle.current_proofs.sort_by(|left, right| {
        left.peer
            .contact_actor_id()
            .cmp(&right.peer.contact_actor_id())
    });
    if bundle.current_proofs.len() != 2
        || bundle
            .current_proofs
            .iter()
            .map(|proof| proof.peer.contact_actor_id())
            .collect::<std::collections::BTreeSet<_>>()
            != [
                local_core_id.clone(),
                contact_address.recipient.contact_actor_id(),
            ]
            .into_iter()
            .collect()
    {
        return Err(super::super::events::peer::schema_violation(
            "Contact Event outcome does not complete the exact pair proof set",
        ));
    }
    record.contact_round_evidence = Some(bundle);
    advance_contact_revision(&mut record, expected_updated_at);
    save_contact_cas(contacts, expected_updated_at, record).await
}

pub(crate) async fn reenqueue_deferred_contact_control(
    state: &AppState,
    request: &PeerContactSubmitRequestBody,
    deferred: &arkret_models_collaboration::contact_operations::PeerContactControlDeferredOutcome,
    peer_id: &str,
) -> Result<(), AppError> {
    let expected_kind = match request {
        PeerContactSubmitRequestBody::GlareFinalize { .. } => PeerContactControlKind::GlareFinalize,
        PeerContactSubmitRequestBody::ProofRefresh { .. } => PeerContactControlKind::ProofRefresh,
        _ => {
            return Err(super::super::events::peer::schema_violation(
                "deferred Contact control outcome names an Event carrier",
            ));
        }
    };
    if deferred.status != PeerContactOutcome::Deferred
        || deferred.request_kind != expected_kind
        || deferred.control_receipt.outcome != PeerContactOutcome::Deferred
        || deferred.control_receipt.result_digest.is_some()
    {
        return Err(super::super::events::peer::schema_violation(
            "deferred Contact control outcome has inconsistent status/kind",
        ));
    }
    let request_digest = contact_control_request_digest(request)?;
    let receipt = &deferred.control_receipt;
    if receipt.request_kind != expected_kind
        || receipt.request_digest != request_digest
        || receipt.issuer_id.as_str() != peer_id
        || receipt.recipient_id.as_str() != peer_id
    {
        return Err(super::super::events::peer::schema_violation(
            "deferred Contact control receipt does not bind the request",
        ));
    }
    let signing_bytes = contact_control_receipt_signing_bytes(receipt)?;
    verify_contact_evidence_signature(
        state,
        peer_id,
        &receipt.signature,
        &signing_bytes,
        "deferred Contact control receipt",
    )?;

    // A semantic response was received, so the next evaluation uses a fresh
    // key. It is deterministically derived from the previous exact body digest
    // so response-loss replay enqueues the same successor intent, while a
    // second deferred response (whose request includes that successor key)
    // advances to another key.
    let next_key = IdempotencyKey::new(format!("contact-control-retry:{request_digest}"))
        .map_err(|error| AppError::internal(format!("Contact retry key invalid: {error}")))?;
    let mut retry = request.clone();
    match &mut retry {
        PeerContactSubmitRequestBody::GlareFinalize {
            idempotency_key, ..
        }
        | PeerContactSubmitRequestBody::ProofRefresh {
            idempotency_key, ..
        } => *idempotency_key = next_key,
        _ => unreachable!("request branch checked above"),
    }
    enqueue_peer_contact_carrier(state, peer_id, &retry).await?;
    Ok(())
}

fn validate_outbound_control_receipt(
    state: &AppState,
    request: &PeerContactSubmitRequestBody,
    receipt: &PeerContactControlReceipt,
    expected_kind: PeerContactControlKind,
    peer_id: &str,
    expected_result_digest: Option<Hash>,
) -> Result<(), AppError> {
    let request_digest = contact_control_request_digest(request)?;
    if receipt.request_kind != expected_kind
        || receipt.request_digest != request_digest
        || receipt.outcome == PeerContactOutcome::Deferred
        || receipt.result_digest != expected_result_digest
        || receipt.issuer_id.as_str() != peer_id
        || receipt.recipient_id.as_str() != peer_id
    {
        return Err(super::super::events::peer::schema_violation(
            "Contact control receipt does not bind the outbound request/result",
        ));
    }
    let signing_bytes = contact_control_receipt_signing_bytes(receipt)?;
    verify_contact_evidence_signature(
        state,
        peer_id,
        &receipt.signature,
        &signing_bytes,
        "Contact control receipt",
    )
}

#[derive(serde::Serialize)]
struct ContactControlReceiptSigningTranscript<'a> {
    domain: &'a PeerContactControlReceiptDomain,
    request_kind: PeerContactControlKind,
    request_digest: &'a Hash,
    outcome: PeerContactOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    result_digest: Option<&'a Hash>,
    recipient_id: &'a arkret_wire::DidCoreId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    received_at: chrono::DateTime<chrono::Utc>,
    issuer_id: &'a arkret_wire::DidCoreId,
}

fn contact_control_receipt_signing_bytes(
    receipt: &PeerContactControlReceipt,
) -> Result<Vec<u8>, AppError> {
    canonical::canonical_json_bytes(&ContactControlReceiptSigningTranscript {
        domain: &receipt.domain,
        request_kind: receipt.request_kind,
        request_digest: &receipt.request_digest,
        outcome: receipt.outcome,
        result_digest: receipt.result_digest.as_ref(),
        recipient_id: &receipt.recipient_id,
        received_at: receipt.received_at,
        issuer_id: &receipt.issuer_id,
    })
    .map_err(|error| AppError::internal(format!("Contact control receipt transcript: {error}")))
}

fn verify_contact_evidence_signature(
    state: &AppState,
    service_id: &str,
    signature: &ProtocolSignature,
    signing_bytes: &[u8],
    field: &str,
) -> Result<(), AppError> {
    super::account::verify_contact_service_signature_bytes(
        state,
        service_id,
        signature,
        signing_bytes,
        field,
    )
}

fn advance_contact_revision(
    record: &mut ContactRecord,
    expected_updated_at: chrono::DateTime<chrono::Utc>,
) {
    record.updated_at = now().max(expected_updated_at + chrono::Duration::microseconds(1));
}

async fn save_contact_cas(
    contacts: &coland_services::identity::ContactService,
    expected_updated_at: chrono::DateTime<chrono::Utc>,
    record: ContactRecord,
) -> Result<(), AppError> {
    let saved = contacts
        .save_contact_if_updated_at(expected_updated_at, record)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    if !saved {
        return Err(AppError::conflict(
            "Contact evidence changed concurrently; replay the exact request",
        ));
    }
    Ok(())
}

fn sign_contact_control_receipt(
    state: &AppState,
    request: &PeerContactSubmitRequestBody,
    request_kind: PeerContactControlKind,
    outcome: PeerContactOutcome,
    result_digest: Option<Hash>,
) -> Result<PeerContactControlReceipt, AppError> {
    let request_digest = Hash::new(
        canonical::canonical_sha256(request)
            .map_err(|error| AppError::internal(format!("Contact control digest: {error}")))?,
    )
    .map_err(|error| AppError::internal(format!("Contact control digest invalid: {error}")))?;
    let received_at = now();
    let issuer = arkret_identifiers::DidCoreId::new(state.service_id().clone())
        .map_err(|error| AppError::internal(format!("service DID invalid: {error}")))?;
    let verification_method = DidUrl::new(
        crate::routing::federation::federation_service_signature_key_id(
            state.service_did().as_str(),
        ),
    )
    .map_err(|error| AppError::internal(format!("service verification method invalid: {error}")))?;
    let mut signing_value = json!({
            "domain": arkret_wire::DomainSeparationId::PEER_CONTACT_CONTROL_RECEIPT_V1,
        "request_kind": request_kind,
        "request_digest": request_digest,
        "outcome": outcome,
        "result_digest": result_digest,
        "recipient_id": issuer,
        "received_at": arkret_canonical::format_timestamp_canonical(received_at),
        "issuer_id": issuer,
    });
    if result_digest.is_none()
        && let Value::Object(fields) = &mut signing_value
    {
        fields.remove("result_digest");
    }
    let signing_bytes = canonical::canonical_json_bytes(&signing_value).map_err(|error| {
        AppError::internal(format!("Contact control receipt canonicalize: {error}"))
    })?;
    let jws = super::account::contact_detached_jws(&state.notary_signing_key(), &signing_bytes)?;
    Ok(PeerContactControlReceipt {
        domain: PeerContactControlReceiptDomain::V1,
        request_kind,
        request_digest,
        outcome,
        result_digest,
        recipient_id: issuer.clone(),
        received_at,
        issuer_id: issuer,
        signature: ProtocolSignature {
            verification_method,
            created_at: received_at,
            jws,
        },
    })
}

fn validate_contact_introduction_evidence_digest(
    payload: &Value,
    evidence: &ContactIntroductionEvidence,
) -> Result<(), AppError> {
    let expected = payload
        .get("introduction_evidence_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            super::super::events::peer::schema_violation(
                "contact_requested_payload.introduction_evidence_digest is required",
            )
        })?;
    let canonical = canonical::canonical_json_bytes(evidence).map_err(|error| {
        super::super::events::peer::schema_violation(format!(
            "contact introduction_evidence is not canonical-hashable: {error}"
        ))
    })?;
    let mut transcript = b"ak.contact.introduction-evidence.v1\n".to_vec();
    transcript.extend(canonical);
    let actual = canonical::sha256_digest(transcript);
    if expected != actual {
        return Err(super::super::events::peer::schema_violation(
            "contact_requested_payload.introduction_evidence_digest mismatch",
        ));
    }
    Ok(())
}

/// Project a delivered contact fact into the local `subject_id`'s contact
/// projection. Returns the receive status (`accepted` / `duplicate`).
fn delivered_direction_predecessor<'a>(
    row: &'a ContactRecord,
    issuer: &arkret_wire::ActorId,
    subject: &arkret_wire::ActorId,
) -> Option<&'a arkret_wire::EventId> {
    let stored_head = if row.requester_id == *issuer {
        row.request_event_ref.as_ref()
    } else if row.target_id == *issuer {
        row.response_event_ref.as_ref()
    } else {
        return None;
    };
    // In a glare round both parties authored a request. The row has only one
    // request/response slot, so the other direction's signed current proof is
    // its durable head until a scope successor replaces it.
    row.contact_round_evidence
        .as_ref()
        .and_then(|bundle| {
            bundle
                .current_proofs
                .iter()
                .find(|proof| !proof.terminal && proof.peer.contact_actor_id() == *subject)
        })
        .map(|proof| &proof.head_event_ref)
        .or(stored_head)
}

async fn project_delivered_contact_fact(
    state: &AppState,
    fact_kind: &str,
    issuer_id: &arkret_wire::ActorId,
    subject_actor_id: &arkret_wire::ActorId,
    payload: &Value,
    contact_event_id: &str,
    request_receipt: Option<&RequestAcceptanceReceipt>,
    response_receipt: Option<&NormalResponseAcceptanceReceipt>,
    reject_receipt: Option<&RejectAcceptanceReceipt>,
    carrier_current_proof: Option<&ContactCurrentProof>,
    source_id: Option<&str>,
) -> Result<&'static str, AppError> {
    let contact_event_ref =
        arkret_wire::EventId::new(contact_event_id.to_owned()).map_err(|error| {
            super::super::events::peer::schema_violation(format!(
                "Contact Event reference is invalid: {error}"
            ))
        })?;
    let source_host_id = source_id
        .map(|value| arkret_wire::DidCoreId::new(value.to_owned()))
        .transpose()
        .map_err(|error| {
            super::super::events::peer::schema_violation(format!(
                "Contact source service is invalid: {error}"
            ))
        })?;
    let projected_scopes = granted_scopes(payload);
    let contacts = state.contacts();
    match fact_kind {
        arkret_wire::event_kind_str::CONTACT_REQUESTED => {
            let request_receipt = request_receipt.ok_or_else(|| {
                super::super::events::peer::schema_violation(
                    "Contact request carrier is missing its acceptance receipt",
                )
            })?;
            let request = serde_json::from_value::<ContactRequestedPayload>(payload.clone())
                .map_err(|_| {
                    super::super::events::peer::schema_violation(
                        "invalid ak.contact.requested payload",
                    )
                })?;
            if request.peer.contact_actor_id() != *subject_actor_id {
                return Err(super::super::events::peer::schema_violation(
                    "ak.contact.requested peer does not match the addressed holder",
                ));
            }
            if request_receipt.core.previous_terminal_contact_round_id
                != request.previous_terminal_contact_round_id
            {
                return Err(super::super::events::peer::schema_violation(
                    "Contact request receipt continuity pointer does not match signed_event",
                ));
            }
            // requester_id = issuer, target = subject_id (this holder). Form a
            // pending_incoming row on the target side.
            // This holder-private Contact projection carries the verified original
            // message; timeline, push and non-Contact projections never read it.
            let message = request.message.clone();
            if let Some(mut existing) = contacts
                .contact_any(issuer_id, subject_actor_id)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?
            {
                if existing.status == "tombstoned" {
                    let terminal = existing.contact_round_evidence.clone().ok_or_else(|| {
                        crate::app_error!(
                            FailedPrecondition,
                            "terminal Contact round evidence is unavailable",
                        )
                    })?;
                    if request.previous_terminal_contact_round_id.as_ref()
                        != Some(&terminal.contact_round_id)
                        || terminal.current_proofs.len() != 2
                        || terminal.current_proofs.iter().any(|proof| {
                            !proof.terminal || proof.contact_round_id != terminal.contact_round_id
                        })
                    {
                        return Err(super::super::events::peer::schema_violation(
                            "recontact request does not bind the durable terminal head",
                        ));
                    }
                    arkret_models_collaboration::contact_operations::validate_recontact_continuity(
                        &terminal,
                        &existing.contact_round_evidence_history,
                    )
                    .map_err(|error| {
                        crate::app_error!(
                            FailedPrecondition,
                            format!("terminal Contact continuity is invalid: {error}"),
                        )
                    })?;
                    let expected_updated_at = existing.updated_at;
                    let created_at = existing.created_at;
                    let mut history = Vec::with_capacity(
                        existing
                            .contact_round_evidence_history
                            .len()
                            .saturating_add(1),
                    );
                    history.push(terminal);
                    history.extend(existing.contact_round_evidence_history);
                    let request_slot_states = existing.request_slot_states;
                    if history.len() > 64 {
                        return Err(crate::app_error!(
                            FailedPrecondition,
                            "Contact round continuity exceeds 64 predecessors",
                        ));
                    }
                    let replacement = ContactRecord {
                        requester_id: issuer_id.clone(),
                        target_id: subject_actor_id.clone(),
                        contact_round_id: None,
                        granted_to_target_scopes: projected_scopes.clone(),
                        granted_to_requester_scopes: Vec::new(),
                        status: "pending".to_owned(),
                        pending_incoming_admitted: true,
                        request_event_ref: Some(contact_event_ref.clone()),
                        request_slot_states,
                        request_receipts: vec![request_receipt.clone()],
                        request_mirror_receipts: Vec::new(),
                        contact_round_evidence: None,
                        contact_round_evidence_history: history,
                        control_outcomes: Vec::new(),
                        response_event_ref: None,
                        tombstone_event_ref: None,
                        message,
                        peer_host_id: source_host_id.clone(),
                        peer_service_resolution: None,
                        created_at,
                        updated_at: now(),
                    };
                    save_contact_cas(contacts, expected_updated_at, replacement).await?;
                    return Ok("accepted");
                }
                if existing.status == "rejected" {
                    let expected_previous = existing
                        .contact_round_evidence_history
                        .first()
                        .map(|bundle| &bundle.contact_round_id);
                    if request.previous_terminal_contact_round_id.as_ref() != expected_previous {
                        return Err(super::super::events::peer::schema_violation(
                            "new Contact request does not preserve terminal continuity",
                        ));
                    }
                    let expected_updated_at = existing.updated_at;
                    let created_at = existing.created_at;
                    let history = existing.contact_round_evidence_history;
                    let request_slot_states = existing.request_slot_states;
                    let replacement = ContactRecord {
                        requester_id: issuer_id.clone(),
                        target_id: subject_actor_id.clone(),
                        contact_round_id: None,
                        granted_to_target_scopes: projected_scopes.clone(),
                        granted_to_requester_scopes: Vec::new(),
                        status: "pending".to_owned(),
                        pending_incoming_admitted: true,
                        request_event_ref: Some(contact_event_ref.clone()),
                        request_slot_states,
                        request_receipts: vec![request_receipt.clone()],
                        request_mirror_receipts: Vec::new(),
                        contact_round_evidence: None,
                        contact_round_evidence_history: history,
                        control_outcomes: Vec::new(),
                        response_event_ref: None,
                        tombstone_event_ref: None,
                        message,
                        peer_host_id: source_host_id.clone(),
                        peer_service_resolution: None,
                        created_at,
                        updated_at: now(),
                    };
                    save_contact_cas(contacts, expected_updated_at, replacement).await?;
                    return Ok("accepted");
                }
                if existing.status == "pending"
                    && existing
                        .request_event_ref
                        .as_ref()
                        .map(|value| value.as_str())
                        == Some(contact_event_id)
                {
                    if !existing.request_receipts.iter().any(|stored| {
                        stored.core.request_event_ref == request_receipt.core.request_event_ref
                            && stored.core.request_digest() == request_receipt.core.request_digest()
                    }) {
                        let expected_updated_at = existing.updated_at;
                        existing.request_receipts.push(request_receipt.clone());
                        advance_contact_revision(&mut existing, expected_updated_at);
                        save_contact_cas(contacts, expected_updated_at, existing).await?;
                    }
                    return Ok("duplicate");
                }
                if existing.status == "pending"
                    && existing.requester_id == *subject_actor_id
                    && existing.target_id == *issuer_id
                    && existing
                        .request_event_ref
                        .as_ref()
                        .map(|value| value.as_str())
                        != Some(contact_event_id)
                {
                    let expected_previous = existing
                        .contact_round_evidence_history
                        .first()
                        .map(|bundle| &bundle.contact_round_id);
                    if request.previous_terminal_contact_round_id.as_ref() != expected_previous {
                        return Err(super::super::events::peer::schema_violation(
                            "glare recontact requests do not bind the same terminal predecessor",
                        ));
                    }
                    // A reverse request may coexist only as an unconsumed
                    // glare candidate. Preserve the original request
                    // orientation and append the exact second source receipt;
                    // founder selection later uses canonical Event-ref order,
                    // never arrival order or DID order.
                    if !existing
                        .request_receipts
                        .iter()
                        .any(|stored| stored.core.request_event_ref.as_str() == contact_event_id)
                    {
                        let expected_updated_at = existing.updated_at;
                        existing.request_receipts.push(request_receipt.clone());
                        existing.granted_to_requester_scopes = projected_scopes.clone();
                        existing.peer_host_id = source_host_id.clone();
                        advance_contact_revision(&mut existing, expected_updated_at);
                        save_contact_cas(contacts, expected_updated_at, existing).await?;
                    }
                    return Ok("accepted");
                }
                return Err(super::super::events::peer::schema_violation(
                    "ak.contact.requested conflicts with the permanent Contact request slot",
                ));
            }
            // `contact-and-direct-conversation.md` section 1.1 -- a stranger's
            // first Contact request is billed to the same per-holder new-source
            // ledger as invite delivery and `ak.self.consent.command.request.v1`.
            // Only the discarded object differs: Contact shares the chokepoint,
            // not the carrier, so an over-quota first contact drops the
            // establishment of this `pending_incoming` row and leaves the holder
            // quarantine cell with zero entries. Contact still neither reads nor
            // writes Consent. Reaching here means no row exists yet, which is
            // exactly the "first contact" the quota is defined over.
            if let Some(holder_account_id) = subject_actor_id.as_account_id()
                && !crate::routing::invites::admit_quarantine_new_source(
                    state,
                    holder_account_id,
                    issuer_id.signing_principal_id().as_str(),
                    now(),
                )
                .await?
            {
                // Byte-identical to an ordinary acceptance: the requester learns
                // nothing the four other members of the section 6.1.1
                // equivalence class would not also show.
                return Ok("accepted");
            }
            let contact = ContactRecord {
                requester_id: issuer_id.clone(),
                target_id: subject_actor_id.clone(),
                contact_round_id: None,
                granted_to_target_scopes: projected_scopes,
                granted_to_requester_scopes: Vec::new(),
                status: "pending".to_owned(),
                pending_incoming_admitted: true,
                request_event_ref: Some(contact_event_ref.clone()),
                request_slot_states: Vec::new(),
                request_receipts: vec![request_receipt.clone()],
                request_mirror_receipts: Vec::new(),
                contact_round_evidence: None,
                contact_round_evidence_history: Vec::new(),
                control_outcomes: Vec::new(),
                response_event_ref: None,
                tombstone_event_ref: None,
                message,
                // Peer end of this pending_incoming row is the remote requester_id
                // (`issuer`), hosted on the delivering source server. The local
                // holder later uses this as the reverse-delivery target when it
                // responds (inkson's `requester_id`).
                peer_host_id: source_host_id.clone(),
                peer_service_resolution: None,
                created_at: now(),
                updated_at: now(),
            };
            contacts
                .save_contact(contact)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?;
            Ok("accepted")
        }
        arkret_wire::event_kind_str::CONTACT_ACCEPTED => {
            let accepted = serde_json::from_value::<ContactAcceptedPayload>(payload.clone())
                .map_err(|_| {
                    super::super::events::peer::schema_violation(
                        "invalid ak.contact.accepted payload",
                    )
                })?;
            if accepted.peer.contact_actor_id() != *subject_actor_id {
                return Err(super::super::events::peer::schema_violation(
                    "ak.contact.accepted peer does not match the original requester_id",
                ));
            }
            // Travelling back to the original requester_id (subject_id). The
            // target (issuer) accepted: flip the requester_id-side row to accepted
            // and project the issuer -> requester_id consent grants by their
            // original event refs, so the requester_id's row surfaces
            // invite_consent_grant_ref / bidirectional scopes without
            // re-minting target-controlled grant facts locally.
            let Some(mut contact) = contacts
                .contact_any(subject_actor_id, issuer_id)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?
            else {
                return Err(super::super::events::peer::schema_violation(
                    "ak.contact.accepted references no local pending request",
                ));
            };
            if contact.status == "accepted" {
                if contact
                    .response_event_ref
                    .as_ref()
                    .map(|value| value.as_str())
                    == Some(contact_event_id)
                {
                    return Ok("duplicate");
                }
                return Err(super::super::events::peer::schema_violation(
                    "ak.contact.accepted conflicts with the accepted Contact round",
                ));
            }
            if contact.status != "pending" || contact.request_event_ref.is_none() {
                return Err(super::super::events::peer::schema_violation(
                    "ak.contact.accepted references a non-pending or unverifiable request",
                ));
            }
            if accepted.request_event_ref.as_str()
                != contact
                    .request_event_ref
                    .as_ref()
                    .map(|value| value.as_str())
                    .unwrap()
            {
                return Err(super::super::events::peer::schema_violation(
                    "ak.contact.accepted request_id does not match the pending request",
                ));
            }
            let response_receipt = response_receipt.ok_or_else(|| {
                super::super::events::peer::schema_violation(
                    "ak.contact.accepted carrier is missing its response receipt",
                )
            })?;
            let request_receipt = contact.request_receipts.first().cloned().ok_or_else(|| {
                crate::app_error!(
                    FailedPrecondition,
                    "pending Contact row has no durable request receipt",
                )
            })?;
            if super::account::canonical_contact_digest(&response_receipt.request_receipt)?
                != super::account::canonical_contact_digest(&request_receipt)?
                || response_receipt.contact_round_id != accepted.contact_round_id
            {
                return Err(super::super::events::peer::schema_violation(
                    "ak.contact.accepted response receipt does not bind the durable request",
                ));
            }
            let (contact_round, derived_contact_round_id) = normal_contact_round(&request_receipt)?;
            if derived_contact_round_id != accepted.contact_round_id {
                return Err(super::super::events::peer::schema_violation(
                    "ak.contact.accepted contact_round id is not derived from the durable request",
                ));
            }
            let expected_updated_at = contact.updated_at;
            contact.granted_to_requester_scopes = granted_scopes(payload);
            contact.contact_round_id = Some(accepted.contact_round_id.clone());
            contact.status = "accepted".to_owned();
            contact.request_receipts.clear();
            contact.request_mirror_receipts.clear();
            contact.response_event_ref = Some(contact_event_ref.clone());
            advance_contact_revision(&mut contact, expected_updated_at);
            // Peer end is the remote accepter (`issuer`), hosted on the
            // delivering source server. Record/backfill it so the requester_id's
            // row can address future invites/responses to the peer's home PS.
            if let Some(source) = source_id {
                contact.peer_host_id = Some(
                    arkret_wire::DidCoreId::new(source.to_owned()).map_err(|error| {
                        super::super::events::peer::schema_violation(format!(
                            "Contact source service is invalid: {error}"
                        ))
                    })?,
                );
            }
            if let Some(remote_proof) = carrier_current_proof {
                if remote_proof.contact_round_id != accepted.contact_round_id
                    || remote_proof.terminal
                {
                    return Err(super::super::events::peer::schema_violation(
                        "ak.contact.accepted current proof has invalid contact_round or terminal state",
                    ));
                }
                // A non-terminal proof must bind this Station's own directional head.
                // Re-signing the remote responder head would certify the wrong actor.
                let local_proof = super::account::local_requester_current_proof(
                    state,
                    &accepted.contact_round_id,
                    &request_receipt,
                )
                .await?
                .ok_or_else(|| {
                    crate::app_error!(
                        TemporarilyUnavailable,
                        "accepted local Contact requester proof is unavailable",
                    )
                })?;
                let mut current_proofs = vec![remote_proof.clone(), local_proof];
                current_proofs.sort_by(|left, right| {
                    left.peer
                        .contact_actor_id()
                        .cmp(&right.peer.contact_actor_id())
                });
                contact.contact_round_evidence = Some(ContactRoundEvidenceBundle {
                    contact_round_id: accepted.contact_round_id.clone(),
                    previous_terminal_contact_round_id: request_receipt
                        .core
                        .previous_terminal_contact_round_id
                        .clone(),
                    contact_round,
                    request_receipts: vec![request_receipt],
                    normal_response_receipt: Some(response_receipt.clone()),
                    glare_concurrency_attestations: None,
                    current_proofs,
                    continuity_checkpoint: contact
                        .contact_round_evidence_history
                        .iter()
                        .find_map(|bundle| bundle.continuity_checkpoint.clone()),
                });
            }
            save_contact_cas(contacts, expected_updated_at, contact).await?;
            Ok("accepted")
        }
        arkret_wire::event_kind_str::CONTACT_REJECTED => {
            let rejected = serde_json::from_value::<ContactRejectedPayload>(payload.clone())
                .map_err(|_| {
                    super::super::events::peer::schema_violation(
                        "invalid ak.contact.rejected payload",
                    )
                })?;
            if rejected.peer.contact_actor_id() != *subject_actor_id {
                return Err(super::super::events::peer::schema_violation(
                    "ak.contact.rejected peer does not match the original requester_id",
                ));
            }
            let Some(mut contact) = contacts
                .contact_any(subject_actor_id, issuer_id)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?
            else {
                return Err(super::super::events::peer::schema_violation(
                    "ak.contact.rejected references no local pending request",
                ));
            };
            if contact.status == "rejected" {
                if contact
                    .response_event_ref
                    .as_ref()
                    .map(|value| value.as_str())
                    == Some(contact_event_id)
                {
                    return Ok("duplicate");
                }
                return Err(super::super::events::peer::schema_violation(
                    "ak.contact.rejected conflicts with the consumed request slot",
                ));
            }
            if contact.status != "pending" || contact.request_event_ref.is_none() {
                return Err(super::super::events::peer::schema_violation(
                    "ak.contact.rejected references a non-pending or unverifiable request",
                ));
            }
            if rejected.request_event_ref.as_str()
                != contact
                    .request_event_ref
                    .as_ref()
                    .map(|value| value.as_str())
                    .unwrap()
            {
                return Err(super::super::events::peer::schema_violation(
                    "ak.contact.rejected request_id does not match the pending request",
                ));
            }
            let reject_receipt = reject_receipt.ok_or_else(|| {
                super::super::events::peer::schema_violation(
                    "ak.contact.rejected carrier is missing its reject receipt",
                )
            })?;
            let durable_request_receipt = contact
                .request_receipts
                .iter()
                .find(|receipt| receipt.core.request_event_ref == rejected.request_event_ref)
                .ok_or_else(|| {
                    crate::app_error!(
                        FailedPrecondition,
                        "pending Contact row has no durable request receipt",
                    )
                })?;
            let durable_request_digest =
                super::account::canonical_contact_digest(durable_request_receipt)?;
            if super::account::canonical_contact_digest(&reject_receipt.request_receipt)?
                != durable_request_digest
                || rejected.request_acceptance_receipt_digest != durable_request_digest
            {
                return Err(super::super::events::peer::schema_violation(
                    "ak.contact.rejected receipt does not bind the durable request",
                ));
            }
            let expected_updated_at = contact.updated_at;
            contact.status = "rejected".to_owned();
            contact.request_receipts.clear();
            contact.request_mirror_receipts.clear();
            contact.response_event_ref = Some(contact_event_ref.clone());
            advance_contact_revision(&mut contact, expected_updated_at);
            save_contact_cas(contacts, expected_updated_at, contact).await?;
            Ok("accepted")
        }
        arkret_wire::event_kind_str::CONTACT_SCOPE_UPDATE => {
            let update = serde_json::from_value::<ContactScopeUpdatePayload>(payload.clone())
                .map_err(|_| {
                    super::super::events::peer::schema_violation(
                        "invalid ak.contact.scope.update payload",
                    )
                })?;
            if update.peer.contact_actor_id() != *subject_actor_id {
                return Err(super::super::events::peer::schema_violation(
                    "ak.contact.scope.update peer does not match the addressed holder",
                ));
            }
            let Some(mut contact) = contacts
                .contact_any(issuer_id, subject_actor_id)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?
            else {
                return Err(super::super::events::peer::schema_violation(
                    "ak.contact.scope.update references no accepted contact_round",
                ));
            };
            let predecessor =
                delivered_direction_predecessor(&contact, issuer_id, subject_actor_id)
                    .map(|value| value.as_str());
            if contact.status != "accepted"
                || contact
                    .contact_round_id
                    .as_ref()
                    .map(|value| value.as_str())
                    != Some(update.contact_round_id.as_str())
                || super::account::direction_version(state, &contact, issuer_id)
                    .await?
                    .and_then(|value| value.checked_add(1))
                    != Some(update.version)
                || predecessor != Some(update.predecessor_event_ref.as_str())
            {
                return Err(super::super::events::peer::schema_violation(
                    "ak.contact.scope.update lineage CAS mismatch",
                ));
            }
            let expected_updated_at = contact.updated_at;
            if contact.requester_id == *issuer_id {
                contact.granted_to_target_scopes = projected_scopes;
                contact.request_event_ref = Some(contact_event_ref.clone());
            } else {
                contact.granted_to_requester_scopes = projected_scopes;
                contact.response_event_ref = Some(contact_event_ref.clone());
            }
            let remote_proof = carrier_current_proof.ok_or_else(|| {
                super::super::events::peer::schema_violation(
                    "ak.contact.scope.update carrier is missing its current proof",
                )
            })?;
            let mut bundle = contact.contact_round_evidence.clone().ok_or_else(|| {
                crate::app_error!(
                    FailedPrecondition,
                    "accepted Contact has no durable contact_round evidence",
                )
            })?;
            if remote_proof.contact_round_id != bundle.contact_round_id || remote_proof.terminal {
                return Err(super::super::events::peer::schema_violation(
                    "ak.contact.scope.update proof has invalid contact_round or terminal state",
                ));
            }
            bundle
                .current_proofs
                .retain(|proof| proof.peer != remote_proof.peer);
            bundle.current_proofs.push(remote_proof.clone());
            bundle.current_proofs.sort_by(|left, right| {
                left.peer
                    .contact_actor_id()
                    .cmp(&right.peer.contact_actor_id())
            });
            contact.contact_round_evidence = Some(bundle);
            advance_contact_revision(&mut contact, expected_updated_at);
            save_contact_cas(contacts, expected_updated_at, contact).await?;
            Ok("accepted")
        }
        arkret_wire::event_kind_str::CONTACT_TOMBSTONE => {
            let tombstone = serde_json::from_value::<ContactTombstonedPayload>(payload.clone())
                .map_err(|_| {
                    super::super::events::peer::schema_violation(
                        "invalid ak.contact.tombstone payload",
                    )
                })?;
            if tombstone.peer.contact_actor_id() != *subject_actor_id {
                return Err(super::super::events::peer::schema_violation(
                    "ak.contact.tombstone peer does not match the addressed holder",
                ));
            }
            let Some(mut row) = contacts
                .contact_any(issuer_id, subject_actor_id)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?
            else {
                return Err(super::super::events::peer::schema_violation(
                    "ak.contact.tombstone references no Contact round",
                ));
            };
            if row.status == "tombstoned" {
                if row.tombstone_event_ref.as_ref().map(|value| value.as_str())
                    == Some(contact_event_id)
                {
                    return Ok("duplicate");
                }
                return Err(super::super::events::peer::schema_violation(
                    "ak.contact.tombstone conflicts with the terminal Contact round",
                ));
            }
            let predecessor = delivered_direction_predecessor(&row, issuer_id, subject_actor_id)
                .map(|value| value.as_str());
            if row.contact_round_id.as_ref().map(|value| value.as_str())
                != Some(tombstone.contact_round_id.as_str())
                || super::account::direction_version(state, &row, issuer_id)
                    .await?
                    .and_then(|value| value.checked_add(1))
                    != Some(tombstone.version)
                || predecessor != Some(tombstone.predecessor_event_ref.as_str())
            {
                return Err(super::super::events::peer::schema_violation(
                    "ak.contact.tombstone lineage CAS mismatch",
                ));
            }
            let expected_updated_at = row.updated_at;
            row.status = "tombstoned".to_owned();
            row.request_receipts.clear();
            row.request_mirror_receipts.clear();
            row.tombstone_event_ref = Some(contact_event_ref.clone());
            let remote_proof = carrier_current_proof.ok_or_else(|| {
                super::super::events::peer::schema_violation(
                    "ak.contact.tombstone carrier is missing its terminal proof",
                )
            })?;
            let mut bundle = row.contact_round_evidence.clone().ok_or_else(|| {
                crate::app_error!(
                    FailedPrecondition,
                    "tombstoned Contact has no durable contact_round evidence",
                )
            })?;
            if remote_proof.contact_round_id != bundle.contact_round_id || !remote_proof.terminal {
                return Err(super::super::events::peer::schema_violation(
                    "ak.contact.tombstone proof has invalid contact_round or terminal state",
                ));
            }
            let remote_peer = bundle
                .request_receipts
                .iter()
                .flat_map(|receipt| [&receipt.core.holder, &receipt.core.peer])
                .find(|peer| peer.contact_actor_id() == *issuer_id)
                .cloned()
                .ok_or_else(|| {
                    super::super::events::peer::schema_violation(
                        "terminal Contact acknowledgement cannot derive the remote peer",
                    )
                })?;
            let local_proof = terminal_ack_contact_current_proof(
                state,
                &row,
                subject_actor_id,
                remote_peer,
                remote_proof,
            )
            .await?;
            bundle
                .current_proofs
                .retain(|proof| proof.peer != remote_proof.peer && proof.peer != local_proof.peer);
            bundle.current_proofs.push(remote_proof.clone());
            bundle.current_proofs.push(local_proof);
            bundle.current_proofs.sort_by(|left, right| {
                left.peer
                    .contact_actor_id()
                    .cmp(&right.peer.contact_actor_id())
            });
            row.contact_round_evidence = Some(bundle);
            advance_contact_revision(&mut row, expected_updated_at);
            save_contact_cas(contacts, expected_updated_at, row).await?;
            Ok("accepted")
        }
        other => Err(super::super::events::peer::schema_violation(format!(
            "unsupported contact fact_kind {other}"
        ))),
    }
}

fn granted_scopes(payload: &Value) -> Vec<String> {
    payload
        .get("granted_to_peer_scopes")
        .and_then(Value::as_array)
        .map(|scopes| {
            scopes
                .iter()
                .filter_map(Value::as_str)
                .filter(|scope| {
                    serde_json::from_value::<ContactScope>(Value::String((*scope).to_owned()))
                        .is_ok()
                })
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use arkret_identifiers::DidCoreId;
    use coland_storage_postgres::Db;

    use super::*;
    use crate::config::{AppConfig, ObjectStorageConfig};

    const ALICE: &str = "ak:did_core:web:alice.example";
    const BOB: &str = "ak:did_core:web:bob.example";
    const ALICE_SERVICE: &str = "ak:did_core:web:alice-service.example";
    const BOB_SERVICE: &str = "ak:did_core:web:bob-service.example";

    fn web_did(core_id: &str) -> String {
        core_id
            .strip_prefix("ak:did_core:web:")
            .map(|authority| format!("did:web:{authority}"))
            .expect("fixture uses a did:web Core identifier")
    }

    fn account_actor(principal_id: &str, station_id: &str) -> arkret_wire::ActorId {
        arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new(principal_id).unwrap(),
            arkret_wire::DidCoreId::new(station_id).unwrap(),
        ))
    }

    fn test_config() -> AppConfig {
        AppConfig {
            public_base_url: "http://test".to_owned(),
            object_storage: ObjectStorageConfig::local(std::env::temp_dir()),
            development_mode: true,
            did_resolver_allow_methods: vec!["web".to_owned(), "key".to_owned()],
            trust_domain: arkret_identifiers::TrustDomainId::new("ak:trust_domain:recipient.local")
                .unwrap(),
            ..AppConfig::test_default()
        }
    }

    #[test]
    fn peer_contact_producer_requires_the_exact_source_signed_event_key() {
        let holder = ContactPeer::Human {
            account_id: arkret_wire::AccountId::new(
                DidCoreId::new(ALICE).unwrap(),
                DidCoreId::new(ALICE_SERVICE).unwrap(),
            ),
        };
        let peer = ContactPeer::Human {
            account_id: arkret_wire::AccountId::new(
                DidCoreId::new(BOB).unwrap(),
                DidCoreId::new(BOB_SERVICE).unwrap(),
            ),
        };
        let method = arkret_wire::DidUrl::new(format!("{}#device", web_did(ALICE))).unwrap();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[29; 32]);
        let signer = ContactProducerSigner::direct(
            method.clone(),
            arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
                signing_key.verifying_key().to_bytes(),
            ))
            .unwrap(),
        )
        .unwrap();
        let realm_id =
            arkret_wire::RealmId::new("ak:realm:AZbOMvW-csKhom4LhjgFr2cuYB-cQ9oR21-cRX94cL9M")
                .unwrap();
        let mut event = Event {
            event_id: arkret_wire::EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [0; 32],
            ),
            kind: arkret_wire::EventKind::ContactRequested,
            realm_id: realm_id.clone(),
            scope_ref: arkret_wire::ScopeRef::Realm { realm_id },
            actor_id: holder.contact_actor_id(),
            executed_by: None,
            authorization_ref: None,
            applet_id: None,
            external_ref: None,
            created_at: chrono::Utc::now(),
            semantic_refs: Vec::new(),
            payload: serde_json::from_value(json!({
                "peer": peer,
                "granted_to_peer_scopes": ["direct_message"],
                "introduction_evidence_digest": format!("sha256:{}", "a".repeat(64)),
            }))
            .unwrap(),
            producer_proof: None,
        };
        let digest = arkret_wire::Hash::new(
            event
                .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                .unwrap(),
        )
        .unwrap();
        event.event_id = arkret_wire::EventId::from_event_digest(&digest).unwrap();
        let mut proof = arkret_wire::ProducerEventProof {
            kind: arkret_wire::proof_kind::DETACHED_JWS.into(),
            verification_method: method,
            event_digest: digest,
            created_at: event.created_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: String::new(),
        };
        proof.jws = arkret_signatures::jws::sign_jws_ed25519(
            &proof.canonical_binding_bytes(&event.actor_id).unwrap(),
            &signing_key,
        )
        .unwrap();
        event.producer_proof = Some(proof);
        verify_exact_contact_event_producer(&event, &holder, &signer, ALICE_SERVICE, None).unwrap();

        let wrong_key = ContactProducerSigner::direct(
            signer.verification_method().clone(),
            arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
                ed25519_dalek::SigningKey::from_bytes(&[30; 32])
                    .verifying_key()
                    .to_bytes(),
            ))
            .unwrap(),
        )
        .unwrap();
        assert!(
            verify_exact_contact_event_producer(&event, &holder, &wrong_key, ALICE_SERVICE, None)
                .is_err()
        );
        assert!(
            verify_exact_contact_event_producer(&event, &holder, &signer, BOB_SERVICE, None)
                .is_err()
        );
        let mut tampered = event;
        tampered.producer_proof.as_mut().unwrap().jws.push('x');
        assert!(
            verify_exact_contact_event_producer(&tampered, &holder, &signer, ALICE_SERVICE, None)
                .is_err()
        );
    }

    fn signed_request_receipt(
        holder: ContactPeer,
        peer: ContactPeer,
        source_did: &str,
        event_ref: &str,
    ) -> RequestAcceptanceReceipt {
        use arkret_models_collaboration::contact_operations::{
            ContactProducerSigner, RequestAcceptanceReceiptCore,
        };

        let source_key = ed25519_dalek::SigningKey::from_bytes(&[31; 32]);
        let holder_key = ed25519_dalek::SigningKey::from_bytes(&[29; 32]);
        let accepted_at = chrono::DateTime::parse_from_rfc3339("2026-08-09T00:00:00.000Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let method = arkret_wire::DidUrl::new(format!(
            "{}#device",
            web_did(holder.contact_actor_id().signing_principal_id().as_str())
        ))
        .unwrap();
        let core = RequestAcceptanceReceiptCore {
            issuer_id: holder.delivery_station_id().clone(),
            holder,
            peer,
            slot_version: 1,
            slot_predecessor: None,
            previous_terminal_contact_round_id: None,
            request_event_ref: arkret_wire::EventId::new(event_ref).unwrap(),
            producer_signer: ContactProducerSigner::direct(
                method,
                arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
                    holder_key.verifying_key().to_bytes(),
                ))
                .unwrap(),
            )
            .unwrap(),
            source_checkpoint: arkret_wire::Hash::new(format!("sha256:{}", "c".repeat(64)))
                .unwrap(),
            accepted_at,
        };
        let receipt = RequestAcceptanceReceipt::sign_with(core, |bytes| {
            Ok(arkret_wire::ProtocolSignature {
                verification_method: arkret_wire::DidUrl::new(format!(
                    "{source_did}#federation-signing-key"
                ))
                .unwrap(),
                created_at: accepted_at,
                jws: arkret_signatures::sign_ed25519_detached_jws(&source_key, bytes).unwrap(),
            })
        })
        .unwrap();
        // This fixture authenticates the source transcript and exact producer
        // descriptor. These projection tests do not supply a complete Event or
        // native DID history and do not stand in for the receiving adapter.
        arkret_signatures::contact_receipt::verify_contact_request_acceptance_receipt(
            &receipt,
            &receipt.core.request_event_ref,
            &source_key.verifying_key(),
        )
        .unwrap();
        receipt
    }
    fn request_receipt(
        holder: &str,
        peer: &str,
        issuer: &str,
        event_ref: &str,
    ) -> RequestAcceptanceReceipt {
        let participant = |principal: &str, station: &str| ContactPeer::Human {
            account_id: arkret_wire::AccountId::new(
                DidCoreId::new(principal).unwrap(),
                DidCoreId::new(station).unwrap(),
            ),
        };
        signed_request_receipt(
            participant(holder, issuer),
            participant(
                peer,
                if peer == ALICE {
                    ALICE_SERVICE
                } else {
                    BOB_SERVICE
                },
            ),
            &web_did(issuer),
            event_ref,
        )
    }

    #[test]
    fn glare_basis_uses_wire_order_for_both_arrival_orders_and_rejects_duplicate_refs() {
        let first = request_receipt(
            ALICE,
            BOB,
            ALICE_SERVICE,
            "ak:event:AQ0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        );
        let mut second = request_receipt(
            BOB,
            ALICE,
            BOB_SERVICE,
            "ak:event:AQYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        );
        let forward = derive_glare_basis(&[first.clone(), second.clone()]).unwrap();
        let reverse = derive_glare_basis(&[second.clone(), first.clone()]).unwrap();
        assert_eq!(forward, reverse);
        let ContactRound::Glare { requests, .. } = &forward.1 else {
            unreachable!()
        };
        assert_eq!(requests[0].request_event_ref, first.core.request_event_ref);
        assert_eq!(
            forward.2[0],
            super::super::account::canonical_contact_digest(&first).unwrap()
        );
        second.core.request_event_ref = first.core.request_event_ref.clone();
        assert!(derive_glare_basis(&[first, second]).is_err());
    }

    /// Cross-PS `ak.contact.requested` delivery: the projected pending_incoming
    /// row on the recipient (target holder) MUST record the *originating*
    /// requester_id's home Station as `peer_id` — the
    /// `source-service-id` of the delivery, NOT the recipient's own service
    /// DID. This is exactly the address inkson reads back as
    /// `requester_id` to federate the reverse `respond` delivery.
    #[tokio::test]
    async fn delivered_request_records_originating_peer_id() {
        use coland_test_support::AppStateTestExt as _;
        let config = test_config();
        let service_did = AppState::new(config.clone(), Db { pool: None }).service_did();
        let persisted = coland_test_support::app_state_with_service_did(
            coland_test_support::app_config(),
            service_did,
        );
        let state =
            AppState::new_with_persistence(config, Db { pool: None }, persisted.test_persistence());
        let holder = coland_test_support::pcr_genesis::PcrGenesisFixture::new(state.service_did());
        holder
            .admit_into(state.test_persistence().as_ref())
            .await
            .expect("accepted holder PCR");
        let requester_id = "ak:did_core:web:remote-alice.example"; // issuer, on source Station
        let target = holder.history.account.principal_id.as_str();
        // The private new-source quota is rooted in the holder's accepted PCR;
        // an account projection alone supplies no private authority.
        state
            .identities()
            .save_account(coland_services::identity::AccountProfileState {
                pk: coland_storage::AccountPk(0),
                account_id: arkret_wire::AccountId::new(
                    DidCoreId::new(target.to_owned()).unwrap(),
                    state.service_core_id().clone(),
                ),
                principal_id: DidCoreId::new(target.to_owned()).unwrap(),
                localpart: "local-bob".to_owned(),
                display_name: None,
                bio: None,
                avatar_blob_ref: None,
                created_at: now(),
            })
            .await
            .expect("holder account");
        let source_id = "ak:did_core:web:remote.local"; // requester_id's home PS

        let payload = json!({
            "peer": {"kind": "human", "account_id": {"principal_id": target, "station_id": state.service_id()}},
            "granted_to_peer_scopes": ["direct_message"],
            "introduction_evidence_digest": format!("sha256:{}", "a".repeat(64)),
            "message": "hi from across the federation",
        });
        let request_event_ref = "ak:event:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-";
        let request_receipt = signed_request_receipt(
            ContactPeer::Human {
                account_id: arkret_wire::AccountId::new(
                    DidCoreId::new(requester_id).unwrap(),
                    DidCoreId::new(source_id).unwrap(),
                ),
            },
            ContactPeer::Human {
                account_id: arkret_wire::AccountId::new(
                    DidCoreId::new(target).unwrap(),
                    state.service_core_id().clone(),
                ),
            },
            "did:web:remote.local",
            request_event_ref,
        );

        let requester = account_actor(requester_id, source_id);
        let target_actor = account_actor(target, state.service_id());
        let outcome = project_delivered_contact_fact(
            &state,
            "ak.contact.requested",
            &requester,
            &target_actor,
            &payload,
            request_event_ref,
            Some(&request_receipt),
            None,
            None,
            None,
            Some(source_id),
        )
        .await
        .expect("delivered request projects");
        assert_eq!(outcome, "accepted");

        let record = state
            .contacts()
            .contact_any(&requester, &target_actor)
            .await
            .expect("contact store lookup")
            .expect("pending_incoming row was projected");

        let reverse = state
            .contacts()
            .contact_any(&target_actor, &requester)
            .await
            .expect("recipient-side lookup")
            .expect("the recipient must find the same directional row");
        assert_eq!(reverse.requester_id, record.requester_id);
        assert_eq!(reverse.target_id, record.target_id);
        assert_eq!(reverse.request_event_ref, record.request_event_ref);
        let wrong_station = account_actor(target, source_id);
        assert!(
            state
                .contacts()
                .contact_any(&requester, &wrong_station)
                .await
                .unwrap()
                .is_none()
        );

        assert_eq!(
            record.peer_host_id.as_ref().map(|value| value.as_str()),
            Some(source_id),
            "peer_id must be the originating requester_id's PS, not the recipient's own \
             service_id ({})",
            state.service_id(),
        );
        assert_eq!(
            record
                .request_event_ref
                .as_ref()
                .map(|value| value.as_str()),
            Some("ak:event:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-"),
        );
        assert_ne!(
            record.peer_host_id.as_ref().map(|value| value.as_str()),
            Some(state.service_id().as_str()),
            "peer_id must not point at this recipient service",
        );
    }

    #[test]
    fn glare_basis_and_initiator_are_independent_of_arrival_order() {
        let alice = request_receipt(
            ALICE,
            BOB,
            ALICE_SERVICE,
            "ak:event:ARbUzETAsZ3suuQ0GSmBWTsNjmUnTEEl_ZnDOUWRPm-N",
        );
        let bob = request_receipt(
            BOB,
            ALICE,
            BOB_SERVICE,
            "ak:event:AS8XThowW7JnZc80U10gJh-_lqkA-iSQ-LAvBXj6_9O5",
        );
        let mut first_arrival = [bob.clone(), alice.clone()];
        first_arrival.sort_by(|left, right| {
            left.core
                .request_event_ref
                .as_str()
                .cmp(right.core.request_event_ref.as_str())
        });
        let mut reverse_arrival = [alice, bob];
        reverse_arrival.sort_by(|left, right| {
            left.core
                .request_event_ref
                .as_str()
                .cmp(right.core.request_event_ref.as_str())
        });
        let (left_id, left_basis, _) = derive_glare_basis(&first_arrival).unwrap();
        let (right_id, right_basis, _) = derive_glare_basis(&reverse_arrival).unwrap();
        assert_eq!(left_id, right_id);
        assert_eq!(
            serde_json::to_value(left_basis).unwrap(),
            serde_json::to_value(right_basis).unwrap()
        );
        assert_eq!(
            first_arrival[0]
                .core
                .holder
                .contact_actor_id()
                .signing_principal_id()
                .as_str(),
            ALICE,
            "requests[0] signed request author is the sole mechanical glare initiator"
        );
    }

    #[tokio::test]
    async fn glare_finalize_cas_has_one_concurrent_winner() {
        let state = AppState::new(test_config(), Db { pool: None });
        let now = chrono::Utc::now();
        let record = ContactRecord {
            requester_id: account_actor(ALICE, ALICE_SERVICE),
            target_id: account_actor(BOB, BOB_SERVICE),
            contact_round_id: None,
            granted_to_target_scopes: vec!["direct_message".to_owned()],
            granted_to_requester_scopes: vec!["direct_message".to_owned()],
            status: "pending".to_owned(),
            pending_incoming_admitted: true,
            request_event_ref: None,
            request_slot_states: Vec::new(),
            request_receipts: Vec::new(),
            request_mirror_receipts: Vec::new(),
            contact_round_evidence: None,
            contact_round_evidence_history: Vec::new(),
            control_outcomes: Vec::new(),
            response_event_ref: None,
            tombstone_event_ref: None,
            message: None,
            peer_host_id: Some(arkret_wire::DidCoreId::new(BOB_SERVICE).unwrap()),
            peer_service_resolution: None,
            created_at: now,
            updated_at: now,
        };
        state.contacts().save_contact(record.clone()).await.unwrap();
        let mut winner = record.clone();
        winner.contact_round_id = Some(Hash::new(format!("sha256:{}", "1".repeat(64))).unwrap());
        winner.updated_at += chrono::Duration::microseconds(1);
        let mut loser = record;
        loser.contact_round_id = Some(Hash::new(format!("sha256:{}", "2".repeat(64))).unwrap());
        loser.updated_at += chrono::Duration::microseconds(1);

        assert!(
            state
                .contacts()
                .save_contact_if_updated_at(now, winner)
                .await
                .unwrap()
        );
        assert!(
            !state
                .contacts()
                .save_contact_if_updated_at(now, loser)
                .await
                .unwrap(),
            "the stale concurrent finalize cannot overwrite the first CAS winner"
        );
    }

    #[tokio::test]
    async fn pending_glare_receipts_survive_restart_without_coordinate_rederivation() {
        let config = test_config();
        let state = AppState::new(config.clone(), Db { pool: None });
        let first = request_receipt(
            ALICE,
            BOB,
            ALICE_SERVICE,
            "ak:event:ARbUzETAsZ3suuQ0GSmBWTsNjmUnTEEl_ZnDOUWRPm-N",
        );
        let second = request_receipt(
            BOB,
            ALICE,
            BOB_SERVICE,
            "ak:event:AS8XThowW7JnZc80U10gJh-_lqkA-iSQ-LAvBXj6_9O5",
        );
        let ordered = [first.clone(), second.clone()];
        let (historical_contact_round_id, historical_basis, _) =
            derive_glare_basis(&ordered).unwrap();
        let historical_bundle = ContactRoundEvidenceBundle {
            contact_round_id: historical_contact_round_id.clone(),
            previous_terminal_contact_round_id: None,
            contact_round: historical_basis,
            request_receipts: ordered.to_vec(),
            normal_response_receipt: None,
            glare_concurrency_attestations: None,
            current_proofs: Vec::new(),
            continuity_checkpoint: None,
        };
        let now = chrono::Utc::now();
        state
            .contacts()
            .save_contact(ContactRecord {
                requester_id: account_actor(ALICE, ALICE_SERVICE),
                target_id: account_actor(BOB, BOB_SERVICE),
                contact_round_id: None,
                granted_to_target_scopes: vec!["direct_message".to_owned()],
                granted_to_requester_scopes: vec!["direct_message".to_owned()],
                status: "pending".to_owned(),
                pending_incoming_admitted: true,
                request_event_ref: Some(first.core.request_event_ref.clone()),
                request_slot_states: Vec::new(),
                request_receipts: vec![first.clone(), second.clone()],
                request_mirror_receipts: Vec::new(),
                contact_round_evidence: None,
                contact_round_evidence_history: vec![historical_bundle],
                control_outcomes: Vec::new(),
                response_event_ref: None,
                tombstone_event_ref: None,
                message: None,
                peer_host_id: Some(arkret_wire::DidCoreId::new(BOB_SERVICE).unwrap()),
                peer_service_resolution: None,
                created_at: now,
                updated_at: now,
            })
            .await
            .unwrap();
        let persistence = state.test_persistence();
        drop(state);
        let restarted = AppState::new_with_persistence(config, Db { pool: None }, persistence);
        restarted.hydrate().await.unwrap();
        let alice = account_actor(ALICE, ALICE_SERVICE);
        let bob = account_actor(BOB, BOB_SERVICE);
        let row = restarted
            .contacts()
            .contact_any(&alice, &bob)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.request_receipts.len(), 2);
        assert_eq!(row.contact_round_evidence_history.len(), 1);
        assert_eq!(
            row.contact_round_evidence_history[0].contact_round_id, historical_contact_round_id,
            "restart hydration must retain the exact historical contact_round chain"
        );
        assert_eq!(
            serde_json::to_value(&row.request_receipts[0].core).unwrap(),
            serde_json::to_value(&first.core).unwrap()
        );
        assert_eq!(
            serde_json::to_value(&row.request_receipts[1].core).unwrap(),
            serde_json::to_value(&second.core).unwrap()
        );
        assert_eq!(
            row.peer_host_id.as_ref().map(DidCoreId::as_str),
            Some(BOB_SERVICE)
        );
    }

    #[test]
    fn control_response_loss_replays_only_the_exact_request_digest() {
        let exact = Hash::new(format!("sha256:{}", "7".repeat(64))).unwrap();
        let outcome: PeerContactSubmitOutcome = serde_json::from_value(json!({
            "result_kind": "proof_refresh",
            "status": "accepted",
            "control_receipt": {
            "domain": arkret_wire::DomainSeparationId::PEER_CONTACT_CONTROL_RECEIPT_V1,
                "request_kind": "proof_refresh",
                "request_digest": exact.clone(),
                "outcome": "accepted",
                "result_digest": format!("sha256:{}", "8".repeat(64)),
                "recipient_id": BOB_SERVICE,
                "received_at": "2026-08-09T00:00:00.000Z",
                "issuer_id": BOB_SERVICE,
                "signature": {
                    "verification_method": "did:web:bob-service.example#federation-signing-key",
                    "created_at": "2026-08-09T00:00:00.000Z",
                    "jws": format!("eyJhbGciOiJFZDI1NTE5In0..{}", "A".repeat(86))
                }
            },
            "current_proof": {
                "contact_round_id": format!("sha256:{}", "9".repeat(64)),
                "issuer_id": ALICE_SERVICE,
                "peer": {
                    "kind": "human",
                    "account_id": {
                        "principal_id": BOB,
                        "station_id": BOB_SERVICE
                    }
                },
                "terminal": false,
                "head_event_ref": "ak:event:ARbUzETAsZ3suuQ0GSmBWTsNjmUnTEEl_ZnDOUWRPm-N",
                "accepted_commit_event_ids": ["ak:event:ARbUzETAsZ3suuQ0GSmBWTsNjmUnTEEl_ZnDOUWRPm-N"],
                "complete_through": 1,
                "fresh_until": "2026-08-09T00:10:00.000Z",
                "signature": {
                    "verification_method": "did:web:alice-service.example#federation-signing-key",
                    "created_at": "2026-08-09T00:00:00.000Z",
                    "jws": format!("eyJhbGciOiJFZDI1NTE5In0..{}", "A".repeat(86))
                }
            }
        }))
        .unwrap();
        let record = ContactRecord {
            requester_id: account_actor(ALICE, ALICE_SERVICE),
            target_id: account_actor(BOB, BOB_SERVICE),
            contact_round_id: None,
            granted_to_target_scopes: Vec::new(),
            granted_to_requester_scopes: Vec::new(),
            status: "pending".to_owned(),
            pending_incoming_admitted: true,
            request_event_ref: None,
            request_slot_states: Vec::new(),
            request_receipts: Vec::new(),
            request_mirror_receipts: Vec::new(),
            contact_round_evidence: None,
            contact_round_evidence_history: Vec::new(),
            control_outcomes: vec![outcome.clone()],
            response_event_ref: None,
            tombstone_event_ref: None,
            message: None,
            peer_host_id: None,
            peer_service_resolution: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        assert!(
            replayed_contact_control_outcome(&record, &exact, PeerContactControlKind::ProofRefresh)
                .is_some()
        );
        let different = Hash::new(format!("sha256:{}", "6".repeat(64))).unwrap();
        assert!(
            replayed_contact_control_outcome(
                &record,
                &different,
                PeerContactControlKind::ProofRefresh
            )
            .is_none(),
            "different request bytes cannot reuse the response-loss outcome"
        );
    }
}
