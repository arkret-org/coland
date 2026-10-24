//! Exact Contact originals, bounded current recovery and durable glare choice.
use arkret_canonical as canonical;
use arkret_identifiers::Hash;
use arkret_models_collaboration::contact_operations::*;
use arkret_models_collaboration::governance::peer_contact::{
    ContactIntroductionEvidence, PeerContactAddress,
};
use arkret_wire::{ActorId, Did, DidUrl, Event, EventId, IdempotencyKey, ProtocolSignature};
use coland_http::error::AppError;
use coland_http::result::{JsonResult, json_ok};
use coland_services::identity::ContactRecord;
use salvo::prelude::*;
use serde_json::{Value, json};
use uuid::Uuid;

use super::now;
use crate::state::AppState;
const HEADER_SOURCE_SERVICE_ID: &str = "source-service-id";
const CONTACT_CONTROL_OPERATION: &str =
    arkret_wire::ServiceOperationId::PEER_CONTACTS_COMMAND_SUBMIT_V1;
const CONTACT_CURRENT_MAX_BYTES: usize = 2 * 1024 * 1024;
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
        || event
            .actor_id
            .as_account_id()
            .map(|a| a.station_id.as_str())
            != Some(source_id)
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

pub(crate) fn peer_router() -> Router {
    Router::new().push(Router::with_path("contacts").post(peer_contacts_submit))
}

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
        | PeerContactSubmitRequestBody::CurrentRefresh {
            idempotency_key,
            contact_address,
            ..
        }
        | PeerContactSubmitRequestBody::GlareFinalize {
            idempotency_key,
            contact_address,
            ..
        } => (idempotency_key.as_str(), contact_address),
    }
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
            PeerContactAdmissionAttemptOutcome::Accepted
                | PeerContactAdmissionAttemptOutcome::Duplicate
        )
    {
        return Err(super::super::events::peer::cross_domain_replay(format!(
            "{field} issuer, recipient, or authoritative outcome is invalid"
        )));
    }
    let signing_bytes = receipt
        .canonical_signing_bytes()
        .map_err(|error| AppError::internal(format!("{field} transcript failed: {error}")))?;
    crate::routing::identity::account::verify_contact_service_signature_bytes(
        state,
        expected_service_id,
        &receipt.signature,
        &signing_bytes,
        field,
    )
}

fn sign_contact_mirror_receipt(
    state: &AppState,
    request: &PeerContactSubmitRequestBody,
    event: &Event,
    outcome: PeerContactAdmissionAttemptOutcome,
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

fn contact_control_request_digest(
    request: &PeerContactSubmitRequestBody,
) -> Result<Hash, AppError> {
    Hash::new(
        canonical::canonical_sha256(request)
            .map_err(|error| AppError::internal(format!("Contact control digest: {error}")))?,
    )
    .map_err(|error| AppError::internal(format!("Contact control digest invalid: {error}")))
}

fn sign_contact_control_receipt(
    state: &AppState,
    request: &PeerContactSubmitRequestBody,
    request_kind: PeerContactControlKind,
    outcome: PeerContactAdmissionAttemptOutcome,
    control_material_digest: Option<Hash>,
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
        "control_material_digest": control_material_digest,
        "recipient_id": issuer,
        "received_at": arkret_canonical::format_timestamp_canonical(received_at),
        "issuer_id": issuer,
    });
    if control_material_digest.is_none()
        && let Value::Object(fields) = &mut signing_value
    {
        fields.remove("control_material_digest");
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
        control_material_digest,
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

fn contact_control_receipt_signing_bytes(
    receipt: &PeerContactControlReceipt,
) -> Result<Vec<u8>, AppError> {
    receipt.canonical_signing_bytes().map_err(contact_error)
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

pub(crate) async fn reenqueue_deferred_contact_control(
    state: &AppState,
    request: &PeerContactSubmitRequestBody,
    deferred: &arkret_models_collaboration::contact_operations::PeerContactControlDeferredResponseBody,
    peer_id: &str,
) -> Result<(), AppError> {
    let expected_kind = match request {
        PeerContactSubmitRequestBody::GlareFinalize { .. } => PeerContactControlKind::GlareFinalize,
        PeerContactSubmitRequestBody::CurrentRefresh { .. } => {
            PeerContactControlKind::CurrentRefresh
        }
        _ => {
            return Err(super::super::events::peer::schema_violation(
                "deferred Contact control outcome names an Event carrier",
            ));
        }
    };
    if deferred.status != PeerContactAdmissionAttemptOutcome::Deferred
        || deferred.request_kind != expected_kind
        || deferred.control_receipt.outcome != PeerContactAdmissionAttemptOutcome::Deferred
        || deferred.control_receipt.control_material_digest.is_some()
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
        | PeerContactSubmitRequestBody::CurrentRefresh {
            idempotency_key, ..
        } => *idempotency_key = next_key,
        _ => unreachable!("request branch checked above"),
    }
    enqueue_peer_contact_carrier(state, peer_id, &retry).await?;
    Ok(())
}

fn contact_error(error: impl ToString) -> AppError {
    super::super::events::peer::schema_violation(error.to_string())
}
fn operation_from_carrier(
    delivery: &PeerContactSubmitRequestBody,
) -> Result<ContactOperationEvidence, AppError> {
    Ok(match delivery {
        PeerContactSubmitRequestBody::Request {
            signed_event,
            request_receipt,
            ..
        } => ContactOperationEvidence::Request {
            signed_event: signed_event.clone(),
            request_receipt: request_receipt.clone(),
        },
        PeerContactSubmitRequestBody::Response {
            signed_event,
            response_receipt,
            ..
        } => ContactOperationEvidence::Response {
            signed_event: signed_event.clone(),
            response_receipt: response_receipt.clone(),
        },
        PeerContactSubmitRequestBody::Reject {
            signed_event,
            reject_receipt,
            ..
        } => ContactOperationEvidence::Reject {
            signed_event: signed_event.clone(),
            reject_receipt: reject_receipt.clone(),
        },
        PeerContactSubmitRequestBody::ScopeUpdate {
            signed_event,
            lineage,
            ..
        } => ContactOperationEvidence::ScopeUpdate {
            signed_event: signed_event.clone(),
            lineage: lineage.clone(),
        },
        PeerContactSubmitRequestBody::Tombstone {
            signed_event,
            lineage,
            ..
        } => ContactOperationEvidence::Tombstone {
            signed_event: signed_event.clone(),
            lineage: lineage.clone(),
        },
        _ => {
            return Err(contact_error(
                "control carrier contains no holder operation",
            ));
        }
    })
}
fn carried_current(delivery: &PeerContactSubmitRequestBody) -> Option<&ContactCurrentProof> {
    match delivery {
        PeerContactSubmitRequestBody::Request { current_proof, .. }
        | PeerContactSubmitRequestBody::Response { current_proof, .. } => current_proof.as_ref(),
        PeerContactSubmitRequestBody::ScopeUpdate { current_proof, .. }
        | PeerContactSubmitRequestBody::Tombstone { current_proof, .. } => Some(current_proof),
        _ => None,
    }
}
pub(crate) async fn cache_assertion_at(
    state: &AppState,
    signature: &ProtocolSignature,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<(), AppError> {
    let did = arkret_identity::verification_method_did(signature.verification_method.as_str())
        .map_err(contact_error)?;
    let pinned = state
        .dids()
        .resolve_webvh_state_at(&did, at)
        .await
        .map_err(|e| crate::app_error!(TemporarilyUnavailable, e.to_string()))?;
    let document: arkret_models_identity::service_identity::ServiceDidDocument =
        serde_json::from_value(pinned.document).map_err(contact_error)?;
    let method = document
        .verification_method
        .iter()
        .find(|m| {
            m.id == signature.verification_method.as_str()
                && m.controller == did
                && document.assertion_method.contains(&m.id)
        })
        .ok_or_else(|| {
            contact_error("source method not assertionMethod at exact confirmation time")
        })?;
    let bytes =
        canonical::decode_ed25519_multibase(&method.public_key_multibase).map_err(contact_error)?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes).map_err(contact_error)?;
    if !state.install_historical_contact_assertion_key(
        signature.verification_method.as_str(),
        at,
        key,
    ) {
        return Err(contact_error(
            "source historical method conflicts at evidence time",
        ));
    }
    Ok(())
}
pub(crate) async fn verify_original_contact_operation(
    state: &AppState,
    operation: &ContactOperationEvidence,
) -> Result<(), AppError> {
    operation.validate_shape().map_err(contact_error)?;
    if operation.accepted_at() > now() || operation.source_signature().created_at > now() {
        return Err(contact_error("Contact source confirmation in the future"));
    }
    cache_assertion_at(
        state,
        operation.source_signature(),
        operation.source_authority_at(),
    )
    .await?;
    super::account::verify_contact_service_signature_bytes_at(
        state,
        operation.holder().delivery_station_id().as_str(),
        operation.source_signature(),
        operation.source_authority_at(),
        &operation.source_signing_bytes().map_err(contact_error)?,
        "original Contact source",
    )?;
    match operation {
        ContactOperationEvidence::Response {
            response_receipt, ..
        } => {
            cache_assertion_at(
                state,
                &response_receipt.request_receipt.signature,
                response_receipt.request_receipt.core.accepted_at,
            )
            .await?;
            super::account::validate_request_receipt_cryptography(
                state,
                &response_receipt.request_receipt,
                "original response request",
            )?;
        }
        ContactOperationEvidence::Reject { reject_receipt, .. } => {
            cache_assertion_at(
                state,
                &reject_receipt.request_receipt.signature,
                reject_receipt.request_receipt.core.accepted_at,
            )
            .await?;
            super::account::validate_request_receipt_cryptography(
                state,
                &reject_receipt.request_receipt,
                "original reject request",
            )?;
        }
        _ => {}
    }
    let history = if matches!(operation.holder(), ContactPeer::Agent { .. }) {
        let did = arkret_identity::contact_producer_identity::agent_contact_identity_did(
            operation.event(),
            operation.holder(),
            operation.producer_signer(),
        )
        .map_err(contact_error)?;
        Some(
            state
                .dids()
                .verified_webvh_history(&did)
                .await
                .map_err(|e| crate::app_error!(TemporarilyUnavailable, e.to_string()))?,
        )
    } else {
        None
    };
    verify_exact_contact_event_producer(
        operation.event(),
        operation.holder(),
        operation.producer_signer(),
        operation.holder().delivery_station_id().as_str(),
        history.as_ref(),
    )
}
async fn verify_round_originals(
    state: &AppState,
    basis: &ContactRoundBasis,
    events: &[Event],
) -> Result<(), AppError> {
    basis.validate_shape().map_err(contact_error)?;
    for receipt in &basis.request_receipts {
        let event = events
            .iter()
            .find(|e| e.event_id == receipt.core.request_event_ref)
            .ok_or_else(|| contact_error("round original request missing"))?;
        Box::pin(verify_original_contact_operation(
            state,
            &ContactOperationEvidence::Request {
                signed_event: event.clone(),
                request_receipt: receipt.clone(),
            },
        ))
        .await?;
    }
    if let Some(receipt) = &basis.normal_response_receipt {
        let event = events
            .iter()
            .find(|e| e.event_id == receipt.response_event_ref)
            .ok_or_else(|| contact_error("round original acceptance missing"))?;
        Box::pin(verify_original_contact_operation(
            state,
            &ContactOperationEvidence::Response {
                signed_event: event.clone(),
                response_receipt: receipt.clone(),
            },
        ))
        .await?;
    }
    if let Some(attestations) = &basis.glare_concurrency_attestations {
        for attestation in attestations {
            cache_assertion_at(state, &attestation.signature, attestation.observed_at).await?;
            verify_contact_evidence_signature(
                state,
                attestation.issuer_id.as_str(),
                &attestation.signature,
                &attestation
                    .canonical_signing_bytes()
                    .map_err(contact_error)?,
                "glare durable choice",
            )?;
            validate_glare_checkpoint(attestation)?;
        }
    }
    Ok(())
}
async fn verify_current_proof(
    state: &AppState,
    proof: &ContactCurrentProof,
) -> Result<(), AppError> {
    proof.validate_shape().map_err(contact_error)?;
    if proof.issued_at > now() {
        return Err(contact_error("Contact current issued in future"));
    }
    cache_assertion_at(state, &proof.signature, proof.issued_at).await?;
    verify_contact_evidence_signature(
        state,
        proof.issuer_id.as_str(),
        &proof.signature,
        &proof.canonical_signing_bytes().map_err(contact_error)?,
        "Contact current",
    )?;
    if let Some(closure) = &proof.closed_round {
        Box::pin(verify_original_contact_operation(
            state,
            &closure.operation.operation(),
        ))
        .await?;
    }
    Ok(())
}
pub(crate) async fn verify_contact_current_material(
    state: &AppState,
    material: &ContactCurrentMaterial,
) -> Result<(), AppError> {
    material.validate_shape().map_err(contact_error)?;
    Box::pin(verify_current_proof(state, &material.current_proof)).await?;
    Box::pin(verify_original_contact_operation(
        state,
        &material.head_operation,
    ))
    .await?;
    for grant in &material.scope_grants {
        Box::pin(verify_original_contact_operation(state, grant)).await?;
    }
    if let Some(initial) = &material.initial_identity {
        verify_round_originals(state, &initial.round, &initial.events).await?;
    }
    if let Some(basis) = &material.round_evidence {
        verify_round_originals(
            state,
            basis,
            material
                .round_events
                .as_deref()
                .ok_or_else(|| contact_error("round originals missing"))?,
        )
        .await?;
    }
    for interval in &material.historical_intervals {
        verify_round_originals(state, &interval.round, &interval.round_events).await?;
        Box::pin(verify_original_contact_operation(state, &interval.grant)).await?;
        if let Some(close) = &interval.closed_by {
            Box::pin(verify_original_contact_operation(state, close)).await?;
        }
    }
    Ok(())
}
pub(crate) async fn verify_contact_bundle(
    state: &AppState,
    bundle: &ContactRoundEvidenceBundle,
) -> Result<(), AppError> {
    bundle.validate_shape().map_err(contact_error)?;
    verify_round_originals(
        state,
        &bundle.initial_identity.round,
        &bundle.initial_identity.events,
    )
    .await?;
    verify_round_originals(state, &bundle.basis(), &bundle.round_events).await?;
    for op in bundle.current_operations.iter().chain(&bundle.scope_grants) {
        Box::pin(verify_original_contact_operation(state, op)).await?;
    }
    for proof in &bundle.current_proofs {
        Box::pin(verify_current_proof(state, proof)).await?;
    }
    Ok(())
}
async fn sign_direction_proof(
    state: &AppState,
    current: &ContactPrivateState,
    holder: &ContactPeer,
) -> Result<ContactCurrentProof, AppError> {
    let direction = current
        .direction(holder)
        .ok_or_else(|| crate::app_error!(TemporarilyUnavailable, "source current unavailable"))?;
    let op = &direction.head_operation;
    if holder.delivery_station_id().as_str() != state.service_id() {
        return Err(contact_error(
            "source cannot refresh cached opposite direction",
        ));
    }
    let durable = state
        .contacts()
        .contact_any(&holder.contact_actor_id(), &op.peer().contact_actor_id())
        .await
        .map_err(|e| AppError::internal(e.to_string()))?
        .ok_or_else(|| contact_error("source cursor absent"))?;
    let digest = Hash::new(canonical::canonical_sha256(op).map_err(contact_error)?)
        .map_err(contact_error)?;
    if durable
        .request_slot_states
        .iter()
        .find(|slot| slot.owner_id == holder.contact_actor_id())
        .is_none_or(|slot| {
            slot.peer_id != op.peer().contact_actor_id()
                || slot.version != op.version()
                || slot.head_event_ref != op.event().event_id
                || slot
                    .operation_digest
                    .as_ref()
                    .is_some_and(|known| known != &digest)
        })
    {
        return Err(crate::app_error!(
            TemporarilyUnavailable,
            "source current has not reached its durable operation cursor"
        ));
    }
    let at = now();
    let (method, key) = super::account::contact_assertion_signer(state, at).await?;
    ContactCurrentProof::sign_with(
        op.trust_domain_id().clone(),
        holder.clone(),
        op.peer().clone(),
        current
            .initial_identity
            .as_ref()
            .map(|i| i.round.contact_round_id.clone()),
        current
            .round_basis
            .as_ref()
            .map(|r| r.contact_round_id.clone()),
        state.service_core_id(),
        op.event().event_id.clone(),
        op.version(),
        direction.scope_instances.clone(),
        direction.closed_round.clone().map(Box::new),
        at,
        at + chrono::Duration::minutes(10),
        |bytes| {
            Ok(ProtocolSignature {
                verification_method: method,
                created_at: at,
                jws: super::account::contact_detached_jws(&key, bytes)
                    .map_err(|e| arkret_wire::WireError::Protocol(e.to_string()))?,
            })
        },
    )
    .map_err(contact_error)
}
fn empty_contact(holder: &ContactPeer, peer: &ContactPeer) -> ContactRecord {
    ContactRecord {
        requester_id: holder.contact_actor_id(),
        target_id: peer.contact_actor_id(),
        contact_round_id: None,
        granted_to_target_scopes: vec![],
        granted_to_requester_scopes: vec![],
        status: "pending".into(),
        pending_incoming_admitted: false,
        request_event_ref: None,
        request_slot_states: vec![],
        request_receipts: vec![],
        request_mirror_receipts: vec![],
        contact_round_evidence: None,
        current_state: ContactPrivateState::default(),

        response_event_ref: None,
        tombstone_event_ref: None,
        message: None,
        peer_host_id: None,
        peer_service_resolution: None,
        created_at: now(),
        updated_at: now(),
    }
}
fn replace_direction_proof(
    current: &mut ContactPrivateState,
    proof: ContactCurrentProof,
) -> Result<(), AppError> {
    let direction = current
        .directions
        .iter_mut()
        .find(|d| d.head_operation.holder() == &proof.holder)
        .ok_or_else(|| contact_error("current proof original head missing"))?;
    if direction.head_operation.event().event_id != proof.head_event_ref
        || direction.head_operation.version() != proof.version
        || direction.scope_instances != proof.scope_instances
    {
        return Err(contact_error(
            "source proof changes original operation or scope instances",
        ));
    }
    direction.current_proof = Some(proof);
    Ok(())
}
fn sync_contact_summary(record: &mut ContactRecord) {
    if let Some(basis) = &record.current_state.round_basis {
        record.contact_round_id = Some(basis.contact_round_id.clone());
        if record.status != "tombstoned" {
            record.status = "accepted".into();
        }
    }
    record.contact_round_evidence = record.current_state.evidence_bundle().ok();
    for direction in &record.current_state.directions {
        let scopes = direction
            .scope_instances
            .iter()
            .map(|i| {
                serde_json::to_value(i.contact_scope)
                    .expect("scope serializes")
                    .as_str()
                    .expect("scope string")
                    .to_owned()
            })
            .collect();
        if direction.head_operation.holder().contact_actor_id() == record.requester_id {
            record.granted_to_target_scopes = scopes;
        } else {
            record.granted_to_requester_scopes = scopes;
        }
    }
}
async fn read_exact_control(
    state: &AppState,
    request: &PeerContactSubmitRequestBody,
    requester: &ContactPeer,
) -> Result<Option<PeerContactSubmitResponseBody>, AppError> {
    let (key, _) = peer_contact_delivery_address(request);
    let digest = contact_control_request_digest(request)?;
    let record = state
        .jobs()
        .scoped_idempotency_record(
            &requester.contact_actor_id(),
            CONTACT_CONTROL_OPERATION,
            key,
        )
        .await
        .map_err(|e| AppError::internal(e.to_string()))?;
    record
        .map(|row| {
            if row.request_hash != digest.as_str() {
                return Err(crate::app_error!(
                    DuplicateConflict,
                    "Contact retry key names different canonical bytes"
                ));
            }
            serde_json::from_value(row.response_body).map_err(contact_error)
        })
        .transpose()
}
fn frozen_control_record(
    request: &PeerContactSubmitRequestBody,
    requester: &ContactPeer,
    outcome: &PeerContactSubmitResponseBody,
) -> Result<coland_storage::IdempotencyRecord, AppError> {
    Ok(coland_storage::IdempotencyRecord {
        authenticated_actor: requester.contact_actor_id(),
        operation_id: CONTACT_CONTROL_OPERATION.into(),
        idempotency_key: peer_contact_delivery_address(request).0.into(),
        request_hash: contact_control_request_digest(request)?.to_string(),
        response_status: 200,
        response_body: serde_json::to_value(outcome).map_err(contact_error)?,
        created_at: now(),
        expires_at: chrono::DateTime::<chrono::Utc>::MAX_UTC,
    })
}
fn control_result_digest(
    request: &PeerContactSubmitRequestBody,
    kind: &str,
    material: Option<&ContactCurrentMaterial>,
    attestation: Option<&GlareConcurrencyAttestation>,
    proof: Option<&ContactCurrentProof>,
) -> Result<Hash, AppError> {
    let kind = match kind {
        "current_refresh" => PeerContactControlKind::CurrentRefresh,
        "glare_finalize" => PeerContactControlKind::GlareFinalize,
        _ => return Err(contact_error("unknown Contact control result kind")),
    };
    peer_contact_control_result_digest(
        &contact_control_request_digest(request)?,
        kind,
        attestation,
        proof,
        material,
    )
    .map_err(contact_error)
}
fn deferred_current(
    state: &AppState,
    request: &PeerContactSubmitRequestBody,
    kind: PeerContactControlKind,
) -> Result<PeerContactSubmitResponseBody, AppError> {
    Ok(PeerContactSubmitResponseBody::ControlDeferred(
        PeerContactControlDeferredResponseBody {
            status: PeerContactAdmissionAttemptOutcome::Deferred,
            request_kind: kind,
            control_receipt: sign_contact_control_receipt(
                state,
                request,
                kind,
                PeerContactAdmissionAttemptOutcome::Deferred,
                None,
            )?,
            retry_after_ms: Some(30_000),
        },
    ))
}
async fn handle_current_refresh(
    state: &AppState,
    request: &PeerContactSubmitRequestBody,
    source_id: &str,
) -> Result<PeerContactSubmitResponseBody, AppError> {
    let PeerContactSubmitRequestBody::CurrentRefresh {
        requester,
        trust_domain_id,
        initial_contact_round_id,
        known_version,
        grant_event_refs,
        contact_address,
        ..
    } = request
    else {
        return Err(contact_error("not current_refresh"));
    };
    let holder = &contact_address.recipient;
    if requester.delivery_station_id().as_str() != source_id
        || holder.delivery_station_id().as_str() != state.service_id()
        || trust_domain_id != &state.config().trust_domain
        || requester == holder
        || *known_version > 9_007_199_254_740_991
        || grant_event_refs.len() > 5
        || grant_event_refs
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != grant_event_refs.len()
    {
        return Err(contact_error(
            "current_refresh direction/domain/request bounds invalid",
        ));
    }
    if let Some(result) = Box::pin(read_exact_control(state, request, requester)).await? {
        return Ok(result);
    }
    let record = state
        .contacts()
        .contact_any(&holder.contact_actor_id(), &requester.contact_actor_id())
        .await
        .map_err(|e| AppError::internal(e.to_string()))?;
    let mut record = match record {
        Some(record) if record.current_state.direction(holder).is_some() => record,
        _ => {
            let result = deferred_current(state, request, PeerContactControlKind::CurrentRefresh)?;
            state
                .jobs()
                .store_idempotency_record(frozen_control_record(request, requester, &result)?)
                .await
                .map_err(|e| AppError::internal(e.to_string()))?;
            return Box::pin(read_exact_control(state, request, requester))
                .await?
                .ok_or_else(|| AppError::internal("opaque Contact result was not durable"));
        }
    };
    let original = record
        .current_state
        .direction(holder)
        .ok_or_else(|| contact_error("source direction missing"))?;
    if *known_version > original.head_operation.version()
        || initial_contact_round_id.as_ref().is_some_and(|known| {
            record
                .current_state
                .initial_identity
                .as_ref()
                .map(|i| &i.round.contact_round_id)
                != Some(known)
        })
    {
        let result = deferred_current(state, request, PeerContactControlKind::CurrentRefresh)?;
        let expected = record.updated_at;
        advance_contact_revision(&mut record, expected);
        if !state
            .contacts()
            .save_contact_with_result(
                expected,
                record,
                frozen_control_record(request, requester, &result)?,
            )
            .await
            .map_err(|e| AppError::internal(e.to_string()))?
        {
            return Err(crate::app_error!(
                TemporarilyUnavailable,
                "Contact changed at response cut"
            ));
        }
        return Ok(result);
    }
    let proof = Box::pin(sign_direction_proof(state, &record.current_state, holder)).await?;
    let historical_intervals = state
        .contacts()
        .scope_intervals(trust_domain_id, holder, requester, grant_event_refs)
        .await
        .map_err(|e| AppError::internal(e.to_string()))?;
    if historical_intervals.len() > 5 {
        return Err(crate::app_error!(
            TooLarge,
            "Contact material exceeds response budget"
        ));
    }
    if grant_event_refs.iter().any(|grant| {
        !historical_intervals
            .iter()
            .any(|i| &i.grant.event().event_id == grant)
    }) {
        let result = deferred_current(state, request, PeerContactControlKind::CurrentRefresh)?;
        let expected = record.updated_at;
        advance_contact_revision(&mut record, expected);
        if !state
            .contacts()
            .save_contact_with_result(
                expected,
                record,
                frozen_control_record(request, requester, &result)?,
            )
            .await
            .map_err(|e| AppError::internal(e.to_string()))?
        {
            return Err(crate::app_error!(
                TemporarilyUnavailable,
                "Contact cut changed"
            ));
        }
        return Ok(result);
    }
    let direction = record
        .current_state
        .direction(holder)
        .ok_or_else(|| contact_error("source direction missing"))?;
    let material = ContactCurrentMaterial {
        initial_identity: record.current_state.initial_identity.clone(),
        round_evidence: record.current_state.round_basis.clone(),
        round_events: record
            .current_state
            .round_basis
            .as_ref()
            .map(|_| record.current_state.round_events.clone()),
        head_operation: direction.head_operation.clone(),
        scope_grants: direction.scope_grants.clone(),
        historical_intervals,
        current_proof: proof.clone(),
    };
    material.validate_shape().map_err(contact_error)?;
    let digest = control_result_digest(request, "current_refresh", Some(&material), None, None)?;
    let result = PeerContactSubmitResponseBody::Control(
        PeerContactControlSubmitResponseBody::CurrentRefresh {
            status: PeerContactAdmissionAttemptOutcome::Accepted,
            control_receipt: sign_contact_control_receipt(
                state,
                request,
                PeerContactControlKind::CurrentRefresh,
                PeerContactAdmissionAttemptOutcome::Accepted,
                Some(digest),
            )?,
            material,
        },
    );
    if canonical::canonical_json_bytes(&result)
        .map_err(contact_error)?
        .len()
        > CONTACT_CURRENT_MAX_BYTES
    {
        return Err(crate::app_error!(
            TooLarge,
            "Contact material exceeds response budget"
        ));
    }
    replace_direction_proof(&mut record.current_state, proof)?;
    sync_contact_summary(&mut record);
    let expected = record.updated_at;
    advance_contact_revision(&mut record, expected);
    if !state
        .contacts()
        .save_contact_with_result(
            expected,
            record,
            frozen_control_record(request, requester, &result)?,
        )
        .await
        .map_err(|e| AppError::internal(e.to_string()))?
    {
        return Err(crate::app_error!(
            TemporarilyUnavailable,
            "Contact response cut changed; retry exact request"
        ));
    }
    Ok(result)
}
fn verify_control_result(
    state: &AppState,
    request: &PeerContactSubmitRequestBody,
    receipt: &PeerContactControlReceipt,
    peer_id: &str,
    kind: PeerContactControlKind,
    digest: Option<Hash>,
) -> Result<(), AppError> {
    if receipt.request_kind != kind
        || receipt.request_digest != contact_control_request_digest(request)?
        || receipt.issuer_id.as_str() != peer_id
        || receipt.recipient_id.as_str() != peer_id
        || receipt.control_material_digest != digest
    {
        return Err(contact_error(
            "Contact control receipt does not bind exact request/result/source",
        ));
    }
    verify_contact_evidence_signature(
        state,
        peer_id,
        &receipt.signature,
        &contact_control_receipt_signing_bytes(receipt)?,
        "Contact control result",
    )
}
async fn install_current_response(
    state: &AppState,
    request: &PeerContactSubmitRequestBody,
    material: &ContactCurrentMaterial,
) -> Result<(), AppError> {
    let PeerContactSubmitRequestBody::CurrentRefresh {
        requester,
        trust_domain_id,
        initial_contact_round_id,
        known_version,
        grant_event_refs,
        contact_address,
        ..
    } = request
    else {
        return Err(contact_error("not current_refresh"));
    };
    let proof = &material.current_proof;
    if proof.holder != contact_address.recipient
        || proof.peer != *requester
        || proof.trust_domain_id != *trust_domain_id
        || proof.cache_expires_at <= now()
        || proof.version < *known_version
        || initial_contact_round_id
            .as_ref()
            .is_some_and(|root| Some(root) != proof.initial_contact_round_id.as_ref())
        || material
            .historical_intervals
            .iter()
            .any(|i| !grant_event_refs.contains(&i.grant.event().event_id))
    {
        return Err(contact_error(
            "current response differs from requested direction, instances or freshness",
        ));
    }
    Box::pin(verify_contact_current_material(state, material)).await?;
    let prior = state
        .contacts()
        .contact_any(
            &proof.holder.contact_actor_id(),
            &requester.contact_actor_id(),
        )
        .await
        .map_err(|e| AppError::internal(e.to_string()))?;
    let expected = prior.as_ref().map(|r| r.updated_at);
    let mut record = prior.unwrap_or_else(|| empty_contact(&proof.holder, requester));
    if let Some(round) = &proof.contact_round_id
        && let Some(known) = state
            .contacts()
            .known_round_closure(trust_domain_id, &proof.holder, requester, round)
            .await
            .map_err(|e| AppError::internal(e.to_string()))?
    {
        record
            .current_state
            .close_round(known)
            .map_err(contact_error)?;
    }
    let original_digest =
        Hash::new(canonical::canonical_sha256(&material.head_operation).map_err(contact_error)?)
            .map_err(contact_error)?;
    if let Some(known) = record
        .request_slot_states
        .iter()
        .find(|s| s.owner_id == proof.holder.contact_actor_id())
        && (proof.version < known.version
            || (proof.version == known.version
                && (proof.head_event_ref != known.head_event_ref
                    || known
                        .operation_digest
                        .as_ref()
                        .is_some_and(|digest| digest != &original_digest))))
    {
        return Err(contact_error(
            "current response rolls back or conflicts with durable observed operation",
        ));
    }
    if material.round_evidence.is_none()
        && let ContactOperationEvidence::Request {
            signed_event,
            request_receipt,
        } = &material.head_operation
    {
        let own_pending = record.status == "pending"
            && record.current_state.direction(requester).is_some_and(|d| {
                matches!(d.head_operation, ContactOperationEvidence::Request { .. })
            });
        let admitted = record.pending_incoming_admitted
            || record.current_state.initial_identity.is_some()
            || own_pending;
        let admitted = if admitted {
            true
        } else {
            let target = match requester {
                ContactPeer::Human { account_id } => account_id,
                ContactPeer::Agent {
                    controller_account_id,
                    ..
                } => controller_account_id,
            };
            crate::routing::invites::admit_quarantine_new_source(
                state,
                target,
                proof
                    .holder
                    .contact_actor_id()
                    .signing_principal_id()
                    .as_str(),
                now(),
            )
            .await?
        };
        if !admitted {
            return Err(crate::app_error!(
                TemporarilyUnavailable,
                "Contact pending recovery is unavailable"
            ));
        }
        if !own_pending {
            record.request_receipts.clear();
            record.request_mirror_receipts.clear();
            record.requester_id = proof.holder.contact_actor_id();
            record.target_id = requester.contact_actor_id();
            record.response_event_ref = None;
            record.tombstone_event_ref = None;
        }
        record
            .request_receipts
            .retain(|r| r.core.holder != proof.holder);
        record.request_receipts.push(request_receipt.clone());
        if record.requester_id == proof.holder.contact_actor_id() {
            record.request_event_ref = Some(signed_event.event_id.clone());
        } else {
            record.response_event_ref = Some(signed_event.event_id.clone());
        }
        record.pending_incoming_admitted = true;
        record.status = "pending".into();
        record.contact_round_id = None;
        record.message = signed_event
            .payload
            .get("message")
            .and_then(Value::as_str)
            .map(str::to_owned);
    }
    if material.round_evidence.is_none()
        && let ContactOperationEvidence::Reject { reject_receipt, .. } = &material.head_operation
        && record.current_state.direction(requester).is_some_and(|d| {
            d.head_operation.event().event_id
                == reject_receipt.request_receipt.core.request_event_ref
        })
    {
        record.status = "rejected".into();
        record.contact_round_id = None;
    }
    for instance in &proof.scope_instances {
        let intervals = state
            .contacts()
            .scope_intervals(
                trust_domain_id,
                &proof.holder,
                requester,
                std::slice::from_ref(&instance.grant_event_ref),
            )
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;
        if intervals
            .iter()
            .any(|i| i.contact_scope == instance.contact_scope && i.closed_by.is_some())
        {
            return Err(contact_error(
                "current response revives an independently closed exact grant",
            ));
        }
    }
    record
        .current_state
        .install_authenticated_current(material.clone())
        .map_err(contact_error)?;
    sync_contact_summary(&mut record);
    let holder = &proof.holder.contact_actor_id();
    let next = coland_services::identity::ContactRequestSlotState {
        owner_id: holder.clone(),
        peer_id: requester.contact_actor_id(),
        version: proof.version,
        head_event_ref: proof.head_event_ref.clone(),
        operation_digest: Some(original_digest),
        request_choice: if material.round_evidence.is_none()
            && matches!(
                material.head_operation,
                ContactOperationEvidence::Request { .. }
            ) {
            Some(coland_domain::identity::ContactRequestChoice::Open {
                request_event_ref: proof.head_event_ref.clone(),
            })
        } else {
            record
                .request_slot_states
                .iter()
                .find(|s| &s.owner_id == holder)
                .and_then(|s| s.request_choice.clone())
        },
    };
    if let Some(slot) = record
        .request_slot_states
        .iter_mut()
        .find(|s| &s.owner_id == holder)
    {
        if slot.version <= proof.version {
            *slot = next;
        }
    } else {
        record.request_slot_states.push(next);
    }
    if let Some(expected) = expected {
        advance_contact_revision(&mut record, expected);
        Box::pin(save_contact_cas(state.contacts(), expected, record)).await?;
    } else {
        state
            .contacts()
            .save_contact(record)
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;
    }
    Ok(())
}
pub(crate) async fn cache_contact_outcome_assertion_history(
    state: &AppState,
    outcome: &PeerContactSubmitResponseBody,
) -> Result<(), AppError> {
    let mut signatures = Vec::new();
    match outcome {
        PeerContactSubmitResponseBody::Event(outcome) => {
            signatures.push(&outcome.mirror_receipt.signature);
            if let Some(proof) = &outcome.current_proof {
                signatures.push(&proof.signature);
            }
        }
        PeerContactSubmitResponseBody::Control(
            PeerContactControlSubmitResponseBody::CurrentRefresh {
                control_receipt,
                material,
                ..
            },
        ) => {
            signatures.push(&control_receipt.signature);
            signatures.push(&material.current_proof.signature);
        }
        PeerContactSubmitResponseBody::Control(
            PeerContactControlSubmitResponseBody::GlareFinalize {
                control_receipt,
                glare_concurrency_attestation,
                current_proof,
                ..
            },
        ) => {
            signatures.push(&control_receipt.signature);
            signatures.push(&glare_concurrency_attestation.signature);
            if let Some(proof) = current_proof {
                signatures.push(&proof.signature);
            }
        }
        PeerContactSubmitResponseBody::ControlDeferred(outcome) => {
            signatures.push(&outcome.control_receipt.signature)
        }
    }
    cache_contact_assertion_signatures(state, signatures).await
}
pub(crate) async fn accept_outbound_contact_control_outcome(
    state: &AppState,
    request: &PeerContactSubmitRequestBody,
    outcome: &PeerContactSubmitResponseBody,
    peer_id: &str,
) -> Result<(), AppError> {
    cache_contact_outcome_assertion_history(state, outcome).await?;
    match (request, outcome) {
        (
            PeerContactSubmitRequestBody::CurrentRefresh { .. },
            PeerContactSubmitResponseBody::Control(
                PeerContactControlSubmitResponseBody::CurrentRefresh {
                    status,
                    control_receipt,
                    material,
                },
            ),
        ) => {
            if !matches!(
                status,
                PeerContactAdmissionAttemptOutcome::Accepted
                    | PeerContactAdmissionAttemptOutcome::Duplicate
            ) || control_receipt.outcome != *status
            {
                return Err(contact_error("current result status invalid"));
            }
            verify_control_result(
                state,
                request,
                control_receipt,
                peer_id,
                PeerContactControlKind::CurrentRefresh,
                Some(control_result_digest(
                    request,
                    "current_refresh",
                    Some(material),
                    None,
                    None,
                )?),
            )?;
            if let PeerContactSubmitRequestBody::CurrentRefresh {
                requester,
                trust_domain_id,
                contact_address,
                ..
            } = request
            {
                let op = &material.head_operation;
                if op.holder() != &contact_address.recipient
                    || op.peer() != requester
                    || op.trust_domain_id() != trust_domain_id
                {
                    return Err(contact_error(
                        "current original changes requested pair or domain",
                    ));
                }
                Box::pin(verify_original_contact_operation(state, op)).await?;
                Box::pin(persist_authenticated_observation(state, op)).await?;
            }
            if material.head_operation.round_closure().is_some() {
                let op = &material.head_operation;
                let PeerContactSubmitRequestBody::CurrentRefresh {
                    requester,
                    trust_domain_id,
                    contact_address,
                    ..
                } = request
                else {
                    return Err(contact_error("not current refresh"));
                };
                if op.trust_domain_id() != trust_domain_id
                    || op.holder() != &contact_address.recipient
                    || op.peer() != requester
                {
                    return Err(contact_error(
                        "current original closure changes requested direction",
                    ));
                }
                Box::pin(verify_original_contact_operation(state, op)).await?;
                Box::pin(persist_verified_round_closure(state, op)).await?;
            }
            if let Some(closure) = &material.current_proof.closed_round {
                let op = closure.operation.operation();
                let PeerContactSubmitRequestBody::CurrentRefresh {
                    requester,
                    trust_domain_id,
                    contact_address,
                    ..
                } = request
                else {
                    return Err(contact_error("not current refresh"));
                };
                if op.trust_domain_id() != trust_domain_id
                    || !((op.holder() == requester && op.peer() == &contact_address.recipient)
                        || (op.peer() == requester && op.holder() == &contact_address.recipient))
                {
                    return Err(contact_error(
                        "current closure changes requested exact pair",
                    ));
                }
                Box::pin(verify_original_contact_operation(state, &op)).await?;
                Box::pin(persist_verified_round_closure(state, &op)).await?;
            }
            Box::pin(install_current_response(state, request, material)).await
        }
        (
            PeerContactSubmitRequestBody::GlareFinalize { .. },
            PeerContactSubmitResponseBody::Control(
                PeerContactControlSubmitResponseBody::GlareFinalize {
                    status,
                    control_receipt,
                    glare_concurrency_attestation,
                    current_proof,
                },
            ),
        ) => {
            if !matches!(
                status,
                PeerContactAdmissionAttemptOutcome::Accepted
                    | PeerContactAdmissionAttemptOutcome::Duplicate
            ) || control_receipt.outcome != *status
            {
                return Err(contact_error("glare result status invalid"));
            }
            verify_control_result(
                state,
                request,
                control_receipt,
                peer_id,
                PeerContactControlKind::GlareFinalize,
                Some(control_result_digest(
                    request,
                    "glare_finalize",
                    None,
                    Some(glare_concurrency_attestation),
                    current_proof.as_ref(),
                )?),
            )?;
            Box::pin(install_glare_response(
                state,
                request,
                glare_concurrency_attestation,
                current_proof.as_ref(),
            ))
            .await
        }
        (_, PeerContactSubmitResponseBody::ControlDeferred(deferred)) => {
            reenqueue_deferred_contact_control(state, request, deferred, peer_id).await
        }
        _ => Err(contact_error(
            "Contact control response branch differs from request",
        )),
    }
}
fn validate_glare_checkpoint(attestation: &GlareConcurrencyAttestation) -> Result<(), AppError> {
    attestation
        .validate_slot_commitment()
        .map_err(contact_error)
}
async fn ensure_local_glare_choice(
    state: &AppState,
    record: &mut ContactRecord,
    holder: &ContactPeer,
    receipts: &[RequestAcceptanceReceipt; 2],
) -> Result<GlareConcurrencyAttestation, AppError> {
    use coland_domain::identity::ContactRequestChoice;
    let (round, _, digests) = derive_glare_basis(receipts)?;
    let own = receipts
        .iter()
        .find(|r| r.core.holder == *holder)
        .ok_or_else(|| contact_error("glare own request missing"))?;
    if let Some(prior) = record
        .current_state
        .local_glare_attestations
        .iter()
        .find(|a| a.subject_id == holder.contact_actor_id())
        && prior.contact_round_id == round
    {
        if prior.request_event_ref != own.core.request_event_ref
            || prior.version != own.core.version
            || prior.request_receipt_digests != digests
        {
            return Err(contact_error("glare retry changes fixed original requests"));
        }
        return Ok(prior.clone());
    }
    let peer_request = receipts
        .iter()
        .find(|r| r.core.peer == *holder)
        .ok_or_else(|| contact_error("glare opposite request missing"))?;
    let slot = record
        .request_slot_states
        .iter_mut()
        .find(|s| s.owner_id == holder.contact_actor_id())
        .ok_or_else(|| contact_error("glare source operation cursor absent"))?;
    if slot.head_event_ref != own.core.request_event_ref
        || slot.version != own.core.version
        || !matches!(&slot.request_choice,Some(ContactRequestChoice::Open{request_event_ref}) if request_event_ref==&own.core.request_event_ref)
    {
        return Err(contact_error(
            "request already consumed by another durable choice",
        ));
    }
    let at = now();
    let (method, key) = super::account::contact_assertion_signer(state, at).await?;
    let attestation = GlareConcurrencyAttestation::sign_with(
        own.core.trust_domain_id.clone(),
        own.core.initial_contact_round_id.clone(),
        round,
        own.core.version,
        own.core.request_event_ref.clone(),
        holder.contact_actor_id(),
        state.service_core_id(),
        own.core.peer.contact_actor_id(),
        digests,
        at,
        |bytes| {
            Ok(ProtocolSignature {
                verification_method: method,
                created_at: at,
                jws: super::account::contact_detached_jws(&key, bytes)
                    .map_err(|e| arkret_wire::WireError::Protocol(e.to_string()))?,
            })
        },
    )
    .map_err(contact_error)?;
    slot.request_choice = Some(ContactRequestChoice::Glare {
        request_event_ref: own.core.request_event_ref.clone(),
        counterpart_event_ref: peer_request.core.request_event_ref.clone(),
    });
    record
        .current_state
        .local_glare_attestations
        .retain(|a| a.subject_id != holder.contact_actor_id());
    record
        .current_state
        .local_glare_attestations
        .push(attestation.clone());
    if record.current_state.local_glare_attestations.len() > 2 {
        return Err(contact_error(
            "local glare subjects exceed exact pair bound",
        ));
    }
    let expected = record.updated_at;
    advance_contact_revision(record, expected);
    Box::pin(save_contact_cas(state.contacts(), expected, record.clone())).await?;
    Ok(attestation)
}
async fn verify_glare_attestation(
    state: &AppState,
    attestation: &GlareConcurrencyAttestation,
    receipts: &[RequestAcceptanceReceipt; 2],
) -> Result<(), AppError> {
    let (round, _, digests) = derive_glare_basis(receipts)?;
    let own = receipts
        .iter()
        .find(|r| r.core.holder.contact_actor_id() == attestation.subject_id)
        .ok_or_else(|| contact_error("glare subject outside exact pair"))?;
    if attestation.trust_domain_id != own.core.trust_domain_id
        || attestation.initial_contact_round_id != own.core.initial_contact_round_id
        || attestation.contact_round_id != round
        || attestation.version != own.core.version
        || attestation.request_event_ref != own.core.request_event_ref
        || attestation.peer_id != own.core.peer.contact_actor_id()
        || attestation.issuer_id != own.core.issuer_id
        || attestation.request_receipt_digests != digests
        || attestation.observed_at > now()
        || attestation.signature.created_at != attestation.observed_at
    {
        return Err(contact_error(
            "glare attestation does not bind exact pending origins",
        ));
    }
    validate_glare_checkpoint(attestation)?;
    cache_assertion_at(state, &attestation.signature, attestation.observed_at).await?;
    verify_contact_evidence_signature(
        state,
        attestation.issuer_id.as_str(),
        &attestation.signature,
        &attestation
            .canonical_signing_bytes()
            .map_err(contact_error)?,
        "glare choice",
    )
}
async fn establish_glare(
    state: &AppState,
    record: &mut ContactRecord,
    receipts: &[RequestAcceptanceReceipt; 2],
    local: &GlareConcurrencyAttestation,
    remote: &GlareConcurrencyAttestation,
) -> Result<ContactCurrentProof, AppError> {
    verify_glare_attestation(state, local, receipts).await?;
    verify_glare_attestation(state, remote, receipts).await?;
    if local.subject_id == remote.subject_id {
        return Err(contact_error(
            "glare needs both independent durable choices",
        ));
    }
    let (round, core, _) = derive_glare_basis(receipts)?;
    // Opposite finalize carriers may list the same original requests in
    // opposite order. Persist their evidence in the round's wire-byte order.
    let mut ordered_receipts = receipts.clone();
    ordered_receipts.sort_by(|a, b| {
        arkret_models_collaboration::contact_operations::compare_contact_request_event_refs(
            &a.core.request_event_ref,
            &b.core.request_event_ref,
        )
    });
    let mut events = Vec::new();
    for receipt in &ordered_receipts {
        let original = record
            .current_state
            .directions
            .iter()
            .find(|d| d.head_operation.event().event_id == receipt.core.request_event_ref)
            .ok_or_else(|| {
                crate::app_error!(TemporarilyUnavailable, "glare original request unavailable")
            })?
            .head_operation
            .clone();
        Box::pin(verify_original_contact_operation(state, &original)).await?;
        events.push(original.event().clone());
    }
    let mut attestations = [local.clone(), remote.clone()];
    attestations.sort_by_key(|a| a.subject_id.clone());
    record
        .current_state
        .establish(
            ContactRoundBasis {
                contact_round_id: round.clone(),
                contact_round: core,
                request_receipts: ordered_receipts.to_vec(),
                normal_response_receipt: None,
                glare_concurrency_attestations: Some(attestations),
            },
            events,
        )
        .map_err(contact_error)?;
    let holder = receipts
        .iter()
        .find(|r| r.core.holder.contact_actor_id() == local.subject_id)
        .ok_or_else(|| contact_error("local glare direction missing"))?
        .core
        .holder
        .clone();
    let proof = Box::pin(sign_direction_proof(state, &record.current_state, &holder)).await?;
    replace_direction_proof(&mut record.current_state, proof.clone())?;
    record.status = "accepted".into();
    record.contact_round_id = Some(round);
    sync_contact_summary(record);
    Ok(proof)
}
async fn handle_glare_finalize(
    state: &AppState,
    request: &PeerContactSubmitRequestBody,
    source_id: &str,
) -> Result<PeerContactSubmitResponseBody, AppError> {
    let PeerContactSubmitRequestBody::GlareFinalize {
        contact_round_id,
        contact_round,
        request_receipts,
        remote_mirror_receipt,
        glare_concurrency_attestation: remote,
        contact_address,
        ..
    } = request
    else {
        return Err(contact_error("not glare_finalize"));
    };
    let requester = &request_receipts
        .iter()
        .find(|r| r.core.holder.contact_actor_id() == remote.subject_id)
        .ok_or_else(|| contact_error("remote glare participant missing"))?
        .core
        .holder;
    if requester.delivery_station_id().as_str() != source_id
        || remote.issuer_id.as_str() != source_id
        || contact_address.recipient
            != request_receipts
                .iter()
                .find(|r| r.core.peer == *requester)
                .ok_or_else(|| contact_error("glare opposite request absent"))?
                .core
                .holder
    {
        return Err(contact_error(
            "glare transport does not bind exact opposite pair",
        ));
    }
    if let Some(result) = Box::pin(read_exact_control(state, request, requester)).await? {
        return Ok(result);
    }
    let (round, core, _) = derive_glare_basis(request_receipts)?;
    if &round != contact_round_id || &core != contact_round {
        return Err(contact_error("glare round core mismatch"));
    }
    cache_contact_assertion_signatures(state, vec![&remote_mirror_receipt.signature]).await?;
    validate_mirror_receipt_cryptography(
        state,
        remote_mirror_receipt,
        state.service_id(),
        "glare request mirror",
    )?;
    if remote_mirror_receipt.signed_event_ref
        != request_receipts
            .iter()
            .find(|r| r.core.holder == *requester)
            .ok_or_else(|| contact_error("glare request missing"))?
            .core
            .request_event_ref
    {
        return Err(contact_error("glare mirror names another request"));
    }
    verify_glare_attestation(state, remote, request_receipts).await?;
    let holder = &contact_address.recipient;
    let mut record = state
        .contacts()
        .contact_any(&holder.contact_actor_id(), &requester.contact_actor_id())
        .await
        .map_err(|e| AppError::internal(e.to_string()))?
        .ok_or_else(|| {
            crate::app_error!(TemporarilyUnavailable, "glare request material unavailable")
        })?;
    let local = Box::pin(ensure_local_glare_choice(
        state,
        &mut record,
        holder,
        request_receipts,
    ))
    .await?;
    let proof = Box::pin(establish_glare(
        state,
        &mut record,
        request_receipts,
        &local,
        remote,
    ))
    .await?;
    let result = PeerContactSubmitResponseBody::Control(
        PeerContactControlSubmitResponseBody::GlareFinalize {
            status: PeerContactAdmissionAttemptOutcome::Accepted,
            control_receipt: sign_contact_control_receipt(
                state,
                request,
                PeerContactControlKind::GlareFinalize,
                PeerContactAdmissionAttemptOutcome::Accepted,
                Some(control_result_digest(
                    request,
                    "glare_finalize",
                    None,
                    Some(&local),
                    Some(&proof),
                )?),
            )?,
            glare_concurrency_attestation: local,
            current_proof: Some(proof),
        },
    );
    let expected = record.updated_at;
    advance_contact_revision(&mut record, expected);
    if !state
        .contacts()
        .save_contact_with_result(
            expected,
            record,
            frozen_control_record(request, requester, &result)?,
        )
        .await
        .map_err(|e| AppError::internal(e.to_string()))?
    {
        return Err(crate::app_error!(
            TemporarilyUnavailable,
            "glare state changed before result freeze"
        ));
    }
    Ok(result)
}
async fn install_glare_response(
    state: &AppState,
    request: &PeerContactSubmitRequestBody,
    remote: &GlareConcurrencyAttestation,
    remote_proof: Option<&ContactCurrentProof>,
) -> Result<(), AppError> {
    let PeerContactSubmitRequestBody::GlareFinalize {
        request_receipts,
        glare_concurrency_attestation: local,
        ..
    } = request
    else {
        return Err(contact_error("not glare_finalize"));
    };
    let holder = &request_receipts
        .iter()
        .find(|r| r.core.holder.contact_actor_id() == local.subject_id)
        .ok_or_else(|| contact_error("local glare request missing"))?
        .core
        .holder;
    let peer = &request_receipts
        .iter()
        .find(|r| r.core.holder.contact_actor_id() == remote.subject_id)
        .ok_or_else(|| contact_error("remote glare request missing"))?
        .core
        .holder;
    let mut record = state
        .contacts()
        .contact_any(&holder.contact_actor_id(), &peer.contact_actor_id())
        .await
        .map_err(|e| AppError::internal(e.to_string()))?
        .ok_or_else(|| crate::app_error!(TemporarilyUnavailable, "glare current unavailable"))?;
    if !record
        .current_state
        .local_glare_attestations
        .contains(local)
    {
        return Err(contact_error("glare response changes durable local choice"));
    }
    let expected = record.updated_at;
    Box::pin(establish_glare(
        state,
        &mut record,
        request_receipts,
        local,
        remote,
    ))
    .await?;
    if let Some(proof) = remote_proof {
        Box::pin(verify_current_proof(state, proof)).await?;
        if proof.holder != *peer || proof.peer != *holder || proof.cache_expires_at <= now() {
            return Err(contact_error(
                "glare response current direction or freshness mismatch",
            ));
        }
        replace_direction_proof(&mut record.current_state, proof.clone())?;
    }
    sync_contact_summary(&mut record);
    advance_contact_revision(&mut record, expected);
    Box::pin(save_contact_cas(state.contacts(), expected, record)).await
}
async fn queue_current_refresh(
    state: &AppState,
    requester: &ContactPeer,
    holder: &ContactPeer,
    current: &ContactPrivateState,
    grants: Vec<EventId>,
) -> Result<(), AppError> {
    let Some(address) = super::account::contact_delivery_address(state, holder, None).await? else {
        return Ok(());
    };
    let durable = state
        .contacts()
        .contact_any(&holder.contact_actor_id(), &requester.contact_actor_id())
        .await
        .map_err(|e| AppError::internal(e.to_string()))?;
    let observed_version = durable
        .as_ref()
        .and_then(|r| {
            r.request_slot_states
                .iter()
                .find(|slot| slot.owner_id == holder.contact_actor_id())
        })
        .map_or(0, |slot| slot.version);
    let request = PeerContactSubmitRequestBody::CurrentRefresh {
        idempotency_key: IdempotencyKey::new(format!("contact-current:{}", Uuid::new_v4()))
            .map_err(contact_error)?,
        requester: requester.clone(),
        trust_domain_id: state.config().trust_domain.clone(),
        initial_contact_round_id: current
            .initial_identity
            .as_ref()
            .map(|i| i.round.contact_round_id.clone())
            .or_else(|| current.initial_root_floor.clone()),
        known_version: current
            .direction(holder)
            .map_or(0, |d| d.head_operation.version())
            .max(observed_version),
        grant_event_refs: grants,
        contact_address: address,
    };
    enqueue_peer_contact_carrier(state, holder.delivery_station_id().as_str(), &request).await?;
    Ok(())
}
pub(crate) async fn persist_request_mirror_receipt(
    state: &AppState,
    holder: &ActorId,
    peer: &ActorId,
    receipt: &PeerContactMirrorReceipt,
) -> Result<(), AppError> {
    let Some(mut record) = state
        .contacts()
        .contact_any(holder, peer)
        .await
        .map_err(|e| AppError::internal(e.to_string()))?
    else {
        return Err(contact_error("request mirror has no original Contact"));
    };
    if !record
        .request_receipts
        .iter()
        .any(|r| r.core.request_event_ref == receipt.signed_event_ref)
    {
        // The enclosing carrier already binds this signed acknowledgement to
        // its exact original. A later round does not need the obsolete mirror.
        return Ok(());
    }
    if record
        .request_mirror_receipts
        .iter()
        .any(|r| r.signed_event_ref == receipt.signed_event_ref)
    {
        return Ok(());
    }
    let expected = record.updated_at;
    record.request_mirror_receipts.retain(|r| {
        record
            .request_receipts
            .iter()
            .any(|request| request.core.request_event_ref == r.signed_event_ref)
    });
    record.request_mirror_receipts.push(receipt.clone());
    if record.request_mirror_receipts.len() > 2 {
        return Err(contact_error(
            "pending Contact mirrors exceed two exact requests",
        ));
    }
    advance_contact_revision(&mut record, expected);
    Box::pin(save_contact_cas(state.contacts(), expected, record)).await
}
pub(crate) async fn enqueue_glare_finalize_if_ready(
    state: &AppState,
    holder: &ActorId,
    peer: &ActorId,
) -> Result<(), AppError> {
    let Some(mut record) = state
        .contacts()
        .contact_any(holder, peer)
        .await
        .map_err(|e| AppError::internal(e.to_string()))?
    else {
        return Ok(());
    };
    let Ok(receipts) = <[RequestAcceptanceReceipt; 2]>::try_from(record.request_receipts.clone())
    else {
        return Ok(());
    };
    let Some(own) = receipts.iter().find(|r| {
        r.core.holder.contact_actor_id() == *holder
            && r.core.holder.delivery_station_id().as_str() == state.service_id()
    }) else {
        return Ok(());
    };
    if own.core.peer.delivery_station_id().as_str() == state.service_id() {
        if record.status == "accepted" {
            return Ok(());
        }
        let own = own.clone();
        let local = Box::pin(ensure_local_glare_choice(
            state,
            &mut record,
            &own.core.holder,
            &receipts,
        ))
        .await?;
        let remote = Box::pin(ensure_local_glare_choice(
            state,
            &mut record,
            &own.core.peer,
            &receipts,
        ))
        .await?;
        Box::pin(establish_glare(
            state,
            &mut record,
            &receipts,
            &local,
            &remote,
        ))
        .await?;
        let proof = Box::pin(sign_direction_proof(
            state,
            &record.current_state,
            &own.core.peer,
        ))
        .await?;
        replace_direction_proof(&mut record.current_state, proof)?;
        sync_contact_summary(&mut record);
        let expected = record.updated_at;
        advance_contact_revision(&mut record, expected);
        return Box::pin(save_contact_cas(state.contacts(), expected, record)).await;
    }
    let Some(mirror) = record
        .request_mirror_receipts
        .iter()
        .find(|m| {
            m.signed_event_ref == own.core.request_event_ref
                && m.issuer_id == *own.core.peer.delivery_station_id()
        })
        .cloned()
    else {
        return Ok(());
    };
    let own = own.clone();
    let local = Box::pin(ensure_local_glare_choice(
        state,
        &mut record,
        &own.core.holder,
        &receipts,
    ))
    .await?;
    let (round, core, _) = derive_glare_basis(&receipts)?;
    let Some(address) =
        super::account::contact_delivery_address(state, &own.core.peer, None).await?
    else {
        return Ok(());
    };
    let request = PeerContactSubmitRequestBody::GlareFinalize {
        idempotency_key: IdempotencyKey::new(format!(
            "glare-finalize:{round}:{}",
            own.core.request_event_ref
        ))
        .map_err(contact_error)?,
        contact_round_id: round,
        contact_round: core,
        request_receipts: receipts,
        remote_mirror_receipt: mirror,
        glare_concurrency_attestation: local,
        contact_address: address,
    };
    enqueue_peer_contact_carrier(
        state,
        own.core.peer.delivery_station_id().as_str(),
        &request,
    )
    .await?;
    Ok(())
}
async fn apply_delivered_operation(
    state: &AppState,
    delivery: &PeerContactSubmitRequestBody,
    operation: &ContactOperationEvidence,
    response: &mut PeerContactSubmitResponseBody,
) -> Result<(), AppError> {
    let holder = operation.holder();
    let peer = operation.peer();
    let prior = state
        .contacts()
        .contact_any(&holder.contact_actor_id(), &peer.contact_actor_id())
        .await
        .map_err(|e| AppError::internal(e.to_string()))?;
    let mut record = match prior {
        Some(record) => record,
        None => {
            if !matches!(operation, ContactOperationEvidence::Request { .. }) {
                Box::pin(queue_current_refresh(
                    state,
                    peer,
                    holder,
                    &ContactPrivateState::default(),
                    vec![],
                ))
                .await?;
                return Err(crate::app_error!(
                    TemporarilyUnavailable,
                    "Contact exact current recovery required"
                ));
            }
            let mut record = empty_contact(holder, peer);
            record.peer_host_id = Some(holder.delivery_station_id().clone());
            // Persist no authorizing fact before the exact result transaction.
            state
                .contacts()
                .save_contact(record.clone())
                .await
                .map_err(|e| AppError::internal(e.to_string()))?;
            record = state
                .contacts()
                .contact_any(&holder.contact_actor_id(), &peer.contact_actor_id())
                .await
                .map_err(|e| AppError::internal(e.to_string()))?
                .ok_or_else(|| AppError::internal("Contact row disappeared"))?;
            record
        }
    };
    let expected = record.updated_at;
    if let ContactOperationEvidence::Tombstone {
        signed_event,
        lineage,
    } = &operation
    {
        let round = lineage
            .contact_round_id
            .clone()
            .ok_or_else(|| contact_error("tombstone missing exact round"))?;
        record
            .current_state
            .close_round(ContactRoundClosure {
                contact_round_id: round.clone(),
                operation: ContactTombstoneEvidence {
                    kind: ContactTombstoneEvidenceKind::Tombstone,
                    signed_event: signed_event.clone(),
                    lineage: lineage.clone(),
                },
            })
            .map_err(contact_error)?;
        if record.contact_round_id.as_ref() == Some(&round) {
            record.status = "tombstoned".into();
            record.tombstone_event_ref = Some(signed_event.event_id.clone());
        }
    }
    let original_digest = Hash::new(canonical::canonical_sha256(operation).map_err(contact_error)?)
        .map_err(contact_error)?;
    let known = record
        .request_slot_states
        .iter()
        .find(|s| s.owner_id == holder.contact_actor_id());
    if known.is_some_and(|s| {
        s.version == operation.version()
            && (s.head_event_ref != operation.event().event_id
                || s.operation_digest
                    .as_ref()
                    .is_some_and(|digest| digest != &original_digest))
    }) {
        return Err(contact_error(
            "delivered same version changes the immutable observed operation",
        ));
    }
    let prior_version = record
        .current_state
        .direction(holder)
        .map_or(0, |d| d.head_operation.version())
        .max(known.map_or(0, |s| s.version));
    if operation.version() < prior_version {
        return Ok(());
    }
    if let Some(prior) = record.current_state.direction(holder)
        && prior.head_operation.version() == operation.version()
    {
        if canonical::canonical_json_bytes(&prior.head_operation).map_err(contact_error)?
            != canonical::canonical_json_bytes(operation).map_err(contact_error)?
        {
            return Err(contact_error("same version changes immutable original"));
        }
        return Ok(());
    }
    let installed_version = record
        .current_state
        .direction(holder)
        .map_or(0, |d| d.head_operation.version());
    if installed_version == 0 && operation.version() > 1 {
        Box::pin(queue_current_refresh(
            state,
            peer,
            holder,
            &record.current_state,
            vec![],
        ))
        .await?;
        return Err(crate::app_error!(
            TemporarilyUnavailable,
            "original direction recovery required at durable observation floor"
        ));
    }
    if operation.version() > installed_version + 1 {
        // A valid old closure is committed independently; no gap invents a head.
        if matches!(operation, ContactOperationEvidence::Tombstone { .. }) {
            advance_contact_revision(&mut record, expected);
            Box::pin(save_contact_cas(state.contacts(), expected, record.clone())).await?;
        }
        Box::pin(queue_current_refresh(
            state,
            peer,
            holder,
            &record.current_state,
            vec![],
        ))
        .await?;
        return Err(crate::app_error!(
            TemporarilyUnavailable,
            "Contact operation gap requires complete current"
        ));
    }
    if let Some(initial) = &record.current_state.initial_identity {
        if operation.initial_contact_round_id() != Some(&initial.round.contact_round_id) {
            return Err(contact_error(
                "delivered Contact operation changes fixed first identity",
            ));
        }
    } else if operation.initial_contact_round_id().is_some() {
        Box::pin(queue_current_refresh(
            state,
            peer,
            holder,
            &record.current_state,
            vec![],
        ))
        .await?;
        return Err(crate::app_error!(
            TemporarilyUnavailable,
            "Contact fixed first identity recovery required"
        ));
    }
    if matches!(operation, ContactOperationEvidence::Request { .. })
        && record
            .current_state
            .direction(holder)
            .is_none_or(|d| d.head_operation.event().event_id != operation.event().event_id)
    {
        if record.status == "accepted" {
            return Err(contact_error("active Contact cannot open another round"));
        }
        if record.status != "pending" {
            record.request_receipts.clear();
            record.request_mirror_receipts.clear();
            record.requester_id = holder.contact_actor_id();
            record.target_id = peer.contact_actor_id();
            record.request_event_ref = None;
            record.response_event_ref = None;
            record.tombstone_event_ref = None;
        }
        record.current_state.round_basis = None;
        record.current_state.round_events.clear();
        record
            .current_state
            .local_glare_attestations
            .retain(|a| a.subject_id != holder.contact_actor_id());
        for direction in &mut record.current_state.directions {
            direction.scope_instances.clear();
            direction.scope_grants.clear();
            direction.current_proof = None;
        }
    }
    if operation.version() >= prior_version {
        record
            .current_state
            .apply_confirmed(operation.clone())
            .map_err(contact_error)?;
        let choice = match operation {
            ContactOperationEvidence::Request { .. } => {
                Some(coland_domain::identity::ContactRequestChoice::Open {
                    request_event_ref: operation.event().event_id.clone(),
                })
            }
            ContactOperationEvidence::Response {
                response_receipt, ..
            } => Some(coland_domain::identity::ContactRequestChoice::Normal {
                request_event_ref: response_receipt
                    .request_receipt
                    .core
                    .request_event_ref
                    .clone(),
            }),
            ContactOperationEvidence::Reject { reject_receipt, .. } => {
                Some(coland_domain::identity::ContactRequestChoice::Rejected {
                    request_event_ref: reject_receipt
                        .request_receipt
                        .core
                        .request_event_ref
                        .clone(),
                })
            }
            _ => None,
        };
        if let Some(slot) = record
            .request_slot_states
            .iter_mut()
            .find(|s| s.owner_id == holder.contact_actor_id())
        {
            slot.version = operation.version();
            slot.head_event_ref = operation.event().event_id.clone();
            slot.operation_digest = Some(original_digest.clone());
            if choice.is_some() {
                slot.request_choice = choice;
            }
        } else {
            record
                .request_slot_states
                .push(coland_services::identity::ContactRequestSlotState {
                    owner_id: holder.contact_actor_id(),
                    peer_id: peer.contact_actor_id(),
                    version: operation.version(),
                    head_event_ref: operation.event().event_id.clone(),
                    operation_digest: Some(original_digest.clone()),
                    request_choice: choice,
                });
        }
        match operation {
            ContactOperationEvidence::Request {
                signed_event,
                request_receipt,
            } => {
                if record.status == "accepted" {
                    return Err(contact_error(
                        "active Contact round cannot silently open another",
                    ));
                }
                let is_new = record
                    .request_receipts
                    .iter()
                    .all(|r| r.core.request_event_ref != signed_event.event_id);
                if is_new {
                    record.request_receipts.retain(|r| r.core.holder != *holder);
                    record.request_receipts.push(request_receipt.clone());
                }
                if record.request_receipts.len() > 2 {
                    return Err(contact_error("pending request bound exceeded"));
                }
                if record.requester_id == holder.contact_actor_id() {
                    record.request_event_ref = Some(signed_event.event_id.clone());
                } else {
                    record.response_event_ref = Some(signed_event.event_id.clone());
                }
                record.status = "pending".into();
                record.contact_round_id = None;
                record.contact_round_evidence = None;
                record.message = signed_event
                    .payload
                    .get("message")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned);
                record.pending_incoming_admitted = true;
            }
            ContactOperationEvidence::Response {
                signed_event,
                response_receipt,
            } => {
                let request = record
                    .current_state
                    .directions
                    .iter()
                    .find(|d| {
                        d.head_operation.event().event_id
                            == response_receipt.request_receipt.core.request_event_ref
                    })
                    .ok_or_else(|| {
                        crate::app_error!(TemporarilyUnavailable, "normal original request missing")
                    })?
                    .head_operation
                    .event()
                    .clone();
                let core = normal_round(&response_receipt.request_receipt)?;
                record
                    .current_state
                    .establish(
                        ContactRoundBasis {
                            contact_round_id: response_receipt.contact_round_id.clone(),
                            contact_round: core,
                            request_receipts: vec![response_receipt.request_receipt.clone()],
                            normal_response_receipt: Some(response_receipt.clone()),
                            glare_concurrency_attestations: None,
                        },
                        vec![request, signed_event.clone()],
                    )
                    .map_err(contact_error)?;
                record.status = "accepted".into();
                record.response_event_ref = Some(signed_event.event_id.clone());
            }
            ContactOperationEvidence::Reject { .. } => {
                record.status = "rejected".into();
                record.response_event_ref = Some(operation.event().event_id.clone());
            }
            _ => {}
        }
        if let Some(proof) = carried_current(delivery)
            && proof.head_event_ref == operation.event().event_id
        {
            replace_direction_proof(&mut record.current_state, proof.clone())?;
        }
    }
    if let Some(local) = record
        .current_state
        .directions
        .iter()
        .find(|d| d.head_operation.holder().delivery_station_id().as_str() == state.service_id())
        .map(|d| d.head_operation.holder().clone())
    {
        let proof = Box::pin(sign_direction_proof(state, &record.current_state, &local)).await?;
        if let PeerContactSubmitResponseBody::Event(result) = response {
            result.current_proof = Some(proof.clone());
        }
        replace_direction_proof(&mut record.current_state, proof)?;
    }
    sync_contact_summary(&mut record);
    advance_contact_revision(&mut record, expected);
    if !state
        .contacts()
        .save_contact_with_result(
            expected,
            record,
            frozen_control_record(delivery, holder, response)?,
        )
        .await
        .map_err(|e| AppError::internal(e.to_string()))?
    {
        return Err(crate::app_error!(
            TemporarilyUnavailable,
            "Contact receiving cut changed; retry exact carrier"
        ));
    }
    Ok(())
}
fn normal_round(receipt: &RequestAcceptanceReceipt) -> Result<ContactRound, AppError> {
    let mut pair = [
        receipt.core.holder.contact_actor_id(),
        receipt.core.peer.contact_actor_id(),
    ];
    if canonical::canonical_json_bytes(&pair[0]).map_err(contact_error)?
        > canonical::canonical_json_bytes(&pair[1]).map_err(contact_error)?
    {
        pair.swap(0, 1);
    }
    Ok(ContactRound::Normal {
        sorted_pair_member_ids: pair,
        request_event_ref: receipt.core.request_event_ref.clone(),
        request_acceptance_receipt_digest: receipt
            .computed_receipt_digest()
            .map_err(contact_error)?,
    })
}
#[salvo::oapi::endpoint(operation_id = "ak.peer.contacts.command.submit", tags("identity"))]
#[tracing::instrument(skip_all, fields(op = arkret_wire::ServiceOperationId::PEER_CONTACTS_COMMAND_SUBMIT_V1))]
async fn peer_contacts_submit(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<PeerContactSubmitResponseBody> {
    Box::pin(peer_contacts_submit_inner(depot, req)).await
}

// Keep unrelated carrier branches out of the peer authentication poll frame.
async fn peer_contacts_submit_inner(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<PeerContactSubmitResponseBody> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    super::super::events::peer::validate_peer_request(state, req, true).await?;
    let source_id = req
        .headers()
        .get(HEADER_SOURCE_SERVICE_ID)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| contact_error("source-service-id required"))?
        .to_owned();
    let bytes = req
        .payload()
        .await
        .map_err(|_| AppError::json_invalid("invalid Contact carrier"))?;
    if bytes.len() > CONTACT_CURRENT_MAX_BYTES {
        return Err(crate::app_error!(
            TooLarge,
            "Contact request exceeds budget"
        ));
    }
    let delivery: PeerContactSubmitRequestBody = serde_json::from_slice(bytes)
        .map_err(|_| AppError::json_invalid("invalid Contact carrier"))?;
    if canonical::canonical_json_bytes(&delivery)
        .map_err(contact_error)?
        .len()
        > CONTACT_CURRENT_MAX_BYTES
    {
        return Err(crate::app_error!(
            TooLarge,
            "Contact request exceeds canonical budget"
        ));
    }
    let (_, address) = peer_contact_delivery_address(&delivery);
    address.validate_shape().map_err(contact_error)?;
    if address.delivery_station_id().as_str() != state.service_id() {
        return Err(contact_error("Contact carrier recipient Station differs"));
    }
    match &delivery {
        PeerContactSubmitRequestBody::CurrentRefresh { .. } => {
            return json_ok(Box::pin(handle_current_refresh(state, &delivery, &source_id)).await?);
        }
        PeerContactSubmitRequestBody::GlareFinalize { .. } => {
            return json_ok(Box::pin(handle_glare_finalize(state, &delivery, &source_id)).await?);
        }
        _ => {}
    }
    let operation = operation_from_carrier(&delivery)?;
    if operation.holder().delivery_station_id().as_str() != source_id
        || operation.peer() != &address.recipient
        || operation.trust_domain_id() != &state.config().trust_domain
    {
        return Err(contact_error(
            "Contact carrier source/direction/domain mismatch",
        ));
    }
    if let Some(result) = Box::pin(read_exact_control(state, &delivery, operation.holder())).await?
    {
        return json_ok(result);
    }
    Box::pin(verify_original_contact_operation(state, &operation)).await?;
    if !matches!(operation, ContactOperationEvidence::Request { .. }) {
        Box::pin(persist_authenticated_observation(state, &operation)).await?;
    }
    if matches!(operation, ContactOperationEvidence::Tombstone { .. }) {
        Box::pin(persist_verified_round_closure(state, &operation)).await?;
    }

    if let PeerContactSubmitRequestBody::Request {
        introduction_evidence,
        signed_event,
        ..
    } = &delivery
    {
        validate_contact_introduction_evidence_digest(
            &serde_json::to_value(&signed_event.payload).map_err(contact_error)?,
            introduction_evidence,
        )?;
    }
    if let Some(proof) = carried_current(&delivery) {
        if let Some(closure) = &proof.closed_round {
            let close = closure.operation.operation();
            if close.trust_domain_id() != operation.trust_domain_id()
                || !((close.holder() == operation.holder() && close.peer() == operation.peer())
                    || (close.holder() == operation.peer() && close.peer() == operation.holder()))
            {
                return Err(contact_error(
                    "carried closure changes exact operation pair/domain",
                ));
            }
            Box::pin(verify_original_contact_operation(state, &close)).await?;
            Box::pin(persist_verified_round_closure(state, &close)).await?;
        }

        Box::pin(verify_current_proof(state, proof)).await?;
        if proof.holder != *operation.holder()
            || proof.peer != *operation.peer()
            || proof.trust_domain_id != *operation.trust_domain_id()
            || proof.version < operation.version()
            || (proof.version == operation.version()
                && proof.head_event_ref != operation.event().event_id)
        {
            return Err(contact_error(
                "Contact current proof differs from original operation",
            ));
        }
    }
    // First-contact policy is private. A hidden decision returns the same
    // opaque deferred receipt without installing a mirrored authorizing fact.
    if matches!(operation, ContactOperationEvidence::Request { .. }) {
        let prior = state
            .contacts()
            .contact_any(
                &operation.holder().contact_actor_id(),
                &operation.peer().contact_actor_id(),
            )
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;
        let admitted = if prior
            .as_ref()
            .and_then(|r| r.current_state.initial_identity.as_ref())
            .is_some()
        {
            true
        } else {
            let target = match operation.peer() {
                ContactPeer::Human { account_id } => account_id,
                ContactPeer::Agent {
                    controller_account_id,
                    ..
                } => controller_account_id,
            };
            let exists = state
                .identities()
                .account(target)
                .await
                .map_err(|e| AppError::internal(e.to_string()))?
                .is_some();
            if exists {
                crate::routing::invites::admit_quarantine_new_source(
                    state,
                    target,
                    operation
                        .holder()
                        .contact_actor_id()
                        .signing_principal_id()
                        .as_str(),
                    now(),
                )
                .await?
            } else {
                false
            }
        };
        if !admitted {
            let mirror = sign_contact_mirror_receipt(
                state,
                &delivery,
                operation.event(),
                PeerContactAdmissionAttemptOutcome::Deferred,
            )?;
            let result = PeerContactSubmitResponseBody::Event(PeerContactEventSubmitResponseBody {
                operation_kind: ContactOperationKind::Request,
                status: PeerContactAdmissionAttemptOutcome::Deferred,
                mirror_receipt: mirror,
                current_proof: None,
                retry_after_ms: Some(30_000),
            });
            state
                .jobs()
                .store_idempotency_record(frozen_control_record(
                    &delivery,
                    operation.holder(),
                    &result,
                )?)
                .await
                .map_err(|e| AppError::internal(e.to_string()))?;
            return json_ok(
                Box::pin(read_exact_control(state, &delivery, operation.holder()))
                    .await?
                    .ok_or_else(|| AppError::internal("opaque Contact receipt not durable"))?,
            );
        }
    }
    if matches!(operation, ContactOperationEvidence::Request { .. }) {
        Box::pin(persist_authenticated_observation(state, &operation)).await?;
    }
    let operation_kind = match &operation {
        ContactOperationEvidence::Request { .. } => ContactOperationKind::Request,
        ContactOperationEvidence::Response { .. } => ContactOperationKind::Response,
        ContactOperationEvidence::Reject { .. } => ContactOperationKind::Reject,
        ContactOperationEvidence::ScopeUpdate { .. } => ContactOperationKind::ScopeUpdate,
        ContactOperationEvidence::Tombstone { .. } => ContactOperationKind::Tombstone,
    };
    let mut response = PeerContactSubmitResponseBody::Event(PeerContactEventSubmitResponseBody {
        operation_kind,
        status: PeerContactAdmissionAttemptOutcome::Accepted,
        mirror_receipt: sign_contact_mirror_receipt(
            state,
            &delivery,
            operation.event(),
            PeerContactAdmissionAttemptOutcome::Accepted,
        )?,
        current_proof: None,
        retry_after_ms: None,
    });
    Box::pin(apply_delivered_operation(
        state,
        &delivery,
        &operation,
        &mut response,
    ))
    .await?;
    if matches!(operation, ContactOperationEvidence::Request { .. }) {
        if let PeerContactSubmitResponseBody::Event(result) = &response {
            Box::pin(persist_request_mirror_receipt(
                state,
                &operation.holder().contact_actor_id(),
                &operation.peer().contact_actor_id(),
                &result.mirror_receipt,
            ))
            .await?;
        }
        Box::pin(enqueue_glare_finalize_if_ready(
            state,
            &operation.peer().contact_actor_id(),
            &operation.holder().contact_actor_id(),
        ))
        .await?;
    }
    // Recovery of the opposite current is a separate bounded read. The
    // transport acknowledgement never fabricates a local holder operation.
    json_ok(response)
}
pub(crate) async fn accept_outbound_contact_event_outcome(
    state: &AppState,
    request: &PeerContactSubmitRequestBody,
    outcome: &PeerContactEventSubmitResponseBody,
    peer_id: &str,
) -> Result<(), AppError> {
    let operation = operation_from_carrier(request)?;
    if outcome.mirror_receipt.request_digest != contact_control_request_digest(request)?
        || outcome.mirror_receipt.signed_event_ref != operation.event().event_id
        || outcome.status != outcome.mirror_receipt.outcome
    {
        return Err(contact_error(
            "Contact event acknowledgement changes exact request or Event",
        ));
    }
    cache_contact_assertion_signatures(state, vec![&outcome.mirror_receipt.signature]).await?;
    if outcome.status == PeerContactAdmissionAttemptOutcome::Deferred {
        verify_contact_evidence_signature(
            state,
            peer_id,
            &outcome.mirror_receipt.signature,
            &outcome
                .mirror_receipt
                .canonical_signing_bytes()
                .map_err(contact_error)?,
            "opaque Contact mirror",
        )?;
        let mut retry = request.clone();
        let key = IdempotencyKey::new(format!(
            "contact-event-retry:{}",
            contact_control_request_digest(request)?
        ))
        .map_err(contact_error)?;
        match &mut retry {
            PeerContactSubmitRequestBody::Request {
                idempotency_key, ..
            }
            | PeerContactSubmitRequestBody::Response {
                idempotency_key, ..
            }
            | PeerContactSubmitRequestBody::Reject {
                idempotency_key, ..
            }
            | PeerContactSubmitRequestBody::ScopeUpdate {
                idempotency_key, ..
            }
            | PeerContactSubmitRequestBody::Tombstone {
                idempotency_key, ..
            } => *idempotency_key = key,
            _ => return Err(contact_error("not an Event carrier")),
        }
        enqueue_peer_contact_carrier(state, peer_id, &retry).await?;
        return Ok(());
    }
    validate_mirror_receipt_cryptography(
        state,
        &outcome.mirror_receipt,
        peer_id,
        "outbound Event mirror",
    )?;
    let holder = operation.holder();
    let peer = operation.peer();
    if let Some(proof) = &outcome.current_proof {
        Box::pin(verify_current_proof(state, proof)).await?;
        if proof.holder != *peer
            || proof.peer != *holder
            || proof.issuer_id.as_str() != peer_id
            || proof.trust_domain_id != *operation.trust_domain_id()
        {
            return Err(contact_error("acknowledged current direction mismatch"));
        }
        let mut record = state
            .contacts()
            .contact_any(&holder.contact_actor_id(), &peer.contact_actor_id())
            .await
            .map_err(|e| AppError::internal(e.to_string()))?
            .ok_or_else(|| contact_error("outbound Contact original missing"))?;
        let expected = record.updated_at;
        if let Some(closure) = &proof.closed_round {
            Box::pin(verify_original_contact_operation(
                state,
                &closure.operation.operation(),
            ))
            .await?;
            record
                .current_state
                .close_round((**closure).clone())
                .map_err(contact_error)?;
        }
        if record
            .current_state
            .direction(peer)
            .is_some_and(|d| d.head_operation.event().event_id == proof.head_event_ref)
        {
            replace_direction_proof(&mut record.current_state, proof.clone())?;
            sync_contact_summary(&mut record);
            advance_contact_revision(&mut record, expected);
            Box::pin(save_contact_cas(state.contacts(), expected, record)).await?;
        } else {
            Box::pin(queue_current_refresh(
                state,
                holder,
                peer,
                &record.current_state,
                vec![],
            ))
            .await?;
        }
    } else if !matches!(
        operation,
        ContactOperationEvidence::Request { .. } | ContactOperationEvidence::Reject { .. }
    ) {
        let record = state
            .contacts()
            .contact_any(&holder.contact_actor_id(), &peer.contact_actor_id())
            .await
            .map_err(|e| AppError::internal(e.to_string()))?
            .ok_or_else(|| contact_error("Contact current unavailable"))?;
        Box::pin(queue_current_refresh(
            state,
            holder,
            peer,
            &record.current_state,
            vec![],
        ))
        .await?;
    }
    if matches!(operation, ContactOperationEvidence::Request { .. }) {
        Box::pin(persist_request_mirror_receipt(
            state,
            &holder.contact_actor_id(),
            &peer.contact_actor_id(),
            &outcome.mirror_receipt,
        ))
        .await?;
        Box::pin(enqueue_glare_finalize_if_ready(
            state,
            &holder.contact_actor_id(),
            &peer.contact_actor_id(),
        ))
        .await?;
    }
    Ok(())
}
pub(crate) async fn refresh_local_contact_direction(
    state: &AppState,
    current: &ContactPrivateState,
    holder: &ContactPeer,
) -> Result<ContactCurrentProof, AppError> {
    Box::pin(sign_direction_proof(state, current, holder)).await
}
pub(crate) async fn request_remote_contact_current(
    state: &AppState,
    requester: &ContactPeer,
    holder: &ContactPeer,
    current: &ContactPrivateState,
) -> Result<(), AppError> {
    Box::pin(queue_current_refresh(
        state,
        requester,
        holder,
        current,
        vec![],
    ))
    .await
}
async fn persist_verified_round_closure(
    state: &AppState,
    operation: &ContactOperationEvidence,
) -> Result<(), AppError> {
    let ContactOperationEvidence::Tombstone {
        signed_event,
        lineage,
    } = operation
    else {
        return Err(contact_error("not original closure"));
    };
    let round = lineage
        .contact_round_id
        .clone()
        .ok_or_else(|| contact_error("tombstone round absent"))?;
    let existing = state
        .contacts()
        .contact_any(
            &operation.holder().contact_actor_id(),
            &operation.peer().contact_actor_id(),
        )
        .await
        .map_err(|e| AppError::internal(e.to_string()))?;
    let expected = existing.as_ref().map(|r| r.updated_at);
    let mut record =
        existing.unwrap_or_else(|| empty_contact(operation.holder(), operation.peer()));
    record
        .current_state
        .close_round(ContactRoundClosure {
            contact_round_id: round.clone(),
            operation: ContactTombstoneEvidence {
                kind: ContactTombstoneEvidenceKind::Tombstone,
                signed_event: signed_event.clone(),
                lineage: lineage.clone(),
            },
        })
        .map_err(contact_error)?;
    if record.contact_round_id.as_ref() == Some(&round) {
        record.status = "tombstoned".into();
        record.tombstone_event_ref = Some(signed_event.event_id.clone());
    }
    sync_contact_summary(&mut record);
    if let Some(expected) = expected {
        advance_contact_revision(&mut record, expected);
        Box::pin(save_contact_cas(state.contacts(), expected, record)).await?;
    } else {
        state
            .contacts()
            .save_contact(record)
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;
    }
    Ok(())
}

async fn persist_authenticated_observation(
    state: &AppState,
    operation: &ContactOperationEvidence,
) -> Result<(), AppError> {
    let prior = state
        .contacts()
        .contact_any(
            &operation.holder().contact_actor_id(),
            &operation.peer().contact_actor_id(),
        )
        .await
        .map_err(|e| AppError::internal(e.to_string()))?;
    let expected = prior.as_ref().map(|r| r.updated_at);
    let mut record = prior.unwrap_or_else(|| empty_contact(operation.holder(), operation.peer()));
    let digest = Hash::new(canonical::canonical_sha256(operation).map_err(contact_error)?)
        .map_err(contact_error)?;
    if let Some(slot) = record
        .request_slot_states
        .iter_mut()
        .find(|s| s.owner_id == operation.holder().contact_actor_id())
    {
        if slot.peer_id != operation.peer().contact_actor_id()
            || (slot.version == operation.version()
                && (slot.head_event_ref != operation.event().event_id
                    || slot
                        .operation_digest
                        .as_ref()
                        .is_some_and(|known| known != &digest)))
        {
            return Err(contact_error(
                "authenticated observation conflicts with immutable directional cursor",
            ));
        }
        if slot.version <= operation.version() {
            slot.version = operation.version();
            slot.head_event_ref = operation.event().event_id.clone();
            slot.operation_digest = Some(digest);
        }
    } else {
        record
            .request_slot_states
            .push(coland_services::identity::ContactRequestSlotState {
                owner_id: operation.holder().contact_actor_id(),
                peer_id: operation.peer().contact_actor_id(),
                version: operation.version(),
                head_event_ref: operation.event().event_id.clone(),
                operation_digest: Some(digest),
                request_choice: None,
            });
    }
    record
        .current_state
        .observe_authenticated_operation(operation)
        .map_err(contact_error)?;
    sync_contact_summary(&mut record);
    if let Some(expected) = expected {
        advance_contact_revision(&mut record, expected);
        Box::pin(save_contact_cas(state.contacts(), expected, record)).await?;
    } else {
        state
            .contacts()
            .save_contact(record)
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;
    }
    Ok(())
}
