mod completion;
use arkret_models_collaboration::contact_operations::*;
use arkret_models_collaboration::events_payloads::contact::{
    ContactAcceptedPayload, ContactRejectedPayload, ContactRequestedPayload,
    ContactTombstonedPayload,
};
use arkret_models_collaboration::governance::peer_contact::{
    ContactIntroductionEvidence, PeerContactAddress,
};
use arkret_models_collaboration::prepared_event_draft::PreparedEventDraft;
use arkret_models_identity::ServiceResolutionCarrier;
use arkret_wire::{
    AuthoredEvent, Base64UrlString, DidUrl, Event, IdempotencyKey, ProtocolOperationId,
    ProtocolSignature, ReservationHandle,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
pub(crate) use completion::materialize_contact_completions;
use serde::de::DeserializeOwned;

use super::*;

const CONTACT_RESERVATION_TTL_MINUTES: i64 = 10;
const CONTACT_OUTCOME_TTL_HOURS: i64 = 24;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "result_kind", rename_all = "snake_case", deny_unknown_fields)]
enum ContactReservationBranch {
    Request {
        peer: ContactPeer,
        granted_to_peer_scopes: Vec<ContactScope>,
        initial_contact_round_id: Option<Hash>,
        introduction_evidence: Box<ContactIntroductionEvidence>,
    },
    Response {
        request_receipt: RequestAcceptanceReceipt,
        peer: ContactPeer,
        contact_round_id: Hash,
        granted_to_peer_scopes: Vec<ContactScope>,
    },
    Reject {
        request_receipt: RequestAcceptanceReceipt,
        peer: ContactPeer,
    },
    ScopeUpdate {
        peer: ContactPeer,
        contact_round_id: Hash,
        version: u64,
        predecessor_event_ref: EventId,
        granted_to_peer_scopes: Vec<ContactScope>,
    },
    Tombstone {
        peer: ContactPeer,
        contact_round_id: Hash,
        version: u64,
        predecessor_event_ref: EventId,
        block_peer: bool,
    },
}

impl ContactReservationBranch {
    fn peer(&self) -> &ContactPeer {
        match self {
            Self::Request { peer, .. }
            | Self::Response { peer, .. }
            | Self::Reject { peer, .. }
            | Self::ScopeUpdate { peer, .. }
            | Self::Tombstone { peer, .. } => peer,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContactReservation {
    operation_id: ProtocolOperationId,
    idempotency_key: IdempotencyKey,
    reservation_handle: ReservationHandle,
    holder: ContactPeer,
    branch: ContactReservationBranch,
    event_draft: PreparedEventDraft,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    expires_at: chrono::DateTime<chrono::Utc>,
}

fn contact_reservation_key(handle: &ReservationHandle) -> String {
    format!("contact-reservation:{}", handle.as_str())
}

fn contact_phase_idempotency_key(phase: &str, key: &IdempotencyKey) -> String {
    format!("contact-{phase}:{}", key.as_str())
}

fn contact_hash<T: Serialize>(label: &str, value: &T) -> Result<Hash, AppError> {
    let canonical = arkret_canonical::canonical_json_bytes(value)
        .map_err(|error| AppError::internal(format!("Contact digest canonicalize: {error}")))?;
    let mut transcript = Vec::with_capacity(label.len() + 1 + canonical.len());
    transcript.extend_from_slice(label.as_bytes());
    transcript.push(b'\n');
    transcript.extend_from_slice(&canonical);
    Hash::new(arkret_canonical::sha256_digest(&transcript))
        .map_err(|error| AppError::internal(format!("Contact digest invalid: {error}")))
}

pub(crate) fn canonical_contact_digest<T: Serialize>(value: &T) -> Result<Hash, AppError> {
    Hash::new(
        arkret_canonical::canonical_sha256(value)
            .map_err(|error| AppError::internal(format!("Contact digest canonicalize: {error}")))?,
    )
    .map_err(|error| AppError::internal(format!("Contact digest invalid: {error}")))
}

pub(crate) fn verify_contact_service_signature_bytes(
    state: &AppState,
    expected_service_id: &str,
    signature: &ProtocolSignature,
    signature_bytes: &[u8],
    evidence_field: &str,
) -> Result<(), AppError> {
    verify_contact_service_signature_bytes_at(
        state,
        expected_service_id,
        signature,
        signature.created_at,
        signature_bytes,
        evidence_field,
    )
}
pub(crate) fn verify_contact_service_signature_bytes_at(
    state: &AppState,
    expected_service_id: &str,
    signature: &ProtocolSignature,
    authority_at: chrono::DateTime<chrono::Utc>,
    signature_bytes: &[u8],
    evidence_field: &str,
) -> Result<(), AppError> {
    let (controller, fragment) = signature
        .verification_method
        .as_str()
        .rsplit_once('#')
        .ok_or_else(|| {
            crate::app_error!(
                FailedPrecondition,
                format!("{evidence_field}.signature.verification_method is not a DID URL"),
            )
        })?;
    let controller = arkret_wire::Did::new(controller.to_owned()).map_err(|_| {
        crate::app_error!(
            FailedPrecondition,
            format!("{evidence_field}.signature.verification_method controller is invalid"),
        )
    })?;
    let controller_core = arkret_wire::project_did_to_core_id(&controller).map_err(|_| {
        crate::app_error!(
            FailedPrecondition,
            format!("{evidence_field}.signature.verification_method controller is invalid"),
        )
    })?;
    // Every Contact source assertion names the issuer Station as controller.
    // Callers must also establish this method as a historical assertionMethod
    // at the evidence-specific authority cut before accepting this key.
    if controller_core.as_str() != expected_service_id || fragment.is_empty() {
        return Err(crate::app_error!(
            FailedPrecondition,
            format!(
                "{evidence_field}.signature.verification_method is not the issuer's trusted service method"
            ),
        ));
    }
    let verifying_key = state
        .historical_contact_assertion_key(signature.verification_method.as_str(), authority_at)
        .or_else(|| {
            (expected_service_id == state.service_id()).then(|| state.notary_verifying_key())
        })
        .ok_or_else(|| {
            crate::app_error!(
                FailedPrecondition,
                format!("{evidence_field}.signature historical verification key is unavailable"),
            )
        })?;
    // ProtocolSignature.jws is the SDK compact detached JWS over the exact
    // canonical transcript; a bare base64url signature is not accepted.
    arkret_signatures::Ed25519DetachedJwsVerifier::new()
        .verify_detached_jws(
            signature.jws.as_str(),
            signature_bytes,
            &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                bytes: verifying_key.to_bytes().to_vec(),
            },
        )
        .map_err(|_| {
            crate::app_error!(
                FailedPrecondition,
                format!("{evidence_field}.signature verification failed"),
            )
        })
}

/// Produce the compact detached JWS carried by every Contact receipt,
/// lineage, current proof and peer-service transcript `ProtocolSignature`.
pub(crate) fn contact_detached_jws(
    key: &ed25519_dalek::SigningKey,
    signing_bytes: &[u8],
) -> Result<String, AppError> {
    arkret_signatures::sign_ed25519_detached_jws(key, signing_bytes)
        .map_err(|error| AppError::internal(format!("Contact transcript signing failed: {error}")))
}

pub(crate) fn validate_request_receipt_cryptography(
    state: &AppState,
    receipt: &RequestAcceptanceReceipt,
    evidence_field: &str,
) -> Result<(), AppError> {
    receipt.core.validate().map_err(|error| {
        crate::app_error!(
            FailedPrecondition,
            format!("{evidence_field}.core is invalid: {error}"),
        )
    })?;
    let recomputed = contact_hash(
        arkret_wire::DomainSeparationId::CONTACT_REQUEST_ACCEPTANCE_CORE_V1,
        &receipt.core,
    )?;
    if recomputed != receipt.receipt_digest {
        return Err(crate::app_error!(
            FailedPrecondition,
            format!("{evidence_field}.receipt_digest does not match its canonical core"),
        ));
    }
    verify_contact_service_signature_bytes_at(
        state,
        receipt.core.issuer_id.as_str(),
        &receipt.signature,
        receipt.core.accepted_at,
        &receipt
            .canonical_signing_bytes()
            .map_err(|e| AppError::internal(e.to_string()))?,
        evidence_field,
    )
}

/// Recheck durable Contact evidence when a cold reader uses it for a list,
/// bounded current or Direct Conversation authority. Ingress validation
/// does not populate the in-memory historical-key cache after a restart.
pub(crate) async fn verify_stored_contact_evidence_for_read(
    state: &AppState,
    record: &ContactRecord,
) -> Result<(), AppError> {
    for receipt in &record.request_receipts {
        verify_stored_request_receipt(state, record, receipt).await?;
    }
    if let Some(bundle) = &record.contact_round_evidence {
        verify_stored_contact_round_with_root(state, record, bundle).await?;
    }
    Ok(())
}

async fn verify_stored_contact_round_with_root(
    state: &AppState,
    record: &ContactRecord,
    bundle: &ContactRoundEvidenceBundle,
) -> Result<(), AppError> {
    bundle
        .validate_shape()
        .map_err(|e| AppError::param_invalid(e.to_string()))?;
    verify_stored_contact_round(state, record, bundle).await
}

async fn verify_stored_request_receipt(
    state: &AppState,
    record: &ContactRecord,
    receipt: &RequestAcceptanceReceipt,
) -> Result<(), AppError> {
    let holder = receipt.core.holder.contact_actor_id();
    let peer = receipt.core.peer.contact_actor_id();
    if !((holder == record.requester_id && peer == record.target_id)
        || (holder == record.target_id && peer == record.requester_id))
        || &receipt.core.issuer_id != receipt.core.holder.delivery_station_id()
    {
        return Err(crate::app_error!(
            FailedPrecondition,
            "stored Contact request receipt has wrong participant or source Station",
        ));
    }
    crate::routing::identity::contact_federation::cache_assertion_at(
        state,
        &receipt.signature,
        receipt.core.accepted_at,
    )
    .await?;
    validate_request_receipt_cryptography(state, receipt, "stored_contact.request_receipt")
}

async fn verify_stored_contact_round(
    state: &AppState,
    record: &ContactRecord,
    bundle: &ContactRoundEvidenceBundle,
) -> Result<(), AppError> {
    let pair = [record.requester_id.clone(), record.target_id.clone()];
    if bundle.current_proofs.iter().any(|p| {
        !pair.contains(&p.holder.contact_actor_id()) || !pair.contains(&p.peer.contact_actor_id())
    }) {
        return Err(AppError::param_invalid(
            "stored Contact evidence changes complete pair",
        ));
    }
    crate::routing::identity::contact_federation::verify_contact_bundle(state, bundle).await
}

async fn validate_request_acceptance_receipt(
    state: &AppState,
    record: &ContactRecord,
    responder: &ContactPeer,
    receipt: &RequestAcceptanceReceipt,
) -> Result<(), AppError> {
    receipt.core.validate().map_err(|error| {
        AppError::param_invalid(format!("invalid Contact request receipt: {error}"))
    })?;
    if &receipt.core.peer != responder {
        return Err(AppError::capability_denied(
            "Contact request receipt does not name the responder",
        ));
    }
    if record.status != "pending"
        || !record.pending_incoming_admitted
        || record.requester_id != receipt.core.holder.contact_actor_id()
        || record.target_id != receipt.core.peer.contact_actor_id()
        || record.request_event_ref.as_ref() != Some(&receipt.core.request_event_ref)
    {
        return Err(AppError::conflict(
            "Contact request receipt differs from the durable pending slot",
        ));
    }

    crate::routing::identity::contact_federation::cache_assertion_at(
        state,
        &receipt.signature,
        receipt.core.accepted_at,
    )
    .await?;
    validate_request_receipt_cryptography(state, receipt, "request_receipt")?;

    // The exact request holder determines source authority. The pair row's
    // peer route is a delivery hint and can change orientation during glare.
    let expected_issuer = receipt.core.holder.delivery_station_id().as_str();
    if receipt.core.issuer_id.as_str() != expected_issuer {
        return Err(crate::app_error!(
            FailedPrecondition,
            "request_receipt.core.issuer does not match the durable request source service",
        ));
    }
    let (request_event, digest_suite) = if expected_issuer == state.service_id() {
        let stored = state
        .event_queries()
        .accepted_event(receipt.core.request_event_ref.as_str())
        .await
        .map_err(|error| AppError::internal(format!("Contact request Event lookup: {error}")))?
        .ok_or_else(|| {
            crate::app_error!(FailedPrecondition,
                "request_receipt.core.request_event_ref cannot be verified: the durable accepted source Event is unavailable",
            )
        })?;
        let event = serde_json::from_value::<Event>(stored.envelope).map_err(|error| {
            AppError::internal(format!("stored Contact request Event: {error}"))
        })?;
        (event, stored.digest_suite)
    } else {
        // The bounded private direction retains the exact peer original.
        // Revalidate both holder and source after cold recovery instead of
        // requiring a separate mirror cache populated by an obsolete path.
        let original = &record
            .current_state
            .direction(&receipt.core.holder)
            .ok_or_else(|| {
                crate::app_error!(FailedPrecondition, "Contact request original unavailable")
            })?
            .head_operation;
        let ContactOperationEvidence::Request {
            signed_event,
            request_receipt,
        } = original
        else {
            return Err(crate::app_error!(
                FailedPrecondition,
                "Contact pending head is not its original request"
            ));
        };
        if request_receipt != receipt || signed_event.event_id != receipt.core.request_event_ref {
            return Err(crate::app_error!(
                FailedPrecondition,
                "Contact pending original differs from source receipt"
            ));
        }
        Box::pin(
            crate::routing::identity::contact_federation::verify_original_contact_operation(
                state, original,
            ),
        )
        .await?;
        let event = signed_event.clone();
        let suite = receipt
            .core
            .request_digest()
            .digest_suite()
            .map_err(|error| {
                AppError::internal(format!("Contact request mirror digest suite: {error}"))
            })?;
        (event, suite)
    };
    let request_digest = Hash::new(
        request_event
            .event_digest_with_digest_suite(digest_suite)
            .map_err(|error| {
                AppError::internal(format!("stored Contact request Event digest: {error}"))
            })?,
    )
    .map_err(|error| AppError::internal(format!("stored Contact request digest: {error}")))?;
    let requested_payload = serde_json::from_value::<ContactRequestedPayload>(
        serde_json::to_value(&request_event.payload)
            .map_err(|error| AppError::internal(format!("Contact request payload: {error}")))?,
    )
    .map_err(|error| AppError::internal(format!("stored Contact request payload: {error}")))?;
    let expected_checkpoint = contact_hash(
        arkret_wire::DomainSeparationId::CONTACT_REQUEST_SOURCE_CHECKPOINT_V1,
        &json!({
            "event_ref": request_event.event_id,
            "event_digest": request_digest,
        }),
    )?;
    if request_event.kind != arkret_wire::EventKind::ContactRequested
        || request_event.event_id != receipt.core.request_event_ref
        || request_event.actor_id != receipt.core.holder.contact_actor_id()
        || requested_payload.peer != receipt.core.peer
        || request_digest != receipt.core.request_digest()
        || expected_checkpoint != receipt.core.source_checkpoint
        || receipt.core.accepted_at < request_event.created_at
    {
        return Err(crate::app_error!(
            FailedPrecondition,
            "request_receipt.core coordinates do not match the durable accepted Contact request",
        ));
    }
    Ok(())
}

async fn holder_peer(state: &AppState, session: &SessionRecord) -> Result<ContactPeer, AppError> {
    let holder_principal_id = arkret_identifiers::DidCoreId::new(session.actor.clone())
        .map_err(|error| AppError::internal(format!("holder DID invalid: {error}")))?;
    if let Some(agent) = state
        .agent_pairings()
        .agent(holder_principal_id.as_str())
        .await
        .map_err(|error| AppError::internal(format!("holder Agent lookup: {error}")))?
    {
        if session.agent_session().is_none() {
            return Err(AppError::unauthenticated(
                "Contact Agent holder requires an Agent runtime endpoint",
            ));
        }
        let controller_account_id =
            crate::routing::identity::agent_pcr::agent_controller_account(state, &agent).await?;
        let station_id = arkret_wire::DidCoreId::new(session.audience.clone())
            .map_err(|error| AppError::internal(format!("session audience invalid: {error}")))?;
        if station_id != controller_account_id.station_id {
            return Err(AppError::unauthenticated(
                "Contact Agent holder belongs to another Station",
            ));
        }
        crate::routing::identity::agent_pcr::validate_agent_controller_binding(
            state,
            &agent,
            now(),
        )
        .await?;
        return Ok(ContactPeer::Agent {
            actor_id: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                holder_principal_id,
                station_id,
            )),
            controller_account_id,
        });
    }
    if session.agent_session().is_some() {
        return Err(AppError::unauthenticated(
            "Contact Agent holder has no accepted identity",
        ));
    }
    let account_pk = session
        .account_pk
        .ok_or_else(|| AppError::unauthenticated("session has no account binding"))?;
    let account = state
        .identities()
        .account_by_id(account_pk)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::unauthenticated("session account no longer exists"))?;
    Ok(ContactPeer::Human {
        account_id: account.account_id,
    })
}

fn validate_distinct_peer(holder: &ContactPeer, peer: &ContactPeer) -> Result<(), AppError> {
    if holder.contact_actor_id() == peer.contact_actor_id() {
        return Err(AppError::param_invalid(
            "Contact peer must differ from holder",
        ));
    }
    Ok(())
}

fn contact_scope_strings(scopes: &[ContactScope]) -> Vec<String> {
    scopes
        .iter()
        .map(|scope| {
            serde_json::to_value(scope)
                .ok()
                .and_then(|value| value.as_str().map(ToOwned::to_owned))
                .expect("ContactScope serializes as a string")
        })
        .collect()
}

fn new_unsigned_contact_event<K: arkret_event_draft::EventSpec>(
    holder: &ContactPeer,
    realm_id: RealmId,
    created_at: chrono::DateTime<chrono::Utc>,
    payload: K::Payload,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<AuthoredEvent, AppError> {
    arkret_event_draft::TypedEventDraft::<K>::new(
        arkret_wire::ScopeRef::Realm { realm_id },
        holder.contact_actor_id(),
        payload,
    )
    .and_then(|draft| draft.author_with_digest_suite(created_at, digest_suite))
    .map_err(|error| AppError::internal(format!("Contact typed Event draft invalid: {error}")))
}

fn contact_event_draft(
    event: &Event,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<PreparedEventDraft, AppError> {
    let digest_payload = event
        .digest_payload()
        .map_err(|error| AppError::internal(format!("Contact Event draft: {error}")))?;
    let unsigned_bytes = arkret_canonical::canonical_json_bytes(&digest_payload)
        .map_err(|error| AppError::internal(format!("Contact Event draft bytes: {error}")))?;
    Ok(PreparedEventDraft {
        unsigned_event_bytes: Base64UrlString::new(URL_SAFE_NO_PAD.encode(unsigned_bytes))
            .map_err(|error| AppError::internal(format!("Contact draft encode: {error}")))?,
        event_digest: Hash::new(
            event
                .event_digest_with_digest_suite(digest_suite)
                .map_err(|error| AppError::internal(format!("Contact Event digest: {error}")))?,
        )
        .map_err(|error| AppError::internal(format!("Contact Event digest invalid: {error}")))?,
    })
}

fn prepared_outcome(reservation: &ContactReservation) -> ContactOperationOutcome {
    let fields = (
        reservation.operation_id.clone(),
        reservation.reservation_handle.clone(),
        reservation.expires_at,
        reservation.event_draft.clone(),
    );
    let outcome = match reservation.branch {
        ContactReservationBranch::Request { .. } => ContactPreparedOutcome::Request {
            operation_id: fields.0,
            reservation_handle: fields.1,
            expires_at: fields.2,
            event_draft: fields.3,
        },
        ContactReservationBranch::Response { .. } => ContactPreparedOutcome::Response {
            operation_id: fields.0,
            reservation_handle: fields.1,
            expires_at: fields.2,
            event_draft: fields.3,
        },
        ContactReservationBranch::Reject { .. } => ContactPreparedOutcome::Reject {
            operation_id: fields.0,
            reservation_handle: fields.1,
            expires_at: fields.2,
            event_draft: fields.3,
        },
        ContactReservationBranch::ScopeUpdate { .. } => ContactPreparedOutcome::ScopeUpdate {
            operation_id: fields.0,
            reservation_handle: fields.1,
            expires_at: fields.2,
            event_draft: fields.3,
        },
        ContactReservationBranch::Tombstone { .. } => ContactPreparedOutcome::Tombstone {
            operation_id: fields.0,
            reservation_handle: fields.1,
            expires_at: fields.2,
            event_draft: fields.3,
        },
    };
    ContactOperationOutcome::Prepared { outcome }
}

async fn store_prepare(
    state: &AppState,
    principal: &str,
    idempotency_key: &IdempotencyKey,
    request_hash: &str,
    reservation: &ContactReservation,
) -> Result<(), AppError> {
    let created_at = now();
    let principal_id = DidCoreId::new(principal.to_owned())
        .map_err(|error| AppError::internal(format!("Contact principal id invalid: {error}")))?;
    let outcome = prepared_outcome(reservation);
    for (key, body) in [
        (
            contact_phase_idempotency_key("prepare", idempotency_key),
            serde_json::to_value(&outcome)
                .map_err(|error| AppError::internal(format!("Contact outcome encode: {error}")))?,
        ),
        (
            contact_reservation_key(&reservation.reservation_handle),
            serde_json::to_value(reservation).map_err(|error| {
                AppError::internal(format!("Contact reservation encode: {error}"))
            })?,
        ),
    ] {
        state
            .jobs()
            .store_idempotency_record(coland_services::jobs::IdempotencyState {
                authenticated_actor: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                    principal_id.clone(),
                    state.service_core_id(),
                )),
                operation_id: "org.arkret.coland.contact.prepare.v1".to_owned(),
                idempotency_key: key,
                request_hash: request_hash.to_owned(),
                response_status: StatusCode::OK.as_u16().into(),
                response_body: body,
                created_at,
                expires_at: reservation.expires_at,
            })
            .await
            .map_err(|error| AppError::internal(format!("Contact reservation store: {error}")))?;
    }
    Ok(())
}

async fn replay<T: DeserializeOwned>(
    state: &AppState,
    principal: &str,
    operation_id: &str,
    key: &str,
    request_hash: &str,
) -> Result<Option<T>, AppError> {
    let principal_id = DidCoreId::new(principal.to_owned())
        .map_err(|error| AppError::internal(format!("Contact principal id invalid: {error}")))?;
    let Some(record) = state
        .jobs()
        .scoped_idempotency_record(
            &arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                principal_id,
                state.service_core_id(),
            )),
            operation_id,
            key,
        )
        .await
        .map_err(|error| AppError::internal(format!("Contact idempotency lookup: {error}")))?
    else {
        return Ok(None);
    };
    if record.request_hash != request_hash {
        return Err(AppError::conflict(
            "Contact idempotency key was used for different canonical bytes",
        ));
    }
    serde_json::from_value(record.response_body)
        .map(Some)
        .map_err(|error| AppError::internal(format!("stored Contact outcome: {error}")))
}

async fn persist_final(
    state: &AppState,
    principal: &str,
    operation_id: &str,
    key: &str,
    request_hash: &str,
    outcome: &ContactOperationOutcome,
) -> Result<(), AppError> {
    let created_at = now();
    let principal_id = DidCoreId::new(principal.to_owned())
        .map_err(|error| AppError::internal(format!("Contact principal id invalid: {error}")))?;
    state
        .jobs()
        .store_idempotency_record(coland_services::jobs::IdempotencyState {
            authenticated_actor: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                principal_id,
                state.service_core_id(),
            )),
            operation_id: operation_id.to_owned(),
            idempotency_key: key.to_owned(),
            request_hash: request_hash.to_owned(),
            response_status: StatusCode::OK.as_u16().into(),
            response_body: serde_json::to_value(outcome)
                .map_err(|error| AppError::internal(format!("Contact outcome encode: {error}")))?,
            created_at,
            expires_at: created_at + chrono::Duration::hours(CONTACT_OUTCOME_TTL_HOURS),
        })
        .await
        .map_err(|error| AppError::internal(format!("Contact outcome store: {error}")))
}

struct PrepareContext<K> {
    holder: ContactPeer,
    request_hash: String,
    kind: std::marker::PhantomData<K>,
}

/// Freeze the caller's canonical command identity before selecting mutable
/// server continuity material. An exact retry returns its original draft.
async fn prepare_context<K: arkret_event_draft::EventSpec, T: Serialize>(
    state: &AppState,
    session: &SessionRecord,
    request: &T,
    idempotency_key: &IdempotencyKey,
    peer: &ContactPeer,
) -> Result<(PrepareContext<K>, Option<ContactOperationOutcome>), AppError> {
    let holder = holder_peer(state, session).await?;
    validate_distinct_peer(&holder, peer)?;
    materialize_contact_completions(state).await?;
    if let Some(record) = state
        .contacts()
        .contact_any(&holder.contact_actor_id(), &peer.contact_actor_id())
        .await
        .map_err(|e| AppError::internal(e.to_string()))?
    {
        if record.current_state.initial_root_floor.is_some()
            && record.current_state.initial_identity.is_none()
        {
            return Err(crate::app_error!(
                TemporarilyUnavailable,
                "fixed first identity recovery required before new Contact intent"
            ));
        }
        if let Some(slot) = record
            .request_slot_states
            .iter()
            .find(|s| s.owner_id == holder.contact_actor_id())
            && record
                .current_state
                .direction(&holder)
                .is_none_or(|d| d.head_operation.event().event_id != slot.head_event_ref)
        {
            return Err(crate::app_error!(
                TemporarilyUnavailable,
                "previous Contact source confirmation is incomplete"
            ));
        }
    }
    let request_hash = arkret_canonical::canonical_sha256(&json!({
        "event_kind": K::KIND,
        "request": request,
    }))
    .map_err(|error| AppError::internal(format!("Contact prepare digest: {error}")))?;
    let outcome = replay::<ContactOperationOutcome>(
        state,
        &session.actor,
        "org.arkret.coland.contact.prepare.v1",
        &contact_phase_idempotency_key("prepare", idempotency_key),
        &request_hash,
    )
    .await?;
    Ok((
        PrepareContext {
            holder,
            request_hash,
            kind: std::marker::PhantomData,
        },
        outcome,
    ))
}

async fn prepare<K: arkret_event_draft::EventSpec>(
    state: &AppState,
    session: &SessionRecord,
    context: PrepareContext<K>,
    operation_id: ProtocolOperationId,
    idempotency_key: IdempotencyKey,
    branch: ContactReservationBranch,
    payload: K::Payload,
) -> JsonResult<ContactOperationOutcome> {
    let PrepareContext {
        holder,
        request_hash,
        ..
    } = context;
    validate_distinct_peer(&holder, branch.peer())?;
    // A fresh prepare must reject a stale cursor before persisting a reservation.
    // Exact idempotent replays retain their original outcome; commit also
    // rechecks the lineage to close the prepare/commit race.
    match &branch {
        ContactReservationBranch::ScopeUpdate {
            contact_round_id,
            version,
            predecessor_event_ref,
            ..
        }
        | ContactReservationBranch::Tombstone {
            contact_round_id,
            version,
            predecessor_event_ref,
            ..
        } => {
            let holder_actor = holder.contact_actor_id();
            let peer_actor = branch.peer().contact_actor_id();
            let record = contact_record_for_lineage(state, &holder_actor, &peer_actor)
                .await?
                .ok_or_else(|| {
                    AppError::conflict("Contact lineage is no longer current")
                        .with_wire_code("contact_lineage_conflict")
                })?;
            validate_lineage_head(
                state,
                &record,
                &holder_actor,
                contact_round_id,
                *version,
                predecessor_event_ref,
            )
            .await?;
        }
        _ => {}
    }
    // The authenticated device (or Agent allocation) selects one exact
    // `(principal_id, station_id)` pair and its local lifetime PCR
    // lineage. Never resolve account state from the principal core alone.
    let realm_id = contact_authority_realm(state, session, &holder).await?;
    let created_at = now();
    let digest_suite = state.projections().realm_digest_suite(realm_id.as_str());
    let event =
        new_unsigned_contact_event::<K>(&holder, realm_id, created_at, payload, digest_suite)?;
    let reservation = ContactReservation {
        operation_id,
        idempotency_key: idempotency_key.clone(),
        reservation_handle: ReservationHandle::new(crate::ids::generate("reservation"))
            .map_err(AppError::internal)?,
        holder,
        branch,
        event_draft: contact_event_draft(&event, digest_suite)?,
        expires_at: created_at + chrono::Duration::minutes(CONTACT_RESERVATION_TTL_MINUTES),
    };
    store_prepare(
        state,
        &session.actor,
        &idempotency_key,
        &request_hash,
        &reservation,
    )
    .await?;
    json_ok(prepared_outcome(&reservation))
}

fn device_authorization_matches_contact_account(
    authorize_actor: &str,
    account_id: &arkret_wire::AccountId,
) -> bool {
    arkret_wire::ActorId::account(account_id.clone())
        .canonical_key()
        .is_ok_and(|expected| authorize_actor == expected)
}

async fn contact_authority_realm(
    state: &AppState,
    session: &SessionRecord,
    holder: &ContactPeer,
) -> Result<RealmId, AppError> {
    let realm_id = match holder {
        ContactPeer::Human { account_id } => {
            if account_id.station_id.as_str() != state.service_id() {
                return Err(crate::app_error!(
                    FailedPrecondition,
                    "Contact holder account does not belong to this Station",
                ));
            }
            let device = state
                .identities()
                .find_device(coland_services::identity::FindDeviceQuery {
                    actor_id: account_id.principal_id.to_string(),
                    device_id: session.require_human_device_id().clone(),
                })
                .await
                .map_err(|error| {
                    AppError::internal(format!("Contact holder device lookup: {error}"))
                })?
                .ok_or_else(|| {
                    crate::app_error!(FailedPrecondition, "Contact holder device is unavailable",)
                })?;
            if device.revoked_at.is_some() || device.verification_state != "verified" {
                return Err(crate::app_error!(
                    FailedPrecondition,
                    "Contact holder device is not active",
                ));
            }
            let payload = serde_json::from_value::<
                crate::routing::identity::device_signing::ProjectedDevicePayload,
            >(device.payload)
            .map_err(|error| {
                AppError::internal(format!("Contact holder device evidence: {error}"))
            })?;
            let authorize_event_id = payload.device_authorize_event_id.ok_or_else(|| {
                crate::app_error!(
                    FailedPrecondition,
                    "Contact holder device has no accepted authorization Event",
                )
            })?;
            let authorize_event = state
                .event_queries()
                .canonical_event(authorize_event_id.as_str())
                .await
                .map_err(|error| {
                    AppError::internal(format!("Contact device authorization lookup: {error}"))
                })?
                .ok_or_else(|| {
                    crate::app_error!(
                        FailedPrecondition,
                        "Contact holder device authorization Event is unavailable",
                    )
                })?;
            if !device_authorization_matches_contact_account(&authorize_event.actor_id, account_id)
                || authorize_event.kind != arkret_wire::event_kind_str::DEVICE_AUTHORIZE
            {
                return Err(crate::app_error!(
                    FailedPrecondition,
                    "Contact holder device authorization is invalid",
                ));
            }
            authorize_event.realm_id.ok_or_else(|| {
                crate::app_error!(
                    FailedPrecondition,
                    "Contact holder device authorization has no PCR realm",
                )
            })?
        }
        ContactPeer::Agent { actor_id, .. } => {
            state
                .agent_pairings()
                .agent(actor_id.signing_principal_id().as_str())
                .await
                .map_err(|error| {
                    AppError::internal(format!("Contact holder Agent lookup: {error}"))
                })?
                .ok_or_else(|| {
                    crate::app_error!(
                        FailedPrecondition,
                        "Contact holder Agent allocation is unavailable",
                    )
                })?
                .principal_control_realm_id
        }
    };
    let realm_id = RealmId::new(realm_id).map_err(|error| {
        AppError::internal(format!("Contact authority PCR id is invalid: {error}"))
    })?;
    let authority = state
        .persistence()
        .principal_resolution_for_realm(&realm_id)
        .await
        .map_err(|error| AppError::internal(format!("Contact authority lookup: {error}")))?
        .ok_or_else(|| {
            crate::app_error!(
                FailedPrecondition,
                "Contact account authority pair is unavailable",
            )
        })?;
    let holder_actor_id = holder.contact_actor_id();
    let holder_account_id = holder_actor_id.as_account_id().ok_or_else(|| {
        crate::app_error!(
            FailedPrecondition,
            "Contact holder is not a complete Account"
        )
    })?;
    if authority.account_id != *holder_account_id
        || authority.pcr_realm_id != realm_id
        || authority.account_id.station_id.as_str() != state.service_id()
    {
        return Err(crate::app_error!(
            FailedPrecondition,
            "Contact account authority pair does not match the authenticated holder",
        ));
    }
    Ok(realm_id)
}

fn validate_signed_event(event: &Event, draft: &PreparedEventDraft) -> Result<(), AppError> {
    let actual = arkret_canonical::canonical_json_bytes(
        &event
            .digest_payload()
            .map_err(|error| AppError::param_invalid(format!("signed Contact Event: {error}")))?,
    )
    .map_err(|error| AppError::param_invalid(format!("signed Contact Event bytes: {error}")))?;
    let expected = URL_SAFE_NO_PAD
        .decode(draft.unsigned_event_bytes.as_str())
        .map_err(|_| AppError::internal("stored Contact draft bytes are invalid"))?;
    let digest_suite = draft
        .event_digest
        .digest_suite()
        .map_err(|error| AppError::internal(format!("stored Contact digest suite: {error}")))?;
    let digest = Hash::new(
        event
            .event_digest_with_digest_suite(digest_suite)
            .map_err(|error| AppError::param_invalid(format!("signed Contact Event: {error}")))?,
    )
    .map_err(|error| AppError::param_invalid(format!("signed Contact digest: {error}")))?;
    if actual != expected
        || digest != draft.event_digest
        || event.producer_proof.is_none()
        || event
            .producer_proof
            .as_ref()
            .is_some_and(|proof| proof.event_digest != draft.event_digest)
    {
        return Err(AppError::conflict(
            "signed Contact Event differs from its durable reservation draft",
        ));
    }
    Ok(())
}

async fn reservation_for_commit(
    state: &AppState,
    principal: &str,
    body: &ContactCommitRequestBody,
) -> Result<ContactReservation, AppError> {
    let principal_id = DidCoreId::new(principal.to_owned())
        .map_err(|error| AppError::internal(format!("Contact principal id invalid: {error}")))?;
    let record = state
        .jobs()
        .scoped_idempotency_record(
            &arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                principal_id,
                state.service_core_id(),
            )),
            "org.arkret.coland.contact.prepare.v1",
            &contact_reservation_key(&body.reservation_handle),
        )
        .await
        .map_err(|error| AppError::internal(format!("Contact reservation lookup: {error}")))?
        .ok_or_else(|| AppError::conflict("Contact reservation is missing or expired"))?;
    if record.expires_at <= now() {
        return Err(AppError::conflict("Contact reservation expired"));
    }
    let reservation: ContactReservation = serde_json::from_value(record.response_body)
        .map_err(|error| AppError::internal(format!("stored Contact reservation: {error}")))?;
    if reservation.operation_id != body.operation_id
        || reservation.idempotency_key != body.idempotency_key
        || reservation.reservation_handle != body.reservation_handle
    {
        return Err(AppError::conflict("Contact reservation binding mismatch"));
    }
    validate_signed_event(&body.signed_event, &reservation.event_draft)?;
    Ok(reservation)
}

fn sorted_pair(
    left: &arkret_wire::ActorId,
    right: &arkret_wire::ActorId,
) -> Result<[arkret_wire::ActorId; 2], AppError> {
    let left_bytes = arkret_canonical::canonical_json_bytes(left)
        .map_err(|error| AppError::internal(format!("Contact pair encoding: {error}")))?;
    let right_bytes = arkret_canonical::canonical_json_bytes(right)
        .map_err(|error| AppError::internal(format!("Contact pair encoding: {error}")))?;
    if left_bytes == right_bytes {
        return Err(AppError::param_invalid(
            "Contact pair must contain distinct actors",
        ));
    }
    Ok(if left_bytes < right_bytes {
        [left.clone(), right.clone()]
    } else {
        [right.clone(), left.clone()]
    })
}

fn normal_basis(receipt: &RequestAcceptanceReceipt) -> Result<(ContactRound, Hash), AppError> {
    let contact_round = ContactRound::Normal {
        sorted_pair_member_ids: sorted_pair(
            &receipt.core.holder.contact_actor_id(),
            &receipt.core.peer.contact_actor_id(),
        )?,
        request_event_ref: receipt.core.request_event_ref.clone(),
        request_acceptance_receipt_digest: canonical_contact_digest(receipt)?,
    };
    contact_round
        .validate_canonical_order()
        .map_err(|error| AppError::internal(format!("Contact round order: {error}")))?;
    let contact_round_id = contact_hash("ak.contact.round.v1", &contact_round)?;
    Ok((contact_round, contact_round_id))
}

fn next_request_slot_coordinates(
    states: &[coland_services::identity::ContactRequestSlotState],
    owner_id: &arkret_wire::ActorId,
    peer_id: &arkret_wire::ActorId,
) -> Result<(u64, Option<EventId>), AppError> {
    let mut matches = states
        .iter()
        .filter(|s| &s.owner_id == owner_id && &s.peer_id == peer_id);
    let Some(current) = matches.next() else {
        return Ok((1, None));
    };
    if matches.next().is_some() || current.version == 0 {
        return Err(AppError::internal(
            "invalid durable Contact operation cursor",
        ));
    }
    Ok((
        current
            .version
            .checked_add(1)
            .filter(|v| *v <= 9_007_199_254_740_991)
            .ok_or_else(|| AppError::conflict("Contact version exhausted"))?,
        Some(current.head_event_ref.clone()),
    ))
}
fn advance_contact_operation_cursor(
    record: &mut ContactRecord,
    event: &Event,
) -> Result<(), AppError> {
    use coland_domain::identity::{ContactRequestChoice as Choice, ContactRequestSlotState};
    let peer: ContactPeer = serde_json::from_value(
        event
            .payload
            .get("peer")
            .cloned()
            .ok_or_else(|| AppError::param_invalid("Contact peer missing"))?,
    )
    .map_err(|e| AppError::param_invalid(e.to_string()))?;
    let expected = next_request_slot_coordinates(
        &record.request_slot_states,
        &event.actor_id,
        &peer.contact_actor_id(),
    )?;
    let version = contact_direction_version(event)?;
    let predecessor = event
        .payload
        .get("predecessor_event_ref")
        .cloned()
        .map(serde_json::from_value::<EventId>)
        .transpose()
        .map_err(|e| AppError::param_invalid(e.to_string()))?;
    if expected != (version, predecessor) {
        return Err(AppError::conflict("Contact operation cursor changed")
            .with_wire_code("contact_lineage_conflict"));
    }
    let index = record
        .request_slot_states
        .iter()
        .position(|s| s.owner_id == event.actor_id && s.peer_id == peer.contact_actor_id());
    let prior_choice = index.and_then(|i| record.request_slot_states[i].request_choice.clone());
    let request_ref = || {
        event
            .payload
            .get("request_event_ref")
            .cloned()
            .map(serde_json::from_value::<EventId>)
            .transpose()
            .map_err(|e| AppError::param_invalid(e.to_string()))?
            .ok_or_else(|| AppError::param_invalid("Contact consumed request missing"))
    };
    let choice = match event.kind {
        arkret_wire::EventKind::ContactRequested => Some(Choice::Open {
            request_event_ref: event.event_id.clone(),
        }),
        arkret_wire::EventKind::ContactAccepted => {
            if record.conflicting_contact_request_choice(&event.actor_id, &request_ref()?) {
                return Err(AppError::conflict(
                    "outgoing or glare-selected request cannot become normal",
                ));
            }
            Some(Choice::Normal {
                request_event_ref: request_ref()?,
            })
        }
        arkret_wire::EventKind::ContactRejected => {
            if matches!(prior_choice, Some(Choice::Glare { .. }))
                && record.conflicting_contact_request_choice(&event.actor_id, &request_ref()?)
            {
                return Err(AppError::conflict("glare choice is durable"));
            }
            Some(Choice::Rejected {
                request_event_ref: request_ref()?,
            })
        }
        _ => prior_choice,
    };
    let next = ContactRequestSlotState {
        owner_id: event.actor_id.clone(),
        peer_id: peer.contact_actor_id(),
        version,
        head_event_ref: event.event_id.clone(),
        operation_digest: None,
        request_choice: choice,
    };
    if let Some(i) = index {
        record.request_slot_states[i] = next;
    } else {
        record.request_slot_states.push(next);
        record
            .request_slot_states
            .sort_by_key(|s| s.owner_id.clone());
    }
    Ok(())
}

pub(super) async fn signed_current_proof(
    state: &AppState,
    contact_round_id: Hash,
    holder: ContactPeer,
    peer: ContactPeer,
    closure: Option<ContactRoundClosure>,
    event: &Event,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<ContactCurrentProof, AppError> {
    let head_digest = Hash::new(
        event
            .event_digest_with_digest_suite(digest_suite)
            .map_err(|e| AppError::internal(e.to_string()))?,
    )
    .map_err(|e| AppError::internal(e.to_string()))?;
    if head_digest != event.event_id.event_digest() || event.actor_id != holder.contact_actor_id() {
        return Err(AppError::param_invalid(
            "Contact head identity differs from original Event",
        ));
    }
    let record = state
        .contacts()
        .contact_any(&event.actor_id, &peer.contact_actor_id())
        .await
        .map_err(|e| AppError::internal(e.to_string()))?
        .ok_or_else(|| AppError::not_found("Contact current missing"))?;
    if record
        .request_slot_states
        .iter()
        .find(|slot| slot.owner_id == event.actor_id)
        .is_none_or(|slot| {
            slot.peer_id != peer.contact_actor_id()
                || slot.head_event_ref != event.event_id
                || slot.version != contact_direction_version(event).unwrap_or(0)
        })
    {
        return Err(crate::app_error!(
            TemporarilyUnavailable,
            "source proof head differs from durable current cursor"
        ));
    }
    let payload_scopes: Vec<ContactScope> = event
        .payload
        .get("granted_to_peer_scopes")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|e| AppError::internal(e.to_string()))?
        .unwrap_or_default();
    let previous = record.current_state.direction(&holder);
    let mut instances = previous
        .map(|d| d.scope_instances.clone())
        .unwrap_or_default();
    instances.retain(|i| payload_scopes.contains(&i.contact_scope));
    for scope in payload_scopes {
        if !instances.iter().any(|i| i.contact_scope == scope) {
            instances.push(ContactScopeInstance {
                contact_scope: scope,
                grant_event_ref: event.event_id.clone(),
            });
        }
    }
    instances.sort_by_key(|i| i.contact_scope);
    let initial = record
        .current_state
        .initial_identity
        .as_ref()
        .map(|i| i.round.contact_round_id.clone())
        .unwrap_or_else(|| contact_round_id.clone());
    let closure = closure
        .or_else(|| previous.and_then(|d| d.closed_round.clone()))
        .map(Box::new);
    if record.status == "tombstoned" || event.kind == arkret_wire::EventKind::ContactTombstone {
        instances.clear();
    }
    let signed_at = now();
    let (method, key) = completion::receipt_key_at_acceptance(state, signed_at).await?;
    ContactCurrentProof::sign_with(
        state.config().trust_domain.clone(),
        holder,
        peer,
        Some(initial),
        Some(contact_round_id),
        state.service_core_id(),
        event.event_id.clone(),
        contact_direction_version(event)?,
        instances,
        closure,
        signed_at,
        signed_at + chrono::Duration::minutes(10),
        |bytes| {
            Ok(ProtocolSignature {
                verification_method: method,
                created_at: signed_at,
                jws: contact_detached_jws(&key, bytes)
                    .map_err(|e| arkret_wire::WireError::Protocol(e.to_string()))?,
            })
        },
    )
    .map_err(|e| AppError::internal(e.to_string()))
}
fn contact_direction_version(event: &Event) -> Result<u64, AppError> {
    event
        .payload
        .get("version")
        .and_then(Value::as_u64)
        .filter(|v| *v > 0 && *v <= 9_007_199_254_740_991)
        .ok_or_else(|| AppError::param_invalid("Contact lifetime operation version missing"))
}

#[cfg(test)]
fn sign_contact_transcript(state: &AppState, bytes: &[u8]) -> Result<ProtocolSignature, AppError> {
    Ok(ProtocolSignature {
        verification_method: DidUrl::new(
            crate::routing::federation::federation_service_signature_key_id(
                state.service_did().as_str(),
            ),
        )
        .map_err(|error| AppError::internal(error.to_string()))?,
        created_at: now(),
        jws: contact_detached_jws(&state.notary_signing_key(), bytes)?,
    })
}

#[cfg(test)]
fn signed_lineage(
    state: &AppState,
    holder: ContactPeer,
    peer: ContactPeer,
    contact_round_id: Hash,
    version: u64,
    predecessor_event_ref: Option<EventId>,
    event_ref: EventId,
    scopes: Vec<ContactScope>,
    _terminal: bool,
) -> Result<ContactLineage, AppError> {
    let producer = arkret_models_collaboration::contact_operations::ContactProducerSigner::Direct(
        arkret_models_collaboration::contact_operations::ContactDirectProducerSigner {
            verification_method: DidUrl::new(
                crate::routing::federation::federation_service_signature_key_id(
                    state.service_did().as_str(),
                ),
            )
            .map_err(|error| AppError::internal(error.to_string()))?,
            public_key_b64u: Base64UrlString::new(
                URL_SAFE_NO_PAD.encode(state.notary_signing_key().verifying_key().as_bytes()),
            )
            .map_err(|error| AppError::internal(error.to_string()))?,
        },
    );
    let accepted_at = now();
    ContactLineage::sign_with(
        state.config().trust_domain.clone(),
        Some(contact_round_id.clone()),
        Some(contact_round_id),
        holder,
        peer,
        version,
        predecessor_event_ref,
        event_ref,
        producer,
        scopes,
        accepted_at,
        |bytes| {
            sign_contact_transcript(state, bytes)
                .map_err(|error| arkret_wire::WireError::Protocol(error.to_string()))
        },
    )
    .map_err(|error| AppError::internal(error.to_string()))
}

/// The exact current reader of one local issuer direction
/// `(contact_round_id, holder, peer)`: its committed head Event on this
/// Station and that head's confirmed direction version
/// (contact-and-direct-conversation.md section 3). A request head is the
/// founding edge at version 1. `None` when the head is not a Commit of this
/// Station authored by `holder`.
pub(crate) async fn local_direction_current(
    state: &AppState,
    record: &ContactRecord,
    holder: &arkret_wire::ActorId,
) -> Result<Option<(EventId, u64)>, AppError> {
    let Some(head) = record
        .request_slot_states
        .iter()
        .find(|s| &s.owner_id == holder)
        .map(|s| &s.head_event_ref)
    else {
        return Ok(None);
    };
    let Some(committed) = state
        .authority_commits()
        .committed_event(head)
        .await
        .map_err(|error| AppError::internal(format!("Contact direction head lookup: {error}")))?
    else {
        return Ok(None);
    };
    if &committed.event.event_id != head
        || committed.commit.event_ref != *head
        || &committed.event.actor_id != holder
    {
        return Ok(None);
    }
    Ok(Some((
        head.clone(),
        contact_direction_version(&committed.event)?,
    )))
}

pub(crate) async fn local_requester_current_proof(
    state: &AppState,
    contact_round_id: &Hash,
    request_receipt: &RequestAcceptanceReceipt,
) -> Result<Option<ContactCurrentProof>, AppError> {
    let Some(committed) = state
        .authority_commits()
        .committed_event(&request_receipt.core.request_event_ref)
        .await
        .map_err(|error| AppError::internal(format!("Contact request Commit lookup: {error}")))?
    else {
        return Ok(None);
    };
    let request_event = committed.event;
    if committed.commit.event_ref != request_event.event_id {
        return Err(AppError::internal(
            "Contact request Commit does not bind its Event",
        ));
    }
    let request_digest_suite = request_receipt
        .core
        .request_digest()
        .digest_suite()
        .map_err(|error| AppError::internal(format!("Contact request digest suite: {error}")))?;
    if request_event.kind != arkret_wire::EventKind::ContactRequested
        || request_event.actor_id != request_receipt.core.holder.contact_actor_id()
        || Hash::new(
            request_event
                .event_digest_with_digest_suite(request_digest_suite)
                .map_err(|error| {
                    AppError::internal(format!("accepted Contact request digest: {error}"))
                })?,
        )
        .map_err(|error| AppError::internal(format!("Contact request digest invalid: {error}")))?
            != request_receipt.core.request_digest()
    {
        return Err(AppError::internal(
            "accepted Contact request does not match its signed receipt",
        ));
    }
    let Some(resolution) = state
        .persistence()
        .principal_resolution_for_realm(&request_event.realm_id)
        .await
        .map_err(|error| {
            AppError::internal(format!("Contact requester_id authority lookup: {error}"))
        })?
    else {
        return Ok(None);
    };
    if resolution.account_id.principal_id != *request_event.actor_id.signing_principal_id()
        || resolution.pcr_realm_id != request_event.realm_id
        || resolution.account_id.station_id.as_str() != state.service_id()
    {
        return Ok(None);
    }
    signed_current_proof(
        state,
        contact_round_id.clone(),
        request_receipt.core.holder.clone(),
        request_receipt.core.peer.clone(),
        None,
        &request_event,
        request_digest_suite,
    )
    .await
    .map(Some)
}

pub(crate) async fn contact_assertion_signer(
    state: &AppState,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<(DidUrl, ed25519_dalek::SigningKey), AppError> {
    completion::receipt_key_at_acceptance(state, at).await
}

fn commit<'a>(
    state: &'a AppState,
    session: &'a SessionRecord,
    body: ContactCommitRequestBody,
) -> impl std::future::Future<Output = JsonResult<ContactOperationOutcome>> + Send + 'a {
    // Keep construction of this large state machine out of its caller's poll frame.
    Box::pin(async move {
        let request_hash = arkret_canonical::canonical_sha256(&body)
            .map_err(|error| AppError::internal(format!("Contact commit digest: {error}")))?;
        let authenticated_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            DidCoreId::new(session.actor.clone())
                .map_err(|error| AppError::internal(error.to_string()))?,
            state.service_core_id(),
        ));
        let response_binding = coland_storage::ContactCompletionBinding {
            authenticated_actor: authenticated_actor.clone(),
            idempotency_key: contact_phase_idempotency_key("commit", &body.idempotency_key),
            request_hash: request_hash.clone(),
        };
        if let Some(persisted) = state
            .persistence()
            .contact_completion_for_request(
                &authenticated_actor,
                &response_binding.idempotency_key,
                &request_hash,
            )
            .await
            .map_err(|error| AppError::conflict(error.to_string()))?
        {
            if persisted.event.event_id != body.signed_event.event_id {
                return Err(AppError::conflict(
                    "Contact commit key is bound to another Event",
                ));
            }
            return Box::pin(completion::resolve_completion(state, &response_binding)).await;
        }
        if let Some(outcome) = replay::<ContactOperationOutcome>(
            state,
            &session.actor,
            "org.arkret.coland.contact.commit.v1",
            &contact_phase_idempotency_key("commit", &body.idempotency_key),
            &request_hash,
        )
        .await?
        {
            return json_ok(outcome);
        }
        let reservation = reservation_for_commit(state, &session.actor, &body).await?;
        let authenticated_holder = holder_peer(state, session).await?;
        if reservation.holder != authenticated_holder {
            return Err(AppError::capability_denied(
                "Contact reservation belongs to another holder",
            ));
        }
        match &reservation.branch {
            ContactReservationBranch::Response {
                request_receipt,
                peer,
                ..
            }
            | ContactReservationBranch::Reject {
                request_receipt,
                peer,
            } => {
                let record = state
                    .contacts()
                    .contact_any(
                        &peer.contact_actor_id(),
                        &reservation.holder.contact_actor_id(),
                    )
                    .await
                    .map_err(|error| AppError::internal(error.to_string()))?
                    .ok_or_else(|| AppError::not_found("pending Contact request not found"))?;
                validate_request_acceptance_receipt(
                    state,
                    &record,
                    &reservation.holder,
                    request_receipt,
                )
                .await?;
            }
            _ => {}
        }
        // The holder's producer is verified before planning: its exact key is
        // frozen into every source carrier of this Event, and the accepting
        // transaction rechecks the same guard.
        let producer = crate::state::verify_contact_producer(state, session, &body.signed_event)
            .await
            .map_err(contact_admission_error)?;
        // One linearization instant: the slot CAS observation, every receipt's
        // `accepted_at` and the covering Commit.
        let accepted_at = arkret_canonical::normalize_timestamp_canonical(now());
        let (mut contact_projection, action, local_mirror_target) = match plan_contact_commit(
            state,
            &reservation,
            &body.signed_event,
            accepted_at,
        )
        .await?
        {
            ContactCommitPlan::Failed(failed) => {
                let outcome = ContactOperationOutcome::Failed { outcome: failed };
                persist_final(
                    state,
                    &session.actor,
                    "org.arkret.coland.contact.commit.v1",
                    &response_binding.idempotency_key,
                    &request_hash,
                    &outcome,
                )
                .await?;
                return json_ok(outcome);
            }
            ContactCommitPlan::Ready {
                projection,
                action,
                local_mirror_target,
            } => (*projection, *action, local_mirror_target),
        };
        let mut intent = Box::pin(prepare_contact_completion_draft(
            state,
            &reservation,
            &body.signed_event,
            action,
            response_binding.clone(),
            local_mirror_target,
        ))
        .await?
        .bind_producer(producer.signer)
        .map_err(|error| AppError::internal(error.to_string()))?;
        intent
            .freeze_acceptance_time(accepted_at)
            .map_err(|error| AppError::internal(error.to_string()))?;
        contact_projection.completion_intent = Some(intent);
        Box::pin(crate::state::commit_contact_event_unit(
            state,
            &arkret_wire::EventAdmissionSubmission::new(body.signed_event.clone()),
            producer.guard,
            contact_projection,
            accepted_at,
        ))
        .await
        .map_err(contact_admission_error)?;
        Box::pin(completion::resolve_completion(state, &response_binding)).await
    })
}

/// Map a refused Contact admission onto its registered wire code. A lost
/// row or slot CAS keeps the Contact code the planner named; producer and
/// authority-cut refusals keep their registered code.
fn contact_admission_error(error: coland_services::ServiceError) -> AppError {
    use coland_services::ServiceError;
    match &error {
        ServiceError::Conflict(detail) => {
            let (code, message) = detail.split_once(": ").unwrap_or((detail.as_str(), ""));
            if let Some(mapped) = coland_http::error::ErrorCode::from_wire(code) {
                return AppError::from_rejection(mapped, message.to_owned());
            }
            if code.starts_with("contact_") {
                return AppError::conflict(detail.clone()).with_wire_code(code);
            }
            AppError::capability_denied(detail.clone())
        }
        ServiceError::SchemaViolation(detail) => AppError::schema_violation(detail.clone()),
        ServiceError::NotFound(detail) => AppError::not_found(detail.clone()),
        _ => AppError::internal(error.to_string()),
    }
}

enum ContactCommitPlan {
    Failed(ContactFailedOutcome),
    Ready {
        projection: Box<coland_services::events::CommitContactProjection>,
        action: Box<coland_storage::ContactCompletionAction>,
        local_mirror_target: Option<String>,
    },
}
fn plan_contact_commit<'a>(
    state: &'a AppState,
    reservation: &'a ContactReservation,
    event: &'a Event,
    accepted_at: chrono::DateTime<chrono::Utc>,
) -> impl std::future::Future<Output = Result<ContactCommitPlan, AppError>> + Send + 'a {
    Box::pin(async move {
        use coland_storage::ContactCompletionAction;
        let holder = reservation.holder.contact_actor_id().clone();
        let peer = reservation.branch.peer().contact_actor_id().clone();
        let contacts = state.contacts();
        let projection;
        let mut local_mirror_target = None;
        let outcome = match &reservation.branch {
            ContactReservationBranch::Request {
                granted_to_peer_scopes,
                initial_contact_round_id,
                ..
            } => {
                let same_service_target = if let Some(peer_account_id) = peer.as_account_id() {
                    state
                        .identities()
                        .account(peer_account_id)
                        .await
                        .map_err(|error| {
                            AppError::internal(format!("Contact target account lookup: {error}"))
                        })?
                        .is_some()
                } else {
                    false
                };
                let peer_id = Some(reservation.branch.peer().delivery_station_id().clone());
                let existing = contacts
                    .contact_any(&holder, &peer)
                    .await
                    .map_err(|error| AppError::internal(error.to_string()))?;
                let (version, predecessor_event_ref) = next_request_slot_coordinates(
                    existing
                        .as_ref()
                        .map(|r| r.request_slot_states.as_slice())
                        .unwrap_or_default(),
                    &holder,
                    &peer,
                )?;
                if existing.as_ref().is_some_and(|r| {
                    r.status == "accepted"
                        || (r.status == "pending"
                            && r.request_receipts
                                .iter()
                                .any(|q| q.core.holder.contact_actor_id() == holder))
                }) {
                    return Ok(ContactCommitPlan::Failed(ContactFailedOutcome {
                        result_kind: ContactResultKind::Request,
                        operation_id: reservation.operation_id.clone(),
                        reason: ContactOperationRejectReason::ContactRoundConflict,
                    }));
                }
                let (
                    mut private_state,
                    expected_updated_at,
                    created_at,
                    request_slot_states,
                    prior_receipts,
                    prior_mirrors,
                ) = existing
                    .map(|r| {
                        (
                            r.current_state,
                            Some(r.updated_at),
                            r.created_at,
                            r.request_slot_states,
                            if r.status == "pending" {
                                r.request_receipts
                            } else {
                                Vec::new()
                            },
                            if r.status == "pending" {
                                r.request_mirror_receipts
                            } else {
                                Vec::new()
                            },
                        )
                    })
                    .unwrap_or((
                        ContactPrivateState::default(),
                        None,
                        event.created_at,
                        Vec::new(),
                        Vec::new(),
                        Vec::new(),
                    ));
                let expected_initial = private_state
                    .initial_identity
                    .as_ref()
                    .map(|i| i.round.contact_round_id.clone());
                if initial_contact_round_id != &expected_initial {
                    return Err(AppError::conflict(
                        "Contact request changes fixed first identity",
                    ));
                }
                private_state
                    .local_glare_attestations
                    .retain(|a| a.subject_id != holder);
                private_state.round_basis = None;
                private_state.round_events.clear();
                for direction in &mut private_state.directions {
                    direction.scope_instances.clear();
                    direction.scope_grants.clear();
                    direction.current_proof = None;
                }
                let pending_incoming_admitted = if same_service_target {
                    let target_account_id = peer.as_account_id().ok_or_else(|| {
                        AppError::internal("same-service Contact target is not an Account")
                    })?;
                    crate::routing::invites::admit_quarantine_new_source(
                        state,
                        target_account_id,
                        holder.signing_principal_id().as_str(),
                        now(),
                    )
                    .await?
                } else {
                    false
                };
                // Same-service delivery is a fact about the target account's
                // current host, not about the requester_id's introduction-evidence
                // trust tier. A DID without URL components legitimately uses `explicit_address`,
                // but its local recipient still needs the exact privately
                // resolvable request Event required to author a response.
                local_mirror_target = (same_service_target && pending_incoming_admitted)
                    .then(|| contact_mirror_target_holder_key(&peer));
                projection = Some(coland_services::events::CommitContactProjection {
                    completion_intent: None,
                    record: Box::new(ContactRecord {
                        requester_id: holder.clone(),
                        target_id: peer.clone(),
                        contact_round_id: None,
                        granted_to_target_scopes: contact_scope_strings(granted_to_peer_scopes),
                        granted_to_requester_scopes: Vec::new(),
                        status: "pending".to_owned(),
                        pending_incoming_admitted,
                        request_event_ref: Some(event.event_id.clone()),
                        request_slot_states,
                        request_receipts: prior_receipts,
                        request_mirror_receipts: prior_mirrors,
                        contact_round_evidence: None,
                        current_state: private_state,

                        response_event_ref: None,
                        tombstone_event_ref: None,
                        message: event
                            .payload
                            .get("message")
                            .and_then(Value::as_str)
                            .map(ToOwned::to_owned),
                        peer_host_id: peer_id,
                        peer_service_resolution: contact_service_resolution(
                            state,
                            &reservation.branch,
                        )
                        .await?,
                        created_at,
                        updated_at: expected_updated_at
                            .map(|expected| contact_revision_after(expected, event.created_at))
                            .unwrap_or(event.created_at),
                    }),
                    expected_updated_at,
                    conflict_code: "contact_round_conflict".to_owned(),
                    verified_mirror: None,
                    invite_policy: None,
                });
                ContactCompletionAction::Request {
                    version,
                    predecessor_event_ref,
                }
            }
            ContactReservationBranch::Response {
                request_receipt,
                contact_round_id,
                granted_to_peer_scopes,
                ..
            } => {
                let Some(mut record) = contacts
                    .contact_any(&peer, &holder)
                    .await
                    .map_err(|error| AppError::internal(error.to_string()))?
                else {
                    return Err(AppError::not_found("pending Contact request not found"));
                };
                validate_request_acceptance_receipt(
                    state,
                    &record,
                    &reservation.holder,
                    request_receipt,
                )
                .await?;
                require_request_current(state, &record, &reservation.holder, request_receipt)
                    .await?;
                validate_normal_response_slot(&record, &reservation.holder, request_receipt)?;
                let (contact_round, expected_contact_round_id) = normal_basis(request_receipt)?;
                if &expected_contact_round_id != contact_round_id {
                    return Err(AppError::conflict(
                        "Contact response contact_round does not match the accepted request receipt",
                    ));
                }
                let expected_updated_at = record.updated_at;
                let sorted_pair_member_ids = match &contact_round {
                    ContactRound::Normal {
                        sorted_pair_member_ids,
                        ..
                    } => sorted_pair_member_ids.clone(),
                    ContactRound::Glare { .. } => unreachable!("normal basis returned glare"),
                };
                let (version, predecessor_event_ref) =
                    next_request_slot_coordinates(&record.request_slot_states, &holder, &peer)?;
                let absence = OutgoingSlotAbsenceTranscript {
                    trust_domain_id: state.config().trust_domain.clone(),
                    sorted_pair_member_ids,
                    request_slot_owner: holder.clone(),
                    contact_round_id: contact_round_id.clone(),
                    request_event_ref: request_receipt.core.request_event_ref.clone(),
                    version,
                    predecessor_event_ref,
                    observed_at: accepted_at,
                    outgoing_request_state: OutgoingRequestState::Absent,
                };
                absence
                    .validate_shape()
                    .map_err(|e| AppError::internal(e.to_string()))?;
                record.status = "accepted".to_owned();
                record.request_receipts.clear();
                record.request_mirror_receipts.clear();
                record.contact_round_id = Some(contact_round_id.clone());
                record.granted_to_requester_scopes = contact_scope_strings(granted_to_peer_scopes);
                record.response_event_ref = Some(event.event_id.clone());
                record.contact_round_evidence = None;
                record.updated_at = contact_revision_after(expected_updated_at, event.created_at);
                projection = Some(coland_services::events::CommitContactProjection {
                    completion_intent: None,
                    record: Box::new(record),
                    expected_updated_at: Some(expected_updated_at),
                    conflict_code: "contact_lineage_conflict".to_owned(),
                    verified_mirror: None,
                    invite_policy: None,
                });
                ContactCompletionAction::Response {
                    request_receipt: Box::new(request_receipt.clone()),
                    absence: Box::new(absence),
                }
            }
            ContactReservationBranch::Reject {
                request_receipt, ..
            } => {
                let Some(mut record) = contacts
                    .contact_any(&peer, &holder)
                    .await
                    .map_err(|error| AppError::internal(error.to_string()))?
                else {
                    return Err(AppError::not_found("pending Contact request not found"));
                };
                validate_request_acceptance_receipt(
                    state,
                    &record,
                    &reservation.holder,
                    request_receipt,
                )
                .await?;
                if record.status != "pending" {
                    return Err(AppError::conflict(
                        "Contact request slot is already consumed",
                    ));
                }
                let expected_updated_at = record.updated_at;
                record.status = "rejected".to_owned();
                record.request_receipts.clear();
                record.request_mirror_receipts.clear();
                record.response_event_ref = Some(event.event_id.clone());
                record.updated_at = contact_revision_after(expected_updated_at, event.created_at);
                projection = Some(coland_services::events::CommitContactProjection {
                    completion_intent: None,
                    record: Box::new(record),
                    expected_updated_at: Some(expected_updated_at),
                    conflict_code: "contact_lineage_conflict".to_owned(),
                    verified_mirror: None,
                    invite_policy: None,
                });
                ContactCompletionAction::Reject {
                    request_receipt: Box::new(request_receipt.clone()),
                }
            }
            ContactReservationBranch::ScopeUpdate {
                contact_round_id,
                version,
                predecessor_event_ref,
                granted_to_peer_scopes,
                ..
            } => {
                let Some(mut record) = contact_record_for_lineage(state, &holder, &peer).await?
                else {
                    return Err(AppError::not_found("accepted Contact round not found"));
                };
                validate_lineage_head(
                    state,
                    &record,
                    &holder,
                    contact_round_id,
                    *version,
                    predecessor_event_ref,
                )
                .await?;
                require_widening_current(
                    state,
                    &record,
                    &reservation.holder,
                    granted_to_peer_scopes,
                )
                .await?;
                let expected_updated_at = record.updated_at;
                set_holder_scopes(
                    &mut record,
                    &holder,
                    contact_scope_strings(granted_to_peer_scopes),
                );
                record.updated_at = contact_revision_after(expected_updated_at, event.created_at);
                // The accepted contact_round remains accepted even when its directional
                // intersection is empty. Authorization reads the exact full-set
                // heads, so an empty intersection grants nothing.
                record.status = "accepted".to_owned();
                set_holder_head(&mut record, &holder, event.event_id.clone());
                projection = Some(coland_services::events::CommitContactProjection {
                    completion_intent: None,
                    record: Box::new(record),
                    expected_updated_at: Some(expected_updated_at),
                    conflict_code: "contact_lineage_conflict".to_owned(),
                    verified_mirror: None,
                    invite_policy: None,
                });
                ContactCompletionAction::ScopeUpdate
            }
            ContactReservationBranch::Tombstone {
                contact_round_id,
                version,
                predecessor_event_ref,
                block_peer,
                ..
            } => {
                let Some(mut record) = contact_record_for_lineage(state, &holder, &peer).await?
                else {
                    return Err(AppError::not_found("accepted Contact round not found"));
                };
                validate_lineage_head(
                    state,
                    &record,
                    &holder,
                    contact_round_id,
                    *version,
                    predecessor_event_ref,
                )
                .await?;
                let expected_updated_at = record.updated_at;
                record.status = "tombstoned".to_owned();
                record.request_receipts.clear();
                record.request_mirror_receipts.clear();
                record.tombstone_event_ref = Some(event.event_id.clone());
                set_holder_head(&mut record, &holder, event.event_id.clone());
                record.updated_at = contact_revision_after(expected_updated_at, event.created_at);
                let invite_policy = if *block_peer {
                    let holder_account_id = match &reservation.holder {
                        ContactPeer::Human { account_id } => account_id.clone(),
                        ContactPeer::Agent {
                            controller_account_id,
                            ..
                        } => controller_account_id.clone(),
                    };
                    let mut policy = state
                        .contacts()
                        .invite_policy(&holder_account_id)
                        .unwrap_or_else(|| {
                            InviteReceivePolicy::spec_default(holder_account_id.clone())
                        });
                    if !policy.denied_actor_ids.contains(&peer) {
                        policy.denied_actor_ids.push(peer.clone());
                        policy
                            .denied_actor_ids
                            .sort_by_key(arkret_wire::ActorId::to_string);
                    }
                    Some((holder_account_id, policy))
                } else {
                    None
                };
                projection = Some(coland_services::events::CommitContactProjection {
                    completion_intent: None,
                    record: Box::new(record),
                    expected_updated_at: Some(expected_updated_at),
                    conflict_code: "contact_lineage_conflict".to_owned(),
                    verified_mirror: None,
                    invite_policy,
                });
                ContactCompletionAction::Tombstone
            }
        };
        let mut projection =
            projection.ok_or_else(|| AppError::internal("Contact plan omits projection"))?;
        advance_contact_operation_cursor(&mut projection.record, event)?;
        Ok(ContactCommitPlan::Ready {
            projection: Box::new(projection),
            action: Box::new(outcome),
            local_mirror_target,
        })
    })
}

async fn prepare_contact_completion_draft(
    state: &AppState,
    reservation: &ContactReservation,
    event: &Event,
    action: coland_storage::ContactCompletionAction,
    response_binding: coland_storage::ContactCompletionBinding,
    local_mirror_target: Option<String>,
) -> Result<coland_storage::ContactCompletionDraft, AppError> {
    let introduction_evidence = match &reservation.branch {
        ContactReservationBranch::Request {
            introduction_evidence,
            ..
        } => Some((**introduction_evidence).clone()),
        _ => None,
    };
    let contact_address = contact_delivery_address(
        state,
        reservation.branch.peer(),
        introduction_evidence.as_ref(),
    )
    .await?
    .unwrap_or_else(|| PeerContactAddress {
        recipient: reservation.branch.peer().clone(),
        service_resolution: ServiceResolutionCarrier::ResolutionUrl {
            resolution_url: format!(
                "{}{}",
                state.config().public_base_url.trim_end_matches('/'),
                arkret_models_identity::canonical_service_resolution_path(&state.service_core_id())
            ),
        },
        route_assistance: None,
    });
    Ok(coland_storage::ContactCompletionDraft {
        event: event.clone(),
        operation_id: reservation.operation_id.clone(),
        holder: reservation.holder.clone(),
        action,
        response_binding,
        target: coland_storage::ContactDeliveryTarget {
            contact_address,
            introduction_evidence,
            idempotency_key: IdempotencyKey::new(format!("peer-contact:{}", event.event_id))
                .map_err(|error| AppError::internal(error.to_string()))?,
        },
        local_mirror_target,
    })
}

pub(crate) async fn contact_delivery_address(
    state: &AppState,
    peer: &ContactPeer,
    introduction: Option<&ContactIntroductionEvidence>,
) -> Result<Option<PeerContactAddress>, AppError> {
    let station_id = peer.delivery_station_id();
    if station_id.as_str() == state.service_id() {
        return Ok(None);
    }
    // The signed participant fixes the destination. Locator and discovery
    // records supply transport coordinates only; the shared resolver verifies
    // their service identity, method history, freshness and Describe binding.
    let address = if let Some(ContactIntroductionEvidence::LocatorRef { principal_locator }) =
        introduction
    {
        if !matches!(peer, ContactPeer::Human { account_id } if account_id == &principal_locator.account_id)
        {
            return Err(AppError::param_invalid(
                "Contact locator does not address the exact recipient AccountId",
            ));
        }
        PeerContactAddress {
            recipient: peer.clone(),
            service_resolution: principal_locator.service_resolution.clone(),
            route_assistance: principal_locator.route_assistance.clone(),
        }
    } else {
        let route = crate::routing::federation::resolved_peer_route(
            state,
            station_id.as_str(),
            PeerContactAddress::RECIPIENT_SERVICE_KIND,
            false,
        )
        .await
        .map_err(|error| {
            crate::app_error!(
                FailedPrecondition,
                format!("Contact recipient route: {error}")
            )
        })?;
        PeerContactAddress::for_recipient(
            peer.clone(),
            ServiceResolutionCarrier::ResolutionUrl {
                resolution_url: format!(
                    "{}{}",
                    route.base_url(),
                    arkret_models_identity::canonical_service_resolution_path(route.service_id())
                        .trim_start_matches('/')
                ),
            },
        )
    };
    address.validate_shape().map_err(|error| {
        AppError::param_invalid(format!("invalid Contact recipient route: {error}"))
    })?;
    Ok(Some(address))
}

async fn contact_introduction_service_resolution(
    state: &AppState,
    introduction_evidence: &ContactIntroductionEvidence,
) -> Result<Option<ServiceResolutionCarrier>, AppError> {
    let carrier = match introduction_evidence {
        ContactIntroductionEvidence::LocatorRef { principal_locator } => {
            Some(principal_locator.service_resolution.clone())
        }
        // Realm membership proves social context, not transport routing. The
        // removed membership delivery binding must not be resurrected here.
        ContactIntroductionEvidence::SharedRealm { .. } => None,
        ContactIntroductionEvidence::SameStation => Some(ServiceResolutionCarrier::Inline{inline:crate::routing::system::service_resolution::current_authenticated_service_resolution(state).await?}),
        ContactIntroductionEvidence::HandleClaim { .. }
        | ContactIntroductionEvidence::ExplicitAddress => None,
    };
    Ok(carrier)
}

async fn contact_service_resolution(
    state: &AppState,
    branch: &ContactReservationBranch,
) -> Result<Option<Value>, AppError> {
    let ContactReservationBranch::Request {
        introduction_evidence,
        ..
    } = branch
    else {
        return Ok(None);
    };
    contact_introduction_service_resolution(state, introduction_evidence)
        .await?
        .map(|carrier| {
            serde_json::to_value(carrier).map_err(|error| {
                AppError::internal(format!("Contact service resolution encode failed: {error}"))
            })
        })
        .transpose()
}

async fn contact_record_for_lineage(
    state: &AppState,
    holder: &arkret_wire::ActorId,
    peer: &arkret_wire::ActorId,
) -> Result<Option<ContactRecord>, AppError> {
    let forward = state
        .contacts()
        .contact_any(holder, peer)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    if forward.is_some() {
        return Ok(forward);
    }
    // A Contact round has one durable row, oriented by the original
    // requester. Scope/tombstone lineage commands are holder-symmetric, so a
    // holder who was the original target must resolve the reverse key before
    // validating its local lineage head.
    state
        .contacts()
        .contact_any(peer, holder)
        .await
        .map_err(|error| AppError::internal(error.to_string()))
}

fn holder_head<'a>(
    record: &'a ContactRecord,
    holder: &arkret_wire::ActorId,
) -> Option<&'a EventId> {
    record
        .current_state
        .directions
        .iter()
        .find(|direction| direction.head_operation.holder().contact_actor_id() == *holder)
        .map(|direction| &direction.head_operation.event().event_id)
}

fn set_holder_head(record: &mut ContactRecord, holder: &arkret_wire::ActorId, event_ref: EventId) {
    if &record.requester_id == holder {
        record.request_event_ref = Some(event_ref);
    } else {
        record.response_event_ref = Some(event_ref);
    }
}

fn set_holder_scopes(
    record: &mut ContactRecord,
    holder: &arkret_wire::ActorId,
    scopes: Vec<String>,
) {
    if &record.requester_id == holder {
        record.granted_to_target_scopes = scopes;
    } else {
        record.granted_to_requester_scopes = scopes;
    }
}

async fn validate_lineage_head(
    state: &AppState,
    record: &ContactRecord,
    holder: &arkret_wire::ActorId,
    contact_round_id: &Hash,
    version: u64,
    predecessor: &EventId,
) -> Result<(), AppError> {
    // Each issuer direction carries its own lineage version: the next Event
    // extends the holder's own committed head by exactly one
    // (contact-and-direct-conversation.md section 3).
    let current = local_direction_current(state, record, holder).await?;
    if record.contact_round_id.as_ref() != Some(contact_round_id)
        || current
            .as_ref()
            .and_then(|(_, current)| current.checked_add(1))
            != Some(version)
        || current.as_ref().map(|(head, _)| head) != Some(predecessor)
        || holder_head(record, holder) != Some(predecessor)
    {
        return Err(AppError::conflict("Contact lineage CAS mismatch")
            .with_wire_code("contact_lineage_conflict"));
    }
    if record.status != "accepted"
        || record.current_state.initial_identity.is_none()
        || record
            .current_state
            .round_basis
            .as_ref()
            .map(|r| &r.contact_round_id)
            != Some(contact_round_id)
    {
        return Err(AppError::conflict("Contact round not established")
            .with_wire_code("contact_scope_stale"));
    }
    Ok(())
}

async fn require_widening_current(
    state: &AppState,
    record: &ContactRecord,
    holder: &ContactPeer,
    scopes: &[ContactScope],
) -> Result<(), AppError> {
    let own = record
        .current_state
        .direction(holder)
        .ok_or_else(|| AppError::conflict("Contact original direction missing"))?;
    if scopes.iter().all(|scope| {
        own.scope_instances
            .iter()
            .any(|i| i.contact_scope == *scope)
    }) {
        return Ok(());
    }
    for direction in &record.current_state.directions {
        if direction
            .head_operation
            .holder()
            .delivery_station_id()
            .as_str()
            != state.service_id()
            && direction.current_proof.as_ref().is_none_or(|proof| {
                proof.fresh_until <= now()
                    || proof.contact_round_id.as_ref() != record.contact_round_id.as_ref()
            })
        {
            crate::routing::identity::contact_federation::request_remote_contact_current(
                state,
                holder,
                direction.head_operation.holder(),
                &record.current_state,
            )
            .await?;
            return Err(
                AppError::conflict("Contact widening requires current remote evidence")
                    .with_wire_code("contact_scope_stale"),
            );
        }
    }
    Ok(())
}
async fn require_request_current(
    state: &AppState,
    record: &ContactRecord,
    holder: &ContactPeer,
    receipt: &RequestAcceptanceReceipt,
) -> Result<(), AppError> {
    if receipt.core.holder.delivery_station_id().as_str() == state.service_id() {
        return Ok(());
    }
    let current = record.current_state.direction(&receipt.core.holder);
    if current
        .and_then(|d| d.current_proof.as_ref())
        .is_some_and(|proof| {
            proof.head_event_ref == receipt.core.request_event_ref
                && proof.fresh_until > now()
                && proof.scope_instances.is_empty()
        })
    {
        return Ok(());
    }
    crate::routing::identity::contact_federation::request_remote_contact_current(
        state,
        holder,
        &receipt.core.holder,
        &record.current_state,
    )
    .await?;
    Err(
        AppError::conflict("Contact acceptance requires current exact request")
            .with_wire_code("contact_scope_stale"),
    )
}

fn contact_revision_after(
    expected_updated_at: chrono::DateTime<chrono::Utc>,
    preferred: chrono::DateTime<chrono::Utc>,
) -> chrono::DateTime<chrono::Utc> {
    preferred.max(expected_updated_at + chrono::Duration::microseconds(1))
}

fn fixed_initial(record: &ContactRecord) -> Result<Hash, AppError> {
    record
        .current_state
        .initial_identity
        .as_ref()
        .map(|i| i.round.contact_round_id.clone())
        .ok_or_else(|| {
            crate::app_error!(
                TemporarilyUnavailable,
                "Contact fixed first identity is unavailable"
            )
        })
}
pub(super) async fn request(
    state: &AppState,
    session: &SessionRecord,
    body: ContactOperationRequestBody,
) -> JsonResult<ContactOperationOutcome> {
    match body {
        ContactOperationRequestBody::Prepare(body) => {
            let (context, replayed) =
                prepare_context::<arkret_wire::event_spec::ContactRequested, _>(
                    state,
                    session,
                    &body,
                    &body.idempotency_key,
                    &body.peer,
                )
                .await?;
            if let Some(outcome) = replayed {
                return json_ok(outcome);
            }
            let session_actor_id = context.holder.contact_actor_id();
            let prior = state
                .contacts()
                .contact_any(&session_actor_id, &body.peer.contact_actor_id())
                .await
                .map_err(|error| AppError::internal(error.to_string()))?;
            let initial_contact_round_id = prior.as_ref().and_then(|r| {
                r.current_state
                    .initial_identity
                    .as_ref()
                    .map(|i| i.round.contact_round_id.clone())
            });
            let (version, predecessor_event_ref) = next_request_slot_coordinates(
                prior
                    .as_ref()
                    .map(|r| r.request_slot_states.as_slice())
                    .unwrap_or_default(),
                &session_actor_id,
                &body.peer.contact_actor_id(),
            )?;
            let introduction_evidence_digest = contact_hash(
                "ak.contact.introduction-evidence.v1",
                &body.introduction_evidence,
            )?;
            let payload = ContactRequestedPayload {
                trust_domain_id: state.config().trust_domain.clone(),
                version,
                predecessor_event_ref,
                peer: body.peer.clone(),
                granted_to_peer_scopes: body.granted_to_peer_scopes.clone(),
                introduction_evidence_digest,
                initial_contact_round_id: initial_contact_round_id.clone(),
                message: normalize_contact_message(body.message.as_deref())?,
            };
            prepare::<arkret_wire::event_spec::ContactRequested>(
                state,
                session,
                context,
                body.operation_id,
                body.idempotency_key,
                ContactReservationBranch::Request {
                    peer: body.peer,
                    granted_to_peer_scopes: body.granted_to_peer_scopes,
                    initial_contact_round_id,
                    introduction_evidence: Box::new(body.introduction_evidence),
                },
                payload,
            )
            .await
        }
        ContactOperationRequestBody::Commit(body) => commit(state, session, body).await,
    }
}

fn validate_normal_response_slot(
    record: &coland_services::identity::ContactRecord,
    responder: &ContactPeer,
    request_receipt: &RequestAcceptanceReceipt,
) -> Result<(), AppError> {
    if record.status != "pending"
        || record.request_event_ref.as_ref() != Some(&request_receipt.core.request_event_ref)
    {
        return Err(AppError::conflict(
            "Contact request slot is already consumed",
        ));
    }
    // contact_any returns the same pair row in either lookup direction. The
    // retained receipt set, not the direction of that lookup, records whether
    // a reverse outgoing request coexists. Check again at commit; the row CAS
    // prevents a concurrent request from invalidating this absence proof.
    if record.requester_id != request_receipt.core.holder.contact_actor_id()
        || record.target_id != responder.contact_actor_id()
        || request_receipt.core.peer != *responder
        || record.request_receipts.len() != 1
    {
        return Err(AppError::conflict(
            "normal Contact response requires one incoming request and no outgoing request slot",
        ));
    }
    if canonical_contact_digest(&record.request_receipts[0])?
        != canonical_contact_digest(request_receipt)?
    {
        return Err(AppError::conflict(
            "Contact response does not match the retained request receipt",
        ));
    }
    Ok(())
}

fn retained_incoming_receipt(
    record: &ContactRecord,
    holder: &ContactPeer,
    peer: &ContactPeer,
    request_event_ref: &EventId,
) -> Result<RequestAcceptanceReceipt, AppError> {
    if !record.pending_incoming_admitted
        || record.status != "pending"
        || record.target_id != holder.contact_actor_id()
        || record.requester_id != peer.contact_actor_id()
        || record.request_event_ref.as_ref() != Some(request_event_ref)
        || record.request_receipts.len() != 1
    {
        return Err(AppError::conflict(
            "Contact proposal is not currently respondable",
        ));
    }
    let receipt = &record.request_receipts[0];
    if receipt.core.request_event_ref != *request_event_ref
        || receipt.core.holder != *peer
        || receipt.core.peer != *holder
    {
        return Err(AppError::conflict(
            "Contact proposal does not match retained evidence",
        ));
    }
    Ok(receipt.clone())
}

pub(super) async fn respond(
    state: &AppState,
    session: &SessionRecord,
    body: ContactAcceptRequestBody,
) -> JsonResult<ContactOperationOutcome> {
    match body {
        ContactAcceptRequestBody::Prepare(body) => {
            let (context, replayed) =
                prepare_context::<arkret_wire::event_spec::ContactAccepted, _>(
                    state,
                    session,
                    &body,
                    &body.idempotency_key,
                    &body.peer,
                )
                .await?;
            if let Some(outcome) = replayed {
                return json_ok(outcome);
            }
            let holder = context.holder.clone();
            let peer = body.peer.clone();
            let record = state
                .contacts()
                .contact_any(&peer.contact_actor_id(), &holder.contact_actor_id())
                .await
                .map_err(|error| AppError::internal(error.to_string()))?
                .ok_or_else(|| AppError::not_found("pending Contact request not found"))?;
            let request_receipt =
                retained_incoming_receipt(&record, &holder, &peer, &body.request_event_ref)?;
            validate_request_acceptance_receipt(state, &record, &holder, &request_receipt).await?;
            require_request_current(state, &record, &holder, &request_receipt).await?;
            validate_normal_response_slot(&record, &holder, &request_receipt)?;
            let (_, contact_round_id) = normal_basis(&request_receipt)?;
            let (version, predecessor_event_ref) = next_request_slot_coordinates(
                &record.request_slot_states,
                &holder.contact_actor_id(),
                &peer.contact_actor_id(),
            )?;
            let payload = ContactAcceptedPayload {
                trust_domain_id: state.config().trust_domain.clone(),
                predecessor_event_ref,
                peer: peer.clone(),
                contact_round_id: contact_round_id.clone(),
                version,
                request_event_ref: request_receipt.core.request_event_ref.clone(),
                request_acceptance_receipt_digest: canonical_contact_digest(&request_receipt)?,
                initial_contact_round_id: request_receipt.core.initial_contact_round_id.clone(),
                granted_to_peer_scopes: body.granted_to_peer_scopes.clone(),
            };
            prepare::<arkret_wire::event_spec::ContactAccepted>(
                state,
                session,
                context,
                body.operation_id,
                body.idempotency_key,
                ContactReservationBranch::Response {
                    request_receipt,
                    peer,
                    contact_round_id,
                    granted_to_peer_scopes: body.granted_to_peer_scopes,
                },
                payload,
            )
            .await
        }
        ContactAcceptRequestBody::Commit(body) => commit(state, session, body).await,
    }
}

pub(super) async fn reject(
    state: &AppState,
    session: &SessionRecord,
    body: ContactRejectRequestBody,
) -> JsonResult<ContactOperationOutcome> {
    match body {
        ContactRejectRequestBody::Prepare(body) => {
            let (context, replayed) =
                prepare_context::<arkret_wire::event_spec::ContactRejected, _>(
                    state,
                    session,
                    &body,
                    &body.idempotency_key,
                    &body.peer,
                )
                .await?;
            if let Some(outcome) = replayed {
                return json_ok(outcome);
            }
            let holder = context.holder.clone();
            let peer = body.peer.clone();
            let record = state
                .contacts()
                .contact_any(&peer.contact_actor_id(), &holder.contact_actor_id())
                .await
                .map_err(|error| AppError::internal(error.to_string()))?
                .ok_or_else(|| AppError::not_found("pending Contact request not found"))?;
            let request_receipt =
                retained_incoming_receipt(&record, &holder, &peer, &body.request_event_ref)?;
            validate_request_acceptance_receipt(state, &record, &holder, &request_receipt).await?;
            let (version, predecessor_event_ref) = next_request_slot_coordinates(
                &record.request_slot_states,
                &holder.contact_actor_id(),
                &peer.contact_actor_id(),
            )?;
            let payload = ContactRejectedPayload {
                trust_domain_id: state.config().trust_domain.clone(),
                initial_contact_round_id: request_receipt.core.initial_contact_round_id.clone(),
                version,
                predecessor_event_ref,
                peer: peer.clone(),
                request_event_ref: request_receipt.core.request_event_ref.clone(),
                request_acceptance_receipt_digest: canonical_contact_digest(&request_receipt)?,
                reason: None,
            };
            prepare::<arkret_wire::event_spec::ContactRejected>(
                state,
                session,
                context,
                body.operation_id,
                body.idempotency_key,
                ContactReservationBranch::Reject {
                    request_receipt,
                    peer,
                },
                payload,
            )
            .await
        }
        ContactRejectRequestBody::Commit(body) => commit(state, session, body).await,
    }
}

pub(super) async fn scope_update(
    state: &AppState,
    session: &SessionRecord,
    body: ContactScopeUpdateRequestBody,
) -> JsonResult<ContactOperationOutcome> {
    match body {
        ContactScopeUpdateRequestBody::Prepare(body) => {
            let (context, replayed) = prepare_context::<
                arkret_wire::event_spec::ContactScopeUpdate,
                _,
            >(
                state, session, &body, &body.idempotency_key, &body.peer
            )
            .await?;
            if let Some(outcome) = replayed {
                return json_ok(outcome);
            }
            let record = state
                .contacts()
                .contact_any(
                    &context.holder.contact_actor_id(),
                    &body.peer.contact_actor_id(),
                )
                .await
                .map_err(|e| AppError::internal(e.to_string()))?
                .ok_or_else(|| AppError::not_found("Contact missing"))?;
            let payload = ContactScopeUpdatePayload {
                trust_domain_id: state.config().trust_domain.clone(),
                initial_contact_round_id: fixed_initial(&record)?,
                schema: ContactScopeUpdateSchema::V1,
                peer: body.peer.clone(),
                contact_round_id: body.contact_round_id.clone(),
                version: body.version,
                predecessor_event_ref: body.predecessor_event_ref.clone(),
                granted_to_peer_scopes: body.granted_to_peer_scopes.clone(),
            };
            prepare::<arkret_wire::event_spec::ContactScopeUpdate>(
                state,
                session,
                context,
                body.operation_id,
                body.idempotency_key,
                ContactReservationBranch::ScopeUpdate {
                    peer: body.peer,
                    contact_round_id: body.contact_round_id,
                    version: body.version,
                    predecessor_event_ref: body.predecessor_event_ref,
                    granted_to_peer_scopes: body.granted_to_peer_scopes,
                },
                payload,
            )
            .await
        }
        ContactScopeUpdateRequestBody::Commit(body) => commit(state, session, body).await,
    }
}

pub(super) async fn tombstone(
    state: &AppState,
    session: &SessionRecord,
    body: ContactTombstoneRequestBody,
) -> JsonResult<ContactOperationOutcome> {
    match body {
        ContactTombstoneRequestBody::Prepare(body) => {
            let (context, replayed) =
                prepare_context::<arkret_wire::event_spec::ContactTombstone, _>(
                    state,
                    session,
                    &body,
                    &body.idempotency_key,
                    &body.peer,
                )
                .await?;
            if let Some(outcome) = replayed {
                return json_ok(outcome);
            }
            let record = state
                .contacts()
                .contact_any(
                    &context.holder.contact_actor_id(),
                    &body.peer.contact_actor_id(),
                )
                .await
                .map_err(|e| AppError::internal(e.to_string()))?
                .ok_or_else(|| AppError::not_found("Contact missing"))?;
            let payload = ContactTombstonedPayload {
                trust_domain_id: state.config().trust_domain.clone(),
                initial_contact_round_id: fixed_initial(&record)?,
                peer: body.peer.clone(),
                contact_round_id: body.contact_round_id.clone(),
                version: body.version,
                predecessor_event_ref: body.predecessor_event_ref.clone(),
                reason: None,
            };
            prepare::<arkret_wire::event_spec::ContactTombstone>(
                state,
                session,
                context,
                body.operation_id,
                body.idempotency_key,
                ContactReservationBranch::Tombstone {
                    peer: body.peer,
                    contact_round_id: body.contact_round_id,
                    version: body.version,
                    predecessor_event_ref: body.predecessor_event_ref,
                    block_peer: body.block_peer,
                },
                payload,
            )
            .await
        }
        ContactTombstoneRequestBody::Commit(body) => commit(state, session, body).await,
    }
}

fn normalize_contact_message(raw: Option<&str>) -> Result<Option<String>, AppError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let normalized = arkret_canonical::to_nfc(trimmed);
    if normalized.chars().count() > 2_000 {
        return Err(AppError::param_invalid(
            "Contact request message must be at most 2000 characters",
        ));
    }
    Ok(Some(normalized))
}

fn contact_mirror_target_holder_key(holder: &arkret_wire::ActorId) -> String {
    holder.signing_principal_id().to_string()
}

#[cfg(test)]
mod device_authorization_account_tests {
    use arkret_models_collaboration::contact_operations::{ContactLineage, ContactScope};
    use arkret_wire::{AccountId, ActorId, DidCoreId, EventId, Hash};

    use super::{
        ContactPeer, contact_delivery_address, contact_mirror_target_holder_key,
        device_authorization_matches_contact_account, next_request_slot_coordinates,
    };

    fn account(principal: &str, station: &str) -> ActorId {
        ActorId::account(AccountId::new(
            DidCoreId::new(principal).unwrap(),
            DidCoreId::new(station).unwrap(),
        ))
    }

    fn hash(marker: char) -> Hash {
        Hash::new(format!("sha256:{}", marker.to_string().repeat(64))).unwrap()
    }

    #[test]
    fn historical_contact_assertions_keep_two_keys_for_one_rotated_method() {
        use arkret_wire::{DidUrl, ProtocolSignature};
        use chrono::TimeZone as _;

        let state = crate::state::AppState::new(
            crate::config::AppConfig::test_default(),
            coland_storage_postgres::Db { pool: None },
        );
        let source = "ak:did_core:web:contact-peer.example";
        let method = DidUrl::new("did:web:contact-peer.example#notary-key".to_owned()).unwrap();
        let old_at = chrono::Utc.with_ymd_and_hms(2026, 9, 10, 0, 0, 0).unwrap();
        let new_at = chrono::Utc.with_ymd_and_hms(2026, 9, 11, 0, 0, 0).unwrap();
        let old_key = ed25519_dalek::SigningKey::from_bytes(&[23; 32]);
        let new_key = ed25519_dalek::SigningKey::from_bytes(&[24; 32]);
        let transcript = b"exact Contact assertion transcript";
        let signed = |key: &ed25519_dalek::SigningKey, created_at| ProtocolSignature {
            verification_method: method.clone(),
            created_at,
            jws: arkret_signatures::jws::sign_jws_ed25519(transcript, key).unwrap(),
        };
        let old_signature = signed(&old_key, old_at);
        let new_signature = signed(&new_key, new_at);
        assert!(state.install_historical_contact_assertion_key(
            method.as_str(),
            old_at,
            old_key.verifying_key(),
        ));
        assert!(state.install_historical_contact_assertion_key(
            method.as_str(),
            new_at,
            new_key.verifying_key(),
        ));
        state.install_federation_peer_verification_method_key(
            None,
            method.as_str(),
            new_key.verifying_key(),
        );
        for signature in [&old_signature, &new_signature] {
            super::verify_contact_service_signature_bytes(
                &state,
                source,
                signature,
                transcript,
                "test.rotated_contact",
            )
            .unwrap();
        }
        let mut wrong_time = old_signature.clone();
        wrong_time.created_at = new_at;
        assert!(
            super::verify_contact_service_signature_bytes(
                &state,
                source,
                &wrong_time,
                transcript,
                "test.rotated_contact",
            )
            .is_err()
        );
        let mut missing_history = old_signature.clone();
        missing_history.created_at += chrono::Duration::seconds(1);
        assert!(
            super::verify_contact_service_signature_bytes(
                &state,
                source,
                &missing_history,
                transcript,
                "test.rotated_contact",
            )
            .is_err()
        );
        assert!(!state.install_historical_contact_assertion_key(
            method.as_str(),
            old_at,
            new_key.verifying_key(),
        ));
        assert!(
            super::verify_contact_service_signature_bytes(
                &state,
                source,
                &old_signature,
                b"altered transcript",
                "test.rotated_contact",
            )
            .is_err()
        );
    }

    #[test]
    fn normal_response_requires_the_exact_unconsumed_incoming_receipt() {
        use arkret_wire::{Base64UrlString, DidUrl, ProtocolSignature};
        use coland_services::identity::ContactRecord;

        use super::{
            RequestAcceptanceReceipt, retained_incoming_receipt, validate_normal_response_slot,
        };

        for peer_station in [
            "ak:did_core:web:station.example",
            "ak:did_core:web:remote.example",
        ] {
            use arkret_models_collaboration::contact_operations::{
                ContactProducerSigner, RequestAcceptanceReceiptCore,
            };

            let source_key = ed25519_dalek::SigningKey::from_bytes(&[31; 32]);
            let holder_key = ed25519_dalek::SigningKey::from_bytes(&[29; 32]);
            let accepted_at = chrono::DateTime::parse_from_rfc3339("2026-09-09T00:00:00.000Z")
                .unwrap()
                .with_timezone(&chrono::Utc);
            let core = RequestAcceptanceReceiptCore {
                trust_domain_id: arkret_wire::TrustDomainId::new("ak:trust_domain:contact.test")
                    .unwrap(),
                holder: ContactPeer::Human {
                    account_id: AccountId::new(
                        DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                        DidCoreId::new(peer_station).unwrap(),
                    ),
                },
                peer: ContactPeer::Human {
                    account_id: AccountId::new(
                        DidCoreId::new("ak:did_core:web:bob.example").unwrap(),
                        DidCoreId::new("ak:did_core:web:station.example").unwrap(),
                    ),
                },
                version: 1,
                predecessor_event_ref: None,
                initial_contact_round_id: None,
                request_event_ref: EventId::new(
                    "ak:event:AQ0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                )
                .unwrap(),
                producer_signer: ContactProducerSigner::direct(
                    DidUrl::new("did:web:alice.example#device").unwrap(),
                    Base64UrlString::new(arkret_canonical::base64url_encode(
                        holder_key.verifying_key().to_bytes(),
                    ))
                    .unwrap(),
                )
                .unwrap(),
                source_checkpoint: hash('a'),
                accepted_at,
                issuer_id: DidCoreId::new(peer_station).unwrap(),
            };
            let receipt = RequestAcceptanceReceipt::sign_with(core, |bytes| {
                Ok(ProtocolSignature {
                    verification_method: DidUrl::new(format!(
                        "did:web:{}#signing",
                        peer_station.strip_prefix("ak:did_core:web:").unwrap()
                    ))
                    .unwrap(),
                    created_at: accepted_at,
                    jws: arkret_signatures::sign_ed25519_detached_jws(&source_key, bytes).unwrap(),
                })
            })
            .unwrap();
            arkret_signatures::contact_receipt::verify_contact_request_acceptance_receipt(
                &receipt,
                &receipt.core.request_event_ref,
                &source_key.verifying_key(),
            )
            .unwrap();
            let record = ContactRecord {
                requester_id: receipt.core.holder.contact_actor_id(),
                target_id: receipt.core.peer.contact_actor_id(),
                contact_round_id: None,
                granted_to_target_scopes: Vec::new(),
                granted_to_requester_scopes: Vec::new(),
                status: "pending".to_owned(),
                pending_incoming_admitted: true,
                request_event_ref: Some(receipt.core.request_event_ref.clone()),
                request_slot_states: Vec::new(),
                request_receipts: vec![receipt.clone()],
                request_mirror_receipts: Vec::new(),
                contact_round_evidence: None,
                current_state: Default::default(),

                response_event_ref: None,
                tombstone_event_ref: None,
                message: None,
                peer_host_id: Some(receipt.core.issuer_id.clone()),
                peer_service_resolution: None,
                created_at: receipt.core.accepted_at,
                updated_at: receipt.core.accepted_at,
            };
            let responder = &receipt.core.peer;
            assert_eq!(
                retained_incoming_receipt(
                    &record,
                    responder,
                    &receipt.core.holder,
                    &receipt.core.request_event_ref
                )
                .unwrap(),
                receipt
            );
            assert!(
                retained_incoming_receipt(
                    &record,
                    &receipt.core.holder,
                    responder,
                    &receipt.core.request_event_ref
                )
                .is_err()
            );
            let mut unadmitted = record.clone();
            unadmitted.pending_incoming_admitted = false;
            assert!(
                retained_incoming_receipt(
                    &unadmitted,
                    responder,
                    &receipt.core.holder,
                    &receipt.core.request_event_ref
                )
                .is_err()
            );
            validate_normal_response_slot(&record, responder, &receipt).unwrap();
            assert!(
                validate_normal_response_slot(&record, &receipt.core.holder, &receipt).is_err()
            );

            let mut reverse = receipt.clone();
            std::mem::swap(&mut reverse.core.holder, &mut reverse.core.peer);
            reverse.core.request_event_ref = arkret_wire::EventId::new(
                "ak:event:AQYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            )
            .unwrap();
            let mut glare = record.clone();
            assert!(
                retained_incoming_receipt(
                    &record,
                    responder,
                    &receipt.core.holder,
                    &reverse.core.request_event_ref
                )
                .is_err()
            );
            glare.request_receipts.push(reverse);
            assert!(
                retained_incoming_receipt(
                    &glare,
                    responder,
                    &receipt.core.holder,
                    &receipt.core.request_event_ref
                )
                .is_err()
            );
            assert!(validate_normal_response_slot(&glare, responder, &receipt).is_err());

            let mut changed = record.clone();
            changed.request_receipts[0].signature.jws = "ZGVm".to_owned();
            assert!(validate_normal_response_slot(&changed, responder, &receipt).is_err());
            changed.request_receipts.clear();
            assert!(validate_normal_response_slot(&changed, responder, &receipt).is_err());

            for status in ["accepted", "rejected", "tombstoned"] {
                let mut consumed = record.clone();
                consumed.status = status.to_owned();
                assert!(
                    retained_incoming_receipt(
                        &consumed,
                        responder,
                        &receipt.core.holder,
                        &receipt.core.request_event_ref
                    )
                    .is_err()
                );
                assert!(validate_normal_response_slot(&consumed, responder, &receipt).is_err());
            }
        }
    }

    #[tokio::test]
    async fn contact_locator_route_requires_the_exact_recipient_account() {
        use arkret_models_collaboration::contact_operations::ContactPeer;
        use arkret_models_collaboration::governance::peer_contact::ContactIntroductionEvidence;
        use coland_storage_postgres::Db;

        let state = crate::state::AppState::new(
            crate::config::AppConfig::test_default(),
            Db { pool: None },
        );
        let account_id = AccountId::new(
            DidCoreId::new("ak:did_core:web:bob.example").unwrap(),
            DidCoreId::new("ak:did_core:web:remote.example").unwrap(),
        );
        let evidence: ContactIntroductionEvidence = serde_json::from_value(serde_json::json!({
            "kind": "locator_ref",
            "principal_locator": {
                "schema": "ak.schema.principal_locator.v1",
                "account_id": account_id,
                "service_resolution": {
                    "resolution_url": "https://remote.example/_arkret/open/services/ak%3Adid_core%3Aweb%3Aremote.example/resolution"
                },
                "issued_at": "2026-09-08T00:00:00.000Z",
                "expires_at": "2026-09-08T00:15:00.000Z",
                "locator_ref_digest": hash('a'),
                "proofs": []
            }
        })).unwrap();
        let peer = ContactPeer::Human {
            account_id: account_id.clone(),
        };
        let address = contact_delivery_address(&state, &peer, Some(&evidence))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(address.recipient, peer);
        assert_eq!(address.delivery_station_id(), &account_id.station_id);

        for wrong_account in [
            AccountId::new(
                DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                account_id.station_id.clone(),
            ),
            AccountId::new(
                account_id.principal_id.clone(),
                DidCoreId::new("ak:did_core:web:other.example").unwrap(),
            ),
        ] {
            assert!(
                contact_delivery_address(
                    &state,
                    &ContactPeer::Human {
                        account_id: wrong_account
                    },
                    Some(&evidence),
                )
                .await
                .is_err()
            );
        }
    }

    #[test]
    fn same_service_contact_mirror_uses_the_session_principal_lookup_key() {
        let holder = account(
            "ak:did_core:web:bob.example",
            "ak:did_core:web:station.example",
        );
        assert_eq!(
            contact_mirror_target_holder_key(&holder),
            "ak:did_core:web:bob.example"
        );
        assert_ne!(
            contact_mirror_target_holder_key(&holder),
            holder.to_string()
        );
    }

    #[test]
    fn contact_device_authorization_preserves_the_exact_account_and_actor_branch() {
        let principal = DidCoreId::new("ak:did_core:web:alice.example").unwrap();
        let station = DidCoreId::new("ak:did_core:web:station-a.example").unwrap();
        let account = AccountId::new(principal.clone(), station.clone());
        assert!(device_authorization_matches_contact_account(
            &ActorId::account(account.clone()).canonical_key().unwrap(),
            &account,
        ));
        let foreign = AccountId::new(
            principal.clone(),
            DidCoreId::new("ak:did_core:web:station-b.example").unwrap(),
        );
        for actor in [
            ActorId::account(foreign),
            ActorId::service(principal.clone()),
        ] {
            assert!(!device_authorization_matches_contact_account(
                &actor.canonical_key().unwrap(),
                &account,
            ));
        }
        assert!(!device_authorization_matches_contact_account(
            principal.as_str(),
            &account,
        ));
    }

    fn cursor_event(
        version: u64,
        predecessor: Option<EventId>,
        peer: &ActorId,
    ) -> arkret_wire::Event {
        let holder = account(
            "ak:did_core:web:alice.example",
            "ak:did_core:web:station.example",
        );
        let mut payload = serde_json::json!({"peer":ContactPeer::Human{account_id:peer.as_account_id().unwrap().clone()},"version":version});
        if let Some(pred) = predecessor {
            payload["predecessor_event_ref"] = serde_json::json!(pred);
        }
        serde_json::from_value(serde_json::json!({"event_id":EventId::from_digest(arkret_canonical::DigestSuite::Sha256,[version as u8;32]),"kind":"ak.contact.requested","actor_id":holder,"created_at":"2026-10-21T00:00:00.000Z","realm_id":"ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19","scope_ref":{"kind":"realm","realm_id":"ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"},"payload":payload})).unwrap()
    }
    #[test]
    fn request_slot_coordinates_preserve_each_full_direction_and_lifetime_version() {
        let alice = account(
            "ak:did_core:web:alice.example",
            "ak:did_core:web:station.example",
        );
        let bob = account(
            "ak:did_core:web:bob.example",
            "ak:did_core:web:station.example",
        );
        let head = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [7; 32]);
        let slots = vec![coland_services::identity::ContactRequestSlotState {
            owner_id: alice.clone(),
            peer_id: bob.clone(),
            version: 73,
            head_event_ref: head.clone(),
            operation_digest: None,
            request_choice: None,
        }];
        assert_eq!(
            next_request_slot_coordinates(&slots, &alice, &bob).unwrap(),
            (74, Some(head))
        );
        assert_eq!(
            next_request_slot_coordinates(&slots, &bob, &alice).unwrap(),
            (1, None)
        );
        let another = account(
            "ak:did_core:web:bob.example",
            "ak:did_core:web:elsewhere.example",
        );
        assert_eq!(
            next_request_slot_coordinates(&slots, &alice, &another).unwrap(),
            (1, None)
        );
    }
    #[test]
    fn operation_cursor_rejects_stale_or_wrong_predecessor_before_mutation() {
        use coland_services::identity::ContactRecord;
        let alice = account(
            "ak:did_core:web:alice.example",
            "ak:did_core:web:station.example",
        );
        let bob = account(
            "ak:did_core:web:bob.example",
            "ak:did_core:web:station.example",
        );
        let at = chrono::Utc::now();
        let mut record = ContactRecord {
            requester_id: alice.clone(),
            target_id: bob.clone(),
            contact_round_id: None,
            granted_to_target_scopes: vec![],
            granted_to_requester_scopes: vec![],
            status: "tombstoned".into(),
            pending_incoming_admitted: false,
            request_event_ref: None,
            request_slot_states: vec![coland_services::identity::ContactRequestSlotState {
                owner_id: alice,
                peer_id: bob.clone(),
                version: 7,
                head_event_ref: EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [7; 32],
                ),
                operation_digest: None,
                request_choice: None,
            }],
            request_receipts: vec![],
            request_mirror_receipts: vec![],
            contact_round_evidence: None,
            current_state: Default::default(),

            response_event_ref: None,
            tombstone_event_ref: None,
            message: None,
            peer_host_id: None,
            peer_service_resolution: None,
            created_at: at,
            updated_at: at,
        };
        let original = record.request_slot_states.clone();
        for event in [
            cursor_event(7, Some(original[0].head_event_ref.clone()), &bob),
            cursor_event(
                8,
                Some(EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [4; 32],
                )),
                &bob,
            ),
        ] {
            assert!(super::advance_contact_operation_cursor(&mut record, &event).is_err());
            assert_eq!(record.request_slot_states, original);
        }
        super::advance_contact_operation_cursor(
            &mut record,
            &cursor_event(8, Some(original[0].head_event_ref.clone()), &bob),
        )
        .unwrap();
        assert_eq!(record.request_slot_states[0].version, 8);
    }
    #[test]
    fn lineage_signatures_cover_exact_wire_presence_for_initial_successor_and_terminal() {
        let state = crate::state::AppState::new(
            crate::config::AppConfig::test_default(),
            coland_storage_postgres::Db { pool: None },
        );
        let holder = ContactPeer::Human {
            account_id: AccountId::new(
                DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                state.service_core_id(),
            ),
        };
        let peer = ContactPeer::Human {
            account_id: AccountId::new(
                DidCoreId::new("ak:did_core:web:bob.example").unwrap(),
                DidCoreId::new("ak:did_core:web:remote.example").unwrap(),
            ),
        };
        let predecessor = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [1; 32]);
        let event = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [2; 32]);
        for (version, previous, terminal) in [
            (1, None, false),
            (2, Some(predecessor.clone()), false),
            (2, Some(predecessor), true),
        ] {
            let lineage = super::signed_lineage(
                &state,
                holder.clone(),
                peer.clone(),
                hash('a'),
                version,
                previous.clone(),
                event.clone(),
                if terminal {
                    Vec::new()
                } else {
                    vec![ContactScope::DirectMessage]
                },
                terminal,
            )
            .unwrap();
            let wire = serde_json::to_value(&lineage).unwrap();
            assert_eq!(
                wire.get("predecessor_event_ref").is_some(),
                previous.is_some()
            );
            assert!(wire.get("terminal").is_none());
            let roundtrip: ContactLineage = serde_json::from_value(wire).unwrap();
            super::verify_contact_service_signature_bytes(
                &state,
                state.service_id(),
                &roundtrip.signature,
                &roundtrip.canonical_signing_bytes().unwrap(),
                "test.lineage",
            )
            .unwrap();
            let mut tampered = roundtrip;
            tampered.granted_to_peer_scopes.push(ContactScope::Presence);
            assert!(
                super::verify_contact_service_signature_bytes(
                    &state,
                    state.service_id(),
                    &tampered.signature,
                    &tampered.canonical_signing_bytes().unwrap(),
                    "test.lineage",
                )
                .is_err()
            );
        }
    }

    /// Real PostgreSQL: a receipt signed by the production Contact transcript
    /// signer is a compact detached JWS that survives the durable row and
    /// verifies after lookup; the retired bare base64url signature neither
    /// reads back from the row nor verifies.
    #[tokio::test]
    async fn production_contact_receipt_signature_is_detached_jws_through_postgres() {
        use arkret_models_collaboration::contact_operations::{
            ContactProducerSigner, RequestAcceptanceReceiptCore,
        };
        use arkret_wire::{Base64UrlString, DidUrl};
        use base64::Engine as _;
        use coland_storage::ContactStore as _;
        use coland_storage_postgres::PgContactStore;
        use coland_storage_postgres::test_database::TestDatabase;

        use super::{RequestAcceptanceReceipt, validate_request_receipt_cryptography};

        let state = crate::state::AppState::new(
            crate::config::AppConfig::test_default(),
            coland_storage_postgres::Db { pool: None },
        );
        let holder_key = ed25519_dalek::SigningKey::from_bytes(&[29; 32]);
        let accepted_at = chrono::DateTime::parse_from_rfc3339("2026-09-09T00:00:00.000Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let core = RequestAcceptanceReceiptCore {
            trust_domain_id: arkret_wire::TrustDomainId::new("ak:trust_domain:contact.test")
                .unwrap(),
            holder: ContactPeer::Human {
                account_id: AccountId::new(
                    DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                    state.service_core_id(),
                ),
            },
            peer: ContactPeer::Human {
                account_id: AccountId::new(
                    DidCoreId::new("ak:did_core:web:bob.example").unwrap(),
                    DidCoreId::new("ak:did_core:web:remote.example").unwrap(),
                ),
            },
            version: 1,
            predecessor_event_ref: None,
            initial_contact_round_id: None,
            request_event_ref: EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [9; 32]),
            producer_signer: ContactProducerSigner::direct(
                DidUrl::new("did:web:alice.example#device").unwrap(),
                Base64UrlString::new(arkret_canonical::base64url_encode(
                    holder_key.verifying_key().to_bytes(),
                ))
                .unwrap(),
            )
            .unwrap(),
            source_checkpoint: hash('a'),
            accepted_at,
            issuer_id: state.service_core_id(),
        };
        let receipt = RequestAcceptanceReceipt::sign_with(core, |bytes| {
            super::sign_contact_transcript(&state, bytes)
                .map_err(|error| arkret_wire::WireError::Protocol(error.to_string()))
        })
        .unwrap();
        assert!(arkret_wire::is_compact_detached_jws(&receipt.signature.jws));
        arkret_signatures::contact_receipt::verify_contact_request_acceptance_receipt(
            &receipt,
            &receipt.core.request_event_ref,
            &state.notary_verifying_key(),
        )
        .unwrap();

        let record = |receipt: RequestAcceptanceReceipt| coland_storage::ContactRecord {
            requester_id: receipt.core.holder.contact_actor_id(),
            target_id: receipt.core.peer.contact_actor_id(),
            contact_round_id: None,
            granted_to_target_scopes: Vec::new(),
            granted_to_requester_scopes: Vec::new(),
            status: "pending".to_owned(),
            pending_incoming_admitted: false,
            request_event_ref: Some(receipt.core.request_event_ref.clone()),
            request_slot_states: Vec::new(),
            request_receipts: vec![receipt.clone()],
            request_mirror_receipts: Vec::new(),
            contact_round_evidence: None,
            current_state: Default::default(),

            response_event_ref: None,
            tombstone_event_ref: None,
            message: None,
            peer_host_id: None,
            peer_service_resolution: None,
            created_at: receipt.core.accepted_at,
            updated_at: receipt.core.accepted_at,
        };
        let database = TestDatabase::lease().await;
        let contacts = PgContactStore {
            pool: database.pool(),
        };
        let holder = receipt.core.holder.contact_actor_id();
        let peer = receipt.core.peer.contact_actor_id();

        contacts.put(&record(receipt.clone())).await.unwrap();
        let stored = contacts.get(&holder, &peer).await.unwrap().unwrap();
        assert_eq!(
            serde_json::to_value(&stored.request_receipts).unwrap(),
            serde_json::to_value([&receipt]).unwrap()
        );
        validate_request_receipt_cryptography(&state, &stored.request_receipts[0], "test.receipt")
            .unwrap();

        // The same Ed25519 bytes as a bare base64url string are the retired
        // shape: the verifier rejects them and a durable row carrying them
        // fails closed on lookup instead of being reinterpreted.
        let signature = receipt
            .signature
            .jws
            .rsplit('.')
            .next()
            .map(|segment| arkret_canonical::base64url_decode(segment).unwrap())
            .unwrap();
        let mut bare = receipt;
        bare.signature.jws = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature);
        assert!(validate_request_receipt_cryptography(&state, &bare, "test.receipt").is_err());
        contacts.put(&record(bare)).await.unwrap();
        assert!(contacts.get(&holder, &peer).await.is_err());
    }
}
