//! Source projection signatures are issued only for durable committed Events.
use coland_storage::{
    CommittedContactCompletionIntent, ContactCompletionBinding, ContactCompletionIntent,
    ContactCompletionResult,
};

use super::*;

pub(super) async fn resolve_completion(
    state: &AppState,
    binding: &ContactCompletionBinding,
) -> JsonResult<ContactOperationOutcome> {
    materialize_contact_completions(state).await?;
    let result = state
        .persistence()
        .contact_completion_for_request(
            &binding.authenticated_actor,
            &binding.idempotency_key,
            &binding.request_hash,
        )
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .and_then(|state| state.result);
    match result {
        Some(ContactCompletionResult::Accepted { outcome }) => {
            json_ok(ContactOperationOutcome::Accepted { outcome: *outcome })
        }
        Some(ContactCompletionResult::Rejected { problem }) => {
            Err(AppError::from_frozen_problem(problem))
        }
        None => Err(crate::app_error!(
            TemporarilyUnavailable,
            "Contact command is awaiting confirmed completion"
        )),
    }
}

pub(crate) async fn materialize_contact_completions(state: &AppState) -> Result<(), AppError> {
    let mut after = None;
    loop {
        let ready = state
            .persistence()
            .committed_contact_completion_intents(64, after.as_ref())
            .await
            .map_err(|error| AppError::internal(error.to_string()))?;
        let Some(last) = ready.last() else {
            break;
        };
        after = Some(last.event_digest.clone());
        // Continue past incomplete histories: one peer's missing evidence must
        // not starve unrelated committed commands behind the first page.
        for item in &ready {
            if let Err(error) = Box::pin(materialize_one(state, item)).await {
                tracing::warn!(event_id=%item.intent.plan.event.event_id,error=%error,"Contact committed completion remains pending");
            }
        }
        if ready.len() < 64 {
            break;
        }
    }
    Ok(())
}
async fn materialize_one(
    state: &AppState,
    ready: &CommittedContactCompletionIntent,
) -> Result<(), AppError> {
    let committed = state
        .persistence()
        .committed_event(&ready.committed_ref.event_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| {
            crate::app_error!(
                TemporarilyUnavailable,
                "Contact command evidence is unavailable"
            )
        })?;
    if committed.event != ready.intent.plan.event
        || committed.event.event_id.event_digest() != ready.event_digest
        || committed.commit.commit_id != ready.committed_ref.commit_id
        || committed.commit.stream_ref != ready.committed_ref.stream_ref
        || committed.commit.stream_position != ready.committed_ref.stream_position
        || committed.commit.event_ref != ready.committed_ref.event_id
    {
        return Err(crate::app_error!(
            FailedPrecondition,
            "Contact source signature requires the exact committed command"
        ));
    }
    let outcome = Box::pin(sign_outcome(state, &ready.intent)).await?;
    // A normal round whose requester is also this Station's holder completes
    // both directions here: the requester's own request is its direction head.
    // A local tombstone also confirms the opposite direction's terminal fence.
    let counterpart_proof = match &outcome {
        ContactAcceptedOutcome::Request {
            request_acceptance_receipt,
            ..
        } => {
            let peer = &request_acceptance_receipt.core.peer;
            let record = state
                .contacts()
                .contact_any(
                    &ready.intent.plan.holder.contact_actor_id(),
                    &peer.contact_actor_id(),
                )
                .await
                .map_err(|e| AppError::internal(e.to_string()))?
                .ok_or_else(|| AppError::internal("Contact source row unavailable"))?;
            let mut current = record.current_state.clone();
            current
                .apply_confirmed(ContactOperationEvidence::Request {
                    signed_event: ready.intent.plan.event.clone(),
                    request_receipt: request_acceptance_receipt.clone(),
                })
                .map_err(|e| AppError::internal(e.to_string()))?;
            Some(
                Box::pin(
                    crate::routing::identity::contact_federation::refresh_local_contact_direction(
                        state,
                        &current,
                        &ready.intent.plan.holder,
                    ),
                )
                .await?,
            )
        }
        ContactAcceptedOutcome::Response {
            normal_response_acceptance_receipt,
            ..
        } => {
            Box::pin(super::local_requester_current_proof(
                state,
                &normal_response_acceptance_receipt.contact_round_id,
                &normal_response_acceptance_receipt.request_receipt,
            ))
            .await?
        }
        _ => None,
    };
    let delivery = if ready.intent.requires_delivery() {
        let target = &ready.intent.plan.target;
        let mut carrier = ready
            .intent
            .finalized_carrier(&outcome)
            .map_err(|error| AppError::internal(error.to_string()))?;
        if let arkret_models_collaboration::contact_operations::PeerContactSubmitRequestBody::Request{current_proof,..}=&mut carrier {*current_proof=counterpart_proof.clone();}
        let row = crate::routing::identity::contact_federation::prepare_peer_contact_carrier(
            state,
            target.contact_address.delivery_station_id().as_str(),
            &carrier,
        )
        .await?
        .ok_or_else(|| AppError::internal("remote Contact completion has no delivery"))?;
        Some(coland_storage::FederationOutboxRecord::pending(
            row.id,
            row.peer_id,
            row.peer_url
                .ok_or_else(|| AppError::internal("Contact delivery route missing"))?,
            row.endpoint,
            row.idempotency_key,
            row.payload_json,
            row.created_at,
        ))
    } else {
        None
    };
    state
        .persistence()
        .finalize_contact_completion_intent(
            ready,
            &ContactCompletionResult::Accepted {
                outcome: Box::new(outcome.clone()),
            },
            delivery.as_ref(),
            counterpart_proof.as_ref(),
        )
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    if let ContactAcceptedOutcome::Request {
        request_acceptance_receipt,
        ..
    } = &outcome
        && request_acceptance_receipt
            .core
            .peer
            .delivery_station_id()
            .as_str()
            == state.service_id()
    {
        Box::pin(
            crate::routing::identity::contact_federation::enqueue_glare_finalize_if_ready(
                state,
                &ready.intent.plan.holder.contact_actor_id(),
                &request_acceptance_receipt.core.peer.contact_actor_id(),
            ),
        )
        .await?;
    }
    Ok(())
}
async fn sign_outcome(
    state: &AppState,
    intent: &ContactCompletionIntent,
) -> Result<ContactAcceptedOutcome, AppError> {
    use coland_storage::ContactCompletionAction;
    let error = |error: arkret_wire::WireError| AppError::internal(error.to_string());
    let accepted_at = intent
        .accepted_at()
        .map_err(|error| AppError::internal(error.to_string()))?;
    let event = &intent.plan.event;
    let operation_id = intent.plan.operation_id.clone();
    let producer = intent.producer_signer.clone();
    let issuer = state.service_core_id();
    // Receipt signatures refer to the actual durable slot-acceptance instant.
    // Lineage and refreshed checkpoint signatures use their actual signing time.
    let receipt_key = if matches!(
        intent.plan.action,
        ContactCompletionAction::Request { .. }
            | ContactCompletionAction::Response { .. }
            | ContactCompletionAction::Reject { .. }
    ) {
        Some(receipt_key_at_acceptance(state, accepted_at).await?)
    } else {
        None
    };
    let sign_receipt = |bytes: &[u8]| -> arkret_wire::Result<ProtocolSignature> {
        let (method, key) = receipt_key.as_ref().ok_or_else(|| {
            arkret_wire::WireError::Protocol("Contact receipt signing key missing".into())
        })?;
        Ok(ProtocolSignature {
            verification_method: method.clone(),
            created_at: now(),
            jws: super::contact_detached_jws(key, bytes)
                .map_err(|error| arkret_wire::WireError::Protocol(error.to_string()))?,
        })
    };
    let lineage_at = now();
    let (lineage_method, lineage_key) = receipt_key_at_acceptance(state, lineage_at).await?;
    let sign_lineage = |bytes: &[u8]| -> arkret_wire::Result<ProtocolSignature> {
        Ok(ProtocolSignature {
            verification_method: lineage_method.clone(),
            created_at: lineage_at,
            jws: super::contact_detached_jws(&lineage_key, bytes)
                .map_err(|error| arkret_wire::WireError::Protocol(error.to_string()))?,
        })
    };
    Ok(match &intent.plan.action {
        ContactCompletionAction::Request { .. } => ContactAcceptedOutcome::Request {
            operation_id,
            request_acceptance_receipt: RequestAcceptanceReceipt::sign_with(
                intent
                    .request_receipt_core()
                    .map_err(|error| AppError::internal(error.to_string()))?,
                sign_receipt,
            )
            .map_err(error)?,
        },
        ContactCompletionAction::Response {
            request_receipt,
            absence,
        } => {
            let payload: ContactAcceptedPayload = serde_json::from_value(
                serde_json::to_value(&event.payload)
                    .map_err(|error| AppError::internal(error.to_string()))?,
            )
            .map_err(|error| AppError::internal(error.to_string()))?;
            let receipt = NormalResponseAcceptanceReceipt::sign_with(
                payload.trust_domain_id.clone(),
                payload.initial_contact_round_id.clone(),
                payload.version,
                payload.predecessor_event_ref.clone(),
                payload.contact_round_id.clone(),
                request_receipt.as_ref().clone(),
                event.event_id.clone(),
                producer.clone(),
                absence.digest().map_err(error)?,
                accepted_at,
                issuer,
                sign_receipt,
            )
            .map_err(error)?;
            let lineage = ContactLineage::sign_with(
                payload.trust_domain_id.clone(),
                payload.initial_contact_round_id.clone(),
                Some(payload.contact_round_id.clone()),
                intent.plan.holder.clone(),
                payload.peer.clone(),
                payload.version,
                payload.predecessor_event_ref.clone(),
                event.event_id.clone(),
                producer,
                payload.granted_to_peer_scopes,
                accepted_at,
                sign_lineage,
            )
            .map_err(error)?;
            let current_proof = Box::pin(latest_direction_proof(
                state,
                intent,
                &payload.contact_round_id,
                &payload.peer,
                None,
            ))
            .await?;
            ContactAcceptedOutcome::Response {
                operation_id,
                normal_response_acceptance_receipt: receipt,
                lineage,
                current_proof,
            }
        }
        ContactCompletionAction::Reject { request_receipt } => ContactAcceptedOutcome::Reject {
            operation_id,
            reject_acceptance_receipt: RejectAcceptanceReceipt::sign_with(
                state.config().trust_domain.clone(),
                serde_json::from_value::<ContactRejectedPayload>(
                    serde_json::to_value(&event.payload)
                        .map_err(|e| AppError::internal(e.to_string()))?,
                )
                .map_err(|e| AppError::internal(e.to_string()))?
                .initial_contact_round_id,
                event
                    .payload
                    .get("version")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| AppError::internal("Contact reject version missing"))?,
                event
                    .payload
                    .get("predecessor_event_ref")
                    .cloned()
                    .map(serde_json::from_value)
                    .transpose()
                    .map_err(|e| AppError::internal(e.to_string()))?,
                request_receipt.as_ref().clone(),
                event.event_id.clone(),
                producer,
                accepted_at,
                issuer,
                sign_receipt,
            )
            .map_err(error)?,
        },
        ContactCompletionAction::ScopeUpdate => {
            let payload: ContactScopeUpdatePayload = serde_json::from_value(
                serde_json::to_value(&event.payload)
                    .map_err(|error| AppError::internal(error.to_string()))?,
            )
            .map_err(|error| AppError::internal(error.to_string()))?;
            let lineage = ContactLineage::sign_with(
                payload.trust_domain_id.clone(),
                Some(payload.initial_contact_round_id.clone()),
                Some(payload.contact_round_id.clone()),
                intent.plan.holder.clone(),
                payload.peer.clone(),
                payload.version,
                Some(payload.predecessor_event_ref),
                event.event_id.clone(),
                producer,
                payload.granted_to_peer_scopes,
                accepted_at,
                sign_lineage,
            )
            .map_err(error)?;
            let current_proof = Box::pin(latest_direction_proof(
                state,
                intent,
                &payload.contact_round_id,
                &payload.peer,
                None,
            ))
            .await?;
            ContactAcceptedOutcome::ScopeUpdate {
                operation_id,
                lineage,
                current_proof,
            }
        }
        ContactCompletionAction::Tombstone => {
            let payload: ContactTombstonedPayload = serde_json::from_value(
                serde_json::to_value(&event.payload)
                    .map_err(|error| AppError::internal(error.to_string()))?,
            )
            .map_err(|error| AppError::internal(error.to_string()))?;
            let lineage = ContactLineage::sign_with(
                payload.trust_domain_id.clone(),
                Some(payload.initial_contact_round_id.clone()),
                Some(payload.contact_round_id.clone()),
                intent.plan.holder.clone(),
                payload.peer.clone(),
                payload.version,
                Some(payload.predecessor_event_ref),
                event.event_id.clone(),
                producer,
                Vec::new(),
                accepted_at,
                sign_lineage,
            )
            .map_err(error)?;
            let current_proof = Box::pin(latest_direction_proof(
                state,
                intent,
                &payload.contact_round_id,
                &payload.peer,
                Some(ContactRoundClosure {
                    contact_round_id: payload.contact_round_id.clone(),
                    operation: ContactTombstoneEvidence {
                        kind: ContactTombstoneEvidenceKind::Tombstone,
                        signed_event: event.clone(),
                        lineage: lineage.clone(),
                    },
                }),
            ))
            .await?;
            ContactAcceptedOutcome::Tombstone {
                operation_id,
                lineage,
                current_proof,
            }
        }
    })
}
async fn latest_direction_proof(
    state: &AppState,
    intent: &ContactCompletionIntent,
    round_id: &Hash,
    direction_peer: &ContactPeer,
    closure: Option<ContactRoundClosure>,
) -> Result<ContactCurrentProof, AppError> {
    let holder = &intent.plan.event.actor_id;
    let peer = direction_peer.contact_actor_id();
    let record = if let Some(record) = state
        .contacts()
        .contact_any(holder, &peer)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
    {
        record
    } else {
        state
            .contacts()
            .contact_any(&peer, holder)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
            .ok_or_else(|| {
                crate::app_error!(
                    TemporarilyUnavailable,
                    "Contact source projection is unavailable"
                )
            })?
    };
    if record.contact_round_id.as_ref() != Some(round_id) {
        return Err(crate::app_error!(
            TemporarilyUnavailable,
            "Contact current round is unavailable"
        ));
    }
    let head = record
        .request_slot_states
        .iter()
        .find(|slot| slot.owner_id == *holder)
        .map(|slot| &slot.head_event_ref)
        .ok_or_else(|| {
            crate::app_error!(
                TemporarilyUnavailable,
                "Contact own current head unavailable"
            )
        })?;
    let committed = state
        .persistence()
        .committed_event(head)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| {
            crate::app_error!(
                TemporarilyUnavailable,
                "Contact current head confirmation is unavailable"
            )
        })?;
    if &committed.event.event_id != head
        || committed.event.actor_id != *holder
        || committed.commit.event_ref != *head
    {
        return Err(crate::app_error!(
            TemporarilyUnavailable,
            "Contact local directional history is incomplete"
        ));
    }
    let next = Box::pin(signed_current_proof(
        state,
        round_id.clone(),
        intent.plan.holder.clone(),
        direction_peer.clone(),
        closure,
        &committed.event,
        committed
            .event
            .event_id
            .event_digest()
            .digest_suite()
            .map_err(|error| AppError::internal(error.to_string()))?,
    ))
    .await?;
    Ok(next)
}

pub(super) async fn receipt_key_at_acceptance(
    state: &AppState,
    accepted_at: chrono::DateTime<chrono::Utc>,
) -> Result<(DidUrl, ed25519_dalek::SigningKey), AppError> {
    let history = state
        .dids()
        .resolve_webvh_state_at(&state.service_did(), accepted_at)
        .await
        .map_err(|error| {
            crate::app_error!(
                TemporarilyUnavailable,
                format!("Contact historical assertion state unavailable: {error}")
            )
        })?;
    let methods = receipt_assertion_methods(history.document)?;
    let current = state.notary_signing_key();
    if let Some((method, _)) = methods
        .iter()
        .find(|(_, public)| public == current.verifying_key().as_bytes())
    {
        return Ok((method.clone(), current.as_ref().clone()));
    }
    let identity = state
        .stored_service_identity()
        .await
        .map_err(AppError::internal)?;
    let config = state.config().clone();
    tokio::task::spawn_blocking(move || {
        load_retained_receipt_key(&methods, &config, &identity.identity.signing_key_refs)
    })
    .await
    .map_err(|error| AppError::internal(error.to_string()))?
    .map_err(|error| crate::app_error!(TemporarilyUnavailable, error))
}

fn receipt_assertion_methods(
    document: serde_json::Value,
) -> Result<Vec<(DidUrl, [u8; 32])>, AppError> {
    let document: arkret_models_identity::service_identity::ServiceDidDocument =
        serde_json::from_value(document).map_err(|error| AppError::internal(error.to_string()))?;
    document
        .verification_method
        .iter()
        .filter(|method| document.assertion_method.contains(&method.id))
        .map(|method| {
            Ok((
                DidUrl::new(method.id.clone())
                    .map_err(|error| AppError::internal(error.to_string()))?,
                arkret_canonical::decode_ed25519_multibase(&method.public_key_multibase)
                    .map_err(|error| AppError::internal(error.to_string()))?,
            ))
        })
        .collect()
}

// The only production caller supplies methods selected from the authenticated
// historical DID state. Loading a secret does not grant that key authority.
fn load_retained_receipt_key(
    methods: &[(DidUrl, [u8; 32])],
    config: &crate::config::AppConfig,
    references: &[arkret_identity::service_identity::DidCoreIdentityKeyRef],
) -> Result<(DidUrl, ed25519_dalek::SigningKey), String> {
    let store = config
        .key_store
        .open(crate::config::SERVICE_IDENTITY_KEYSTORE_APP)
        .map_err(|error| error.to_string())?;
    for reference in references {
        let seed = if reference.as_str() == crate::config::CONFIGURED_SIGNING_KEY_REF {
            config.notary_signing_key_seed.map(|seed| seed.to_vec())
        } else {
            store
                .as_ref()
                .and_then(|store| store.load(reference.as_str()).ok())
                .map(|bytes| bytes.to_vec())
        };
        let Some(seed) = seed else {
            continue;
        };
        let seed = zeroize::Zeroizing::new(seed);
        let Ok(seed): Result<&[u8; 32], _> = seed.as_slice().try_into() else {
            continue;
        };
        let key = ed25519_dalek::SigningKey::from_bytes(seed);
        if let Some((method, _)) = methods
            .iter()
            .find(|(_, public)| public == key.verifying_key().as_bytes())
        {
            return Ok((method.clone(), key));
        }
    }
    Err("Contact historical assertion private key is unavailable".into())
}

#[cfg(test)]
mod tests;
