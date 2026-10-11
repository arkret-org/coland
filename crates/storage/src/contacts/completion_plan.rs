//! Deterministic materialization of confirmed Contact business inputs.
use arkret_models_collaboration::contact_operations::*;
use arkret_models_collaboration::events_payloads::contact::*;
use arkret_wire::{DomainSeparationId, Hash};

use super::*;
use crate::ContactRequestSlotState;
fn invalid(error: impl ToString) -> crate::PersistenceError {
    crate::PersistenceError::SchemaViolation(error.to_string())
}
fn digest(domain: &str, value: &impl serde::Serialize) -> PersistenceResult<Hash> {
    let mut bytes = domain.as_bytes().to_vec();
    bytes.push(b'\n');
    bytes.extend(arkret_canonical::canonical_json_bytes(value).map_err(invalid)?);
    Hash::new(arkret_canonical::sha256_digest(bytes)).map_err(invalid)
}
impl ContactCompletionIntent {
    pub fn request_receipt_core(&self) -> PersistenceResult<RequestAcceptanceReceiptCore> {
        let ContactCompletionAction::Request {
            slot_version,
            slot_predecessor,
        } = &self.plan.action
        else {
            return Err(invalid("Contact plan is not a request"));
        };
        let payload: ContactRequestedPayload = serde_json::from_value(
            serde_json::to_value(&self.plan.event.payload).map_err(invalid)?,
        )
        .map_err(invalid)?;
        let core = RequestAcceptanceReceiptCore {
            holder: self.plan.holder.clone(),
            peer: payload.peer,
            slot_version: *slot_version,
            slot_predecessor: slot_predecessor.clone(),
            previous_terminal_contact_round_id: payload.previous_terminal_contact_round_id,
            request_event_ref: self.plan.event.event_id.clone(),
            producer_signer: self.producer_signer.clone(),
            source_checkpoint: digest(
                DomainSeparationId::CONTACT_REQUEST_SOURCE_CHECKPOINT_V1,
                &serde_json::json!({"event_ref":self.plan.event.event_id,"event_digest":self.plan.event.event_id.event_digest()}),
            )?,
            accepted_at: self.accepted_at()?,
            issuer_id: self.plan.holder.delivery_station_id().clone(),
        };
        core.validate().map_err(invalid)?;
        Ok(core)
    }
    pub fn request_core_digest(&self) -> PersistenceResult<Hash> {
        digest(
            DomainSeparationId::CONTACT_REQUEST_ACCEPTANCE_CORE_V1,
            &self.request_receipt_core()?,
        )
    }
    pub fn finalized_carrier(
        &self,
        outcome: &ContactAcceptedOutcome,
    ) -> PersistenceResult<PeerContactSubmitRequestBody> {
        self.validate_finalized_outcome(outcome)?;
        let target = &self.plan.target;
        let signed_event = self.plan.event.clone();
        let contact_address = target.contact_address.clone();
        let idempotency_key = target.idempotency_key.clone();
        Ok(match outcome {
            ContactAcceptedOutcome::Request {
                request_acceptance_receipt,
                ..
            } => PeerContactSubmitRequestBody::Request {
                idempotency_key,
                signed_event,
                request_receipt: request_acceptance_receipt.clone(),
                contact_address,
                introduction_evidence: target
                    .introduction_evidence
                    .clone()
                    .ok_or_else(|| invalid("Contact request introduction missing"))?,
                current_proof: None,
            },
            ContactAcceptedOutcome::Response {
                normal_response_acceptance_receipt,
                current_proof,
                ..
            } => PeerContactSubmitRequestBody::Response {
                idempotency_key,
                signed_event,
                response_receipt: normal_response_acceptance_receipt.clone(),
                contact_address,
                current_proof: Some(current_proof.clone()),
            },
            ContactAcceptedOutcome::Reject {
                reject_acceptance_receipt,
                ..
            } => PeerContactSubmitRequestBody::Reject {
                idempotency_key,
                signed_event,
                reject_receipt: reject_acceptance_receipt.clone(),
                contact_address,
            },
            ContactAcceptedOutcome::ScopeUpdate {
                lineage,
                current_proof,
                ..
            } => PeerContactSubmitRequestBody::ScopeUpdate {
                idempotency_key,
                signed_event,
                lineage: lineage.clone(),
                current_proof: current_proof.clone(),
                contact_address,
            },
            ContactAcceptedOutcome::Tombstone {
                lineage,
                current_proof,
                ..
            } => PeerContactSubmitRequestBody::Tombstone {
                idempotency_key,
                signed_event,
                lineage: lineage.clone(),
                current_proof: current_proof.clone(),
                contact_address,
            },
        })
    }
    pub fn validate_finalized_outcome(
        &self,
        outcome: &ContactAcceptedOutcome,
    ) -> PersistenceResult<()> {
        self.validate_event_binding()?;
        let accepted_at = self.accepted_at()?;
        let event = &self.plan.event;
        let expected_operation = &self.plan.operation_id;
        let issuer = self.plan.holder.delivery_station_id();
        let mut lineage_and_proof = None;
        let valid = match (&self.plan.action, outcome) {
            (
                ContactCompletionAction::Request { .. },
                ContactAcceptedOutcome::Request {
                    operation_id,
                    request_acceptance_receipt: receipt,
                },
            ) => {
                receipt.validate_shape().map_err(invalid)?;
                operation_id == expected_operation
                    && receipt.core == self.request_receipt_core()?
                    && receipt.receipt_digest == self.request_core_digest()?
            }
            (
                ContactCompletionAction::Response {
                    request_receipt,
                    absence,
                },
                ContactAcceptedOutcome::Response {
                    operation_id,
                    normal_response_acceptance_receipt: receipt,
                    lineage,
                    current_proof,
                },
            ) => {
                let payload: ContactAcceptedPayload =
                    serde_json::from_value(serde_json::to_value(&event.payload).map_err(invalid)?)
                        .map_err(invalid)?;
                lineage_and_proof = Some((
                    lineage,
                    current_proof,
                    payload.peer,
                    payload.contact_round_id.clone(),
                    payload.version,
                    None,
                    payload.granted_to_peer_scopes,
                    false,
                ));
                operation_id == expected_operation
                    && &receipt.request_receipt == request_receipt.as_ref()
                    && receipt.response_event_ref == event.event_id
                    && receipt.producer_signer == self.producer_signer
                    && receipt.accepted_at == accepted_at
                    && &receipt.issuer_id == issuer
                    && receipt.contact_round_id == payload.contact_round_id
                    && absence.observed_at == accepted_at
                    && receipt.outgoing_slot_absence_digest == absence.digest().map_err(invalid)?
            }
            (
                ContactCompletionAction::Reject { request_receipt },
                ContactAcceptedOutcome::Reject {
                    operation_id,
                    reject_acceptance_receipt: receipt,
                },
            ) => {
                operation_id == expected_operation
                    && &receipt.request_receipt == request_receipt.as_ref()
                    && receipt.reject_event_ref == event.event_id
                    && receipt.producer_signer == self.producer_signer
                    && receipt.accepted_at == accepted_at
                    && &receipt.issuer_id == issuer
            }
            (
                ContactCompletionAction::ScopeUpdate,
                ContactAcceptedOutcome::ScopeUpdate {
                    operation_id,
                    lineage,
                    current_proof,
                },
            ) => {
                let payload: ContactScopeUpdatePayload =
                    serde_json::from_value(serde_json::to_value(&event.payload).map_err(invalid)?)
                        .map_err(invalid)?;
                lineage_and_proof = Some((
                    lineage,
                    current_proof,
                    payload.peer,
                    payload.contact_round_id,
                    payload.version,
                    Some(payload.predecessor_event_ref),
                    payload.granted_to_peer_scopes,
                    false,
                ));
                operation_id == expected_operation
            }
            (
                ContactCompletionAction::Tombstone,
                ContactAcceptedOutcome::Tombstone {
                    operation_id,
                    lineage,
                    current_proof,
                },
            ) => {
                let payload: ContactTombstonedPayload =
                    serde_json::from_value(serde_json::to_value(&event.payload).map_err(invalid)?)
                        .map_err(invalid)?;
                lineage_and_proof = Some((
                    lineage,
                    current_proof,
                    payload.peer,
                    payload.contact_round_id,
                    payload.version,
                    Some(payload.predecessor_event_ref),
                    Vec::new(),
                    true,
                ));
                operation_id == expected_operation
            }
            _ => false,
        };
        if !valid {
            return Err(invalid(
                "Contact completion changed its confirmed business inputs",
            ));
        }
        if let Some((lineage, proof, peer, round, version, predecessor, scopes, terminal)) =
            lineage_and_proof
            && (lineage.issuer != self.plan.holder
                || lineage.peer != peer
                || lineage.contact_round_id != round
                || lineage.version != version
                || lineage.predecessor_event_ref != predecessor
                || lineage.event_ref != event.event_id
                || lineage.producer_signer != self.producer_signer
                || lineage.granted_to_peer_scopes != scopes
                || lineage.terminal != terminal.then_some(true)
                || proof.contact_round_id != round
                || proof.peer != peer
                || &proof.issuer_id != issuer)
        {
            return Err(invalid(
                "Contact completion lineage or current proof changed its exact direction",
            ));
        }
        // The transaction separately binds this proof to the actual current
        // committed head; a larger numeric version alone is never enough.
        Ok(())
    }
}

impl ContactCompletionIntent {
    /// The request-slot CAS this plan froze, recomputed from the pre-state row
    /// the accepting transaction holds locked.
    ///
    /// A request advances its owner's slot with its receipt core digest as the
    /// new head; a normal response advances the responder's slot with its
    /// absence digest, and its `cas_revision` is exactly the slot's accepted
    /// Event prefix plus the consumed request (contact-and-direct-conversation.md
    /// section 2). Every other slot, and every slot of the other Contact
    /// commands, stays unchanged.
    pub fn validate_slot_cas(
        &self,
        pre_state: Option<&ContactRecord>,
        post_state: &ContactRecord,
    ) -> PersistenceResult<()> {
        let owner = self.plan.holder.contact_actor_id();
        let peer = self
            .plan
            .event
            .payload
            .get("peer")
            .cloned()
            .ok_or_else(|| invalid("Contact peer is missing"))
            .and_then(|value| serde_json::from_value::<ContactPeer>(value).map_err(invalid))?
            .contact_actor_id();
        let slot = |states: &'_ [ContactRequestSlotState]| {
            states
                .iter()
                .find(|state| state.owner_id == owner && state.peer_id == peer)
                .cloned()
        };
        let others = |states: &[ContactRequestSlotState]| {
            states
                .iter()
                .filter(|state| !(state.owner_id == owner && state.peer_id == peer))
                .cloned()
                .collect::<Vec<_>>()
        };
        let pre_states = pre_state
            .map(|record| record.request_slot_states.as_slice())
            .unwrap_or_default();
        let pre_slot = slot(pre_states);
        let expected_sequence = match &pre_slot {
            Some(current) => current
                .accepted_sequence
                .checked_add(1)
                .ok_or_else(|| invalid("Contact request-slot sequence is exhausted"))?,
            None => 1,
        };
        let expected_predecessor = pre_slot.as_ref().map(|current| current.head_digest.clone());
        let pre_prefix = |observed: &[arkret_wire::EventId]| match &pre_slot {
            Some(current) => current.prefix_with(observed),
            None => coland_domain::identity::contact_event_prefix(observed),
        };
        let mismatch = || {
            crate::PersistenceError::Conflict(
                "contact_lineage_conflict: the request-slot CAS differs from the accepting cut"
                    .to_owned(),
            )
        };
        if others(pre_states) != others(&post_state.request_slot_states) {
            return Err(mismatch());
        }
        let post_slot = slot(&post_state.request_slot_states);
        let expected_post = match &self.plan.action {
            ContactCompletionAction::Request {
                slot_version,
                slot_predecessor,
            } => {
                if *slot_version != expected_sequence
                    || slot_predecessor.as_ref() != expected_predecessor.as_ref()
                {
                    return Err(mismatch());
                }
                Some(ContactRequestSlotState {
                    owner_id: owner.clone(),
                    peer_id: peer.clone(),
                    accepted_sequence: *slot_version,
                    head_digest: self.request_core_digest()?,
                    accepted_event_refs: pre_prefix(std::slice::from_ref(
                        &self.plan.event.event_id,
                    )),
                })
            }
            ContactCompletionAction::Response {
                request_receipt,
                absence,
            } => {
                let cas_revision = pre_prefix(std::slice::from_ref(
                    &request_receipt.core.request_event_ref,
                ));
                if absence.request_slot_owner != owner
                    || absence.cas_sequence != expected_sequence
                    || absence.slot_predecessor.as_ref() != expected_predecessor.as_ref()
                    || absence.cas_revision != cas_revision
                    || absence.observed_at != self.accepted_at()?
                {
                    return Err(mismatch());
                }
                let mut accepted_event_refs = cas_revision;
                accepted_event_refs.push(self.plan.event.event_id.clone());
                Some(ContactRequestSlotState {
                    owner_id: owner.clone(),
                    peer_id: peer.clone(),
                    accepted_sequence: absence.cas_sequence,
                    head_digest: absence.digest().map_err(invalid)?,
                    accepted_event_refs: coland_domain::identity::contact_event_prefix(
                        &accepted_event_refs,
                    ),
                })
            }
            ContactCompletionAction::Reject { .. }
            | ContactCompletionAction::ScopeUpdate
            | ContactCompletionAction::Tombstone => pre_slot,
        };
        if post_slot != expected_post {
            return Err(mismatch());
        }
        Ok(())
    }
}
