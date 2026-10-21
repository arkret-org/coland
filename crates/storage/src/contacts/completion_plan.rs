//! Deterministic materialization of confirmed Contact business inputs.
use arkret_models_collaboration::contact_operations::*;
use arkret_models_collaboration::events_payloads::contact::*;
use arkret_wire::{DomainSeparationId, Hash};

use super::*;
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
            version,
            predecessor_event_ref,
        } = &self.plan.action
        else {
            return Err(invalid("Contact plan is not a request"));
        };
        let payload: ContactRequestedPayload = serde_json::from_value(
            serde_json::to_value(&self.plan.event.payload).map_err(invalid)?,
        )
        .map_err(invalid)?;
        let core = RequestAcceptanceReceiptCore {
            trust_domain_id: payload.trust_domain_id,
            holder: self.plan.holder.clone(),
            peer: payload.peer,
            version: *version,
            predecessor_event_ref: predecessor_event_ref.clone(),
            initial_contact_round_id: payload.initial_contact_round_id,
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
                    payload.predecessor_event_ref,
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
        if let Some((lineage, proof, peer, round, version, predecessor, scopes, _terminal)) =
            lineage_and_proof
            && (lineage.issuer != self.plan.holder
                || lineage.peer != peer
                || lineage.contact_round_id.as_ref() != Some(&round)
                || lineage.version != version
                || lineage.predecessor_event_ref != predecessor
                || lineage.event_ref != event.event_id
                || lineage.producer_signer != self.producer_signer
                || lineage.granted_to_peer_scopes != scopes
                || proof.contact_round_id.as_ref() != Some(&round)
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
    /// Recompute the lifetime operation CAS from the actual locked pre-state.
    /// Only this holder's new committed Event advances this direction.
    pub fn validate_slot_cas(
        &self,
        pre_state: Option<&ContactRecord>,
        post_state: &ContactRecord,
    ) -> PersistenceResult<()> {
        let owner = self.plan.holder.contact_actor_id();
        let peer: ContactPeer = serde_json::from_value(
            self.plan
                .event
                .payload
                .get("peer")
                .cloned()
                .ok_or_else(|| invalid("Contact peer missing"))?,
        )
        .map_err(invalid)?;
        let peer = peer.contact_actor_id();
        let before = pre_state.and_then(|record| {
            record
                .request_slot_states
                .iter()
                .find(|slot| slot.owner_id == owner && slot.peer_id == peer)
        });
        let after = post_state
            .request_slot_states
            .iter()
            .find(|slot| slot.owner_id == owner && slot.peer_id == peer)
            .ok_or_else(|| invalid("Contact post-state operation cursor absent"))?;
        let version = self
            .plan
            .event
            .payload
            .get("version")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| invalid("Contact operation version missing"))?;
        let predecessor = self
            .plan
            .event
            .payload
            .get("predecessor_event_ref")
            .cloned()
            .map(serde_json::from_value::<arkret_wire::EventId>)
            .transpose()
            .map_err(invalid)?;
        if version != before.map_or(1, |slot| slot.version + 1)
            || predecessor.as_ref() != before.map(|slot| &slot.head_event_ref)
            || after.version != version
            || after.head_event_ref != self.plan.event.event_id
        {
            return Err(crate::PersistenceError::Conflict(
                "contact_lineage_conflict: operation CAS differs from the accepting cut".into(),
            ));
        }
        let other = |record: &ContactRecord| {
            record
                .request_slot_states
                .iter()
                .filter(|slot| slot.owner_id != owner || slot.peer_id != peer)
                .cloned()
                .collect::<Vec<_>>()
        };
        if pre_state.map(other).unwrap_or_default() != other(post_state) {
            return Err(invalid(
                "Contact operation changes the opposite holder cursor",
            ));
        }
        if let ContactCompletionAction::Response {
            request_receipt,
            absence,
        } = &self.plan.action
        {
            if absence.request_slot_owner != owner
                || absence.version != version
                || absence.predecessor_event_ref != predecessor
                || absence.request_event_ref != request_receipt.core.request_event_ref
                || absence.observed_at != self.accepted_at()?
            {
                return Err(invalid(
                    "Contact normal absence differs from exact locked operation",
                ));
            }
            if pre_state.is_some_and(|record| {
                record.conflicting_contact_request_choice(
                    &owner,
                    &request_receipt.core.request_event_ref,
                )
            }) {
                return Err(invalid(
                    "Contact normal accept cannot consume an outgoing or glare-selected request",
                ));
            }
        }
        Ok(())
    }
}
