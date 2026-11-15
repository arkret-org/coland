//! A byte-bound successor source candidate, never an authorization verdict.

use arkret_models_collaboration::events_payloads::realm::RealmOwnerTransferPayload;
use arkret_models_identity::AccountDeviceSignerEvidence;
use arkret_wire::{Event, EventKind};

use crate::{PersistenceError, PersistenceResult};

#[derive(Clone, Debug)]
pub struct OwnerTransferSuccessorSource {
    evidence: AccountDeviceSignerEvidence,
}

impl OwnerTransferSuccessorSource {
    /// Check the finite source shape against the exact original Event.
    ///
    /// This does not verify a C signature, prove current Device eligibility,
    /// or reserve a Realm cut. The accepting adapter must independently do
    /// all of those checks using its actual clock and native locked state.
    pub fn for_event(
        event: &Event,
        evidence: AccountDeviceSignerEvidence,
    ) -> PersistenceResult<Self> {
        if event.kind != EventKind::RealmOwnerTransfer {
            return Err(PersistenceError::SchemaViolation(
                "successor Device evidence is confined to owner transfer".into(),
            ));
        }
        let payload: RealmOwnerTransferPayload = serde_json::from_value(serde_json::Value::Object(
            event.payload.clone().into_iter().collect(),
        ))
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        let intent = payload
            .acceptance_intent(&event.scope_ref, &event.actor_id)
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        evidence
            .validate_owner_transfer_binding(&intent, &payload.successor_acceptance)
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        Ok(Self { evidence })
    }

    pub fn evidence(&self) -> &AccountDeviceSignerEvidence {
        &self.evidence
    }
}
