use arkret_identifiers::{DidCoreId, EventId, Hash};
use arkret_models_collaboration::contact_operations::{
    ContactRoundEvidenceBundle, PeerContactMirrorReceipt, RequestAcceptanceReceipt,
};
use arkret_wire::ActorId;
use chrono::{DateTime, Utc};

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContactRequestSlotState {
    pub owner_id: ActorId,
    pub peer_id: ActorId,
    pub version: u64,
    pub head_event_ref: EventId,
    pub operation_digest: Option<Hash>,
    pub request_choice: Option<ContactRequestChoice>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "choice", rename_all = "snake_case", deny_unknown_fields)]
pub enum ContactRequestChoice {
    Open {
        request_event_ref: EventId,
    },
    Normal {
        request_event_ref: EventId,
    },
    Rejected {
        request_event_ref: EventId,
    },
    Glare {
        request_event_ref: EventId,
        counterpart_event_ref: EventId,
    },
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ContactRecord {
    pub requester_id: ActorId,
    pub target_id: ActorId,
    pub contact_round_id: Option<Hash>,
    pub granted_to_target_scopes: Vec<String>,
    pub granted_to_requester_scopes: Vec<String>,
    pub status: String,
    /// Whether the target holder's directional `pending_incoming` head passed
    /// the shared first-contact admission chokepoint. The source holder's
    /// `pending_outgoing` head remains durable even when this is false.
    pub pending_incoming_admitted: bool,
    pub request_event_ref: Option<EventId>,
    /// Station-internal directional request-slot CAS heads. These are not
    /// Contact-round continuity and never cross the wire by themselves.
    pub request_slot_states: Vec<ContactRequestSlotState>,
    pub request_receipts: Vec<RequestAcceptanceReceipt>,
    pub request_mirror_receipts: Vec<PeerContactMirrorReceipt>,
    pub contact_round_evidence: Option<ContactRoundEvidenceBundle>,
    pub current_state: arkret_models_collaboration::contact_operations::ContactPrivateState,

    pub response_event_ref: Option<EventId>,
    pub tombstone_event_ref: Option<EventId>,
    pub message: Option<String>,
    pub peer_host_id: Option<DidCoreId>,
    /// Exact carrier retained from the verified introduction or shared-Realm
    /// Station route. It is re-verified before routing and is not a cached
    /// endpoint authority.
    pub peer_service_resolution: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl ContactRecord {
    pub fn conflicting_contact_request_choice(&self, owner: &ActorId, incoming: &EventId) -> bool {
        let Some(slot) = self
            .request_slot_states
            .iter()
            .find(|s| &s.owner_id == owner)
        else {
            return false;
        };
        match &slot.request_choice {
            Some(ContactRequestChoice::Open { request_event_ref }) => {
                (&self.requester_id == owner
                    && self.request_event_ref.as_ref() == Some(request_event_ref))
                    || self.request_receipts.iter().any(|r| {
                        r.core.holder.contact_actor_id() == *owner
                            && &r.core.request_event_ref == request_event_ref
                    })
            }
            Some(ContactRequestChoice::Glare {
                request_event_ref,
                counterpart_event_ref,
            }) => request_event_ref == incoming || counterpart_event_ref == incoming,
            _ => false,
        }
    }
}
