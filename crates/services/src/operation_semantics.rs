use arkret_event_draft::ProjectedEventOperation as Operation;
use serde_json::Value;

pub const REASON_KEYPACKAGE_NOT_FOUND: &str =
    coland_domain::reducer::mls::REASON_KEYPACKAGE_NOT_FOUND;
pub const REASON_KEYPACKAGE_ALREADY_CLAIMED: &str =
    coland_domain::reducer::mls::REASON_KEYPACKAGE_ALREADY_CLAIMED;
pub const REASON_KEYPACKAGE_REALM_MISMATCH: &str =
    coland_domain::reducer::mls::REASON_KEYPACKAGE_REALM_MISMATCH;
/// Facet the Station's container-order projection settles. Space child order
/// is a local projection coordinate, not a wire object.
pub const CONTAINER_ORDER_FACET: &str = coland_domain::reducer::facet::CONTAINER_ORDER;

pub fn canonical_kind_for_operation(operation: &Operation) -> Option<arkret_wire::EventKind> {
    coland_domain::kinds::canonical_kind_for_operation(operation)
}

pub fn canonical_kind(operation: &Operation) -> arkret_wire::EventKind {
    coland_domain::kinds::canonical_kind(operation)
}

pub fn operation_is_message_create(operation: &Operation) -> bool {
    coland_domain::kinds::operation_is_message_create(operation)
}

pub fn operation_is_membership(operation: &Operation) -> bool {
    coland_domain::kinds::operation_is_membership(operation)
}

pub fn operation_is_invite(operation: &Operation) -> bool {
    coland_domain::kinds::operation_is_invite(operation)
}

pub fn operation_is_invite_create(operation: &Operation) -> bool {
    coland_domain::kinds::operation_is_invite_create(operation)
}

pub fn operation_is_invite_claim(operation: &Operation) -> bool {
    coland_domain::kinds::operation_is_invite_claim(operation)
}

pub fn operation_is_invite_third_party(operation: &Operation) -> bool {
    coland_domain::kinds::operation_is_invite_third_party(operation)
}

pub fn operation_is_realm_lifecycle(operation: &Operation) -> bool {
    coland_domain::kinds::operation_is_realm_lifecycle(operation)
}

pub fn payload_declares_minimal_metadata_realm(payload: &serde_json::Value) -> bool {
    coland_domain::kinds::payload_declares_minimal_metadata_realm(payload)
}

pub fn validate_join_policy_payload(join_policy: &Value) -> Result<(), &'static str> {
    coland_domain::reducer::validate_join_policy_payload(join_policy)
}

pub fn message_redaction_target_ref(payload: &Value) -> Option<String> {
    coland_domain::reducer::message_redaction_target_ref(payload)
}

pub fn message_id_from_payload_or_event_id(payload: &Value, event_id: &str) -> String {
    coland_domain::reducer::message_id_from_payload_or_event_id(payload, event_id)
}
