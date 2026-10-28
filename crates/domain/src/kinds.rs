use arkret_event_draft::ProjectedEventOperation as Operation;
use arkret_wire::EventKind;
use serde_json::Value;

use crate::artifacts;

pub fn validate_mls_governance_binding(payload: &Value) -> Result<(), &'static str> {
    let binding = payload
        .get("governance_binding")
        .ok_or(arkret_wire::ReasonCode::GOVERNANCE_BINDING_MISMATCH)?;
    serde_json::from_value::<arkret_models_crypto::MlsGovernanceBindingPayload>(binding.clone())
        .map_err(|_| arkret_wire::ReasonCode::GOVERNANCE_BINDING_MISMATCH)?
        .validate()
        .map_err(|_| arkret_wire::ReasonCode::GOVERNANCE_BINDING_MISMATCH)
}

pub fn canonical_kind_for_operation(operation: &Operation) -> Option<EventKind> {
    let kind = operation.event_kind.as_str();
    artifacts::active_local_operation_event_kinds()
        .contains(kind)
        .then(|| EventKind::from(kind))
}

pub fn canonical_kind(operation: &Operation) -> EventKind {
    canonical_kind_for_operation(operation).unwrap_or_else(|| operation.event_kind.clone())
}

pub fn operation_is_message_create(operation: &Operation) -> bool {
    canonical_kind_for_operation(operation) == Some(EventKind::MessageCreate)
}

pub fn operation_is_membership(operation: &Operation) -> bool {
    canonical_kind_for_operation(operation)
        .is_some_and(|kind| arkret_wire::events::kinds::is_membership_kind(&kind))
}

pub fn operation_is_invite(operation: &Operation) -> bool {
    canonical_kind_for_operation(operation)
        .is_some_and(|kind| arkret_wire::events::kinds::is_invite_kind(&kind))
}

pub fn operation_is_invite_create(operation: &Operation) -> bool {
    canonical_kind_for_operation(operation) == Some(EventKind::InviteCreate)
}

pub fn operation_is_realm_lifecycle(operation: &Operation) -> bool {
    canonical_kind_for_operation(operation)
        .is_some_and(|kind| arkret_wire::events::kinds::is_realm_lifecycle_kind(&kind))
}

pub fn payload_declares_minimal_metadata_realm(payload: &Value) -> bool {
    payload
        .get("object")
        .and_then(|object| object.get("schema_refs"))
        .and_then(Value::as_array)
        .is_some_and(|references| {
            references.iter().any(|reference| {
                reference.as_str()
                    == Some(arkret_wire::RejectedProfileId::MLS_MINIMAL_METADATA_REALM_V1)
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mls_binding_is_the_compact_authority_commit_shape() {
        let realm_id = arkret_wire::RealmId::new(
            "ak:realm:AZAySZA7XRDeJ9cO4MqaDWrJD-rqPk6Cudk7CCzsDQz1".to_owned(),
        )
        .unwrap();
        let binding = arkret_models_crypto::MlsGovernanceBindingPayload::realm(
            realm_id,
            Some(arkret_wire::EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [7; 32],
            )),
            7,
            8,
            1,
        )
        .unwrap();
        validate_mls_governance_binding(&serde_json::json!({
            "governance_binding": binding
        }))
        .unwrap();
    }

    #[test]
    fn minimal_metadata_profile_is_read_only_from_realm_object() {
        assert!(payload_declares_minimal_metadata_realm(
            &serde_json::json!({
                "object": { "schema_refs": ["ak.profile.mls.minimal_metadata_realm.v1"] }
            })
        ));
        assert!(!payload_declares_minimal_metadata_realm(
            &serde_json::json!({
                "schema_refs": ["ak.profile.mls.minimal_metadata_realm.v1"]
            })
        ));
    }
}
