use arkret_event_draft::ProjectedEventOperation as Operation;
use arkret_models_collaboration::governance::membership_invite::validate_invite_create_wire_keys;
use serde_json::Value;

use super::*;

pub(crate) fn validate_invite_create_payload(operation: &Operation) -> Result<(), &'static str> {
    let wire_payload = operation.payload.clone();
    validate_invite_create_wire_keys(&wire_payload)
        .map_err(|_| "operation payload carries unsupported fields")?;
    operation
        .typed_payload::<arkret_wire::event_spec::InviteCreate>()
        .map_err(|_| "operation payload violates SDK artifact schema")?;
    Ok(())
}

pub(crate) fn validate_invite_ref_payload(operation: &Operation) -> Result<(), &'static str> {
    let payload = operation
        .payload
        .as_object()
        .ok_or("invite reference payload must be an object")?;
    let invite_id =
        payload_string(payload, "invite_id").ok_or("invite reference requires invite_id")?;
    if arkret_identifiers::InviteId::new(invite_id).is_err() {
        return Err("invite reference invite_id must be ak:invite:<uuidv7>");
    }
    if let Some(reason) = payload.get("reason")
        && !reason.is_string()
    {
        return Err("invite reference reason must be a string");
    }
    validate_operation_payload_against_sdk_artifact(operation)?;
    Ok(())
}

fn payload_string(payload: &serde_json::Map<String, Value>, field: &str) -> Option<String> {
    payload
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

pub fn validate_message_operation_payload(operation: &Operation) -> Result<(), &'static str> {
    if coland_services::operation_semantics::operation_is_message_create(operation) {
        if operation
            .payload
            .get("strand_id")
            .and_then(Value::as_str)
            .is_none_or(|value| value.trim().is_empty())
        {
            return Err("message create requires strand_id");
        }
        let track_name = operation
            .payload
            .get("track_name")
            .and_then(Value::as_str)
            .ok_or("message create requires track_name")?;
        validate_read_scope_track(track_name)?;
    }
    let encrypted = operation
        .payload
        .get("encrypted")
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
        || operation.payload.get("encrypted_content").is_some();
    if encrypted {
        // The encrypted content envelope SHAPE is owned by the registered spec schema
        // `ak.schema.encrypted_envelope.v1`. Its SDK model owns the closed
        // shape; this kind-specific check only enforces the carrier choice.
        if operation.payload.get("encrypted_content").is_none()
            && operation.payload.get("content").is_none()
        {
            return Err("encrypted message operation requires content envelope");
        }
    } else if let Some(content) = operation.payload.get("content") {
        validate_content_blocks(content)?;
        arkret_models_collaboration::events_payloads::validate_mentions_in_realm(
            content,
            &operation.realm_id,
        )
        .map_err(|error| error.message())?;
    }
    Ok(())
}

pub(crate) fn validate_account_data_set_payload(operation: &Operation) -> Result<(), &'static str> {
    let payload = operation
        .typed_payload::<arkret_wire::event_spec::AccountDataSet>()
        .map_err(|_| "account_data.set payload violates SDK artifact schema")?;
    let key = payload.key.as_str();
    crate::routing::account_data_encryption::validate_encrypted_account_data_key(key)
        .map_err(|error| error.message())?;
    if payload.tombstone {
        return Ok(());
    }
    crate::routing::account_data_encryption::validate_encrypted_account_data_value_for_actor(
        key,
        &operation.payload,
        Some(&operation.context.sender),
    )
    .map_err(|error| error.message())
}

pub(crate) fn validate_read_receipt_policy_payload(
    operation: &Operation,
) -> Result<(), &'static str> {
    let payload_value = &operation.payload;
    let payload = payload_value
        .as_object()
        .ok_or("ak.scope.read_receipt_policy payload must be an object")?;
    if payload.is_empty() {
        return Err("ak.scope.read_receipt_policy payload must set at least one field");
    }
    operation
        .typed_payload::<arkret_wire::event_spec::ScopeReadReceiptPolicy>()
        .map_err(|_| "ak.scope.read_receipt_policy payload violates SDK artifact schema")?;
    Ok(())
}

pub(crate) fn validate_read_marker_payload(operation: &Operation) -> Result<(), &'static str> {
    let read_scope = operation
        .payload
        .get("read_scope")
        .and_then(|value| value.as_object())
        .ok_or("read marker read_scope must be an object")?;
    for key in read_scope.keys() {
        if !["kind", "container_ref", "track_name"].contains(&key.as_str()) {
            return Err("read marker read_scope has unknown field");
        }
    }
    let kind = read_scope
        .get("kind")
        .and_then(|value| value.as_str())
        .ok_or("read marker read_scope.kind is required")?;
    match kind {
        "realm" => {
            if read_scope
                .get("container_ref")
                .is_some_and(|value| !value.is_null())
            {
                return Err("read marker read_scope.container_ref must be omitted for realm");
            }
            if read_scope
                .get("track_name")
                .is_some_and(|value| !value.is_null())
            {
                return Err("read marker read_scope.track_name requires kind strand");
            }
        }
        "circle" | "space" | "strand" | "thread" => {
            let reference = read_scope
                .get("container_ref")
                .and_then(|value| value.as_str())
                .filter(|value| !value.trim().is_empty())
                .ok_or("read marker read_scope.container_ref is required")?;
            let expected_prefix = match kind {
                "circle" => "ak:circle:",
                "space" => "ak:space:",
                "strand" => "ak:strand:",
                "thread" => "ak:message:",
                _ => unreachable!(),
            };
            if !reference.starts_with(expected_prefix) {
                return Err("read marker read_scope.ref has invalid typed id kind");
            }
            if kind != "strand"
                && read_scope
                    .get("track_name")
                    .is_some_and(|value| !value.is_null())
            {
                return Err("read marker read_scope.track_name requires kind strand");
            }
        }
        "view" | "message" | "morph" => {
            return Err("read marker read_scope.kind is receipt-only");
        }
        "strand_discussion" | "strand_synthesis" => {
            return Err("read marker read_scope.kind removed; use strand plus track_name");
        }
        _ => return Err("read marker read_scope.kind is invalid"),
    }
    if let Some(track) = read_scope
        .get("track_name")
        .and_then(|value| value.as_str())
    {
        if kind != "strand" {
            return Err("read marker read_scope.track_name requires kind strand");
        }
        validate_read_scope_track(track)?;
    }
    let position = operation
        .payload
        .get("position")
        .and_then(|value| value.as_object())
        .ok_or("read marker position must be an object")?;
    if position
        .get("event_id")
        .and_then(|value| value.as_str())
        .is_none_or(|value| !value.starts_with("ak:event:"))
    {
        return Err("read marker position.event_id is invalid");
    }
    let hlc = position
        .get("hlc")
        .and_then(|value| value.as_str())
        .ok_or("read marker position.hlc is required")?;
    validate_read_cursor_hlc(hlc)?;
    Ok(())
}

pub(crate) fn validate_history_access_payload(operation: &Operation) -> Result<(), &'static str> {
    let from = operation.payload.get("from").and_then(Value::as_str);
    let to = operation
        .payload
        .get("to")
        .and_then(Value::as_str)
        .ok_or("ak.realm.history_access requires to")?;
    if !matches!(
        (from, to),
        (None, "all_history_for_current_members" | "since_join")
            | (Some("all_history_for_current_members"), "since_join")
            | (Some("since_join"), "since_join")
    ) {
        return Err("history_access_widening_forbidden");
    }
    Ok(())
}

pub(crate) fn validate_read_scope_track(track: &str) -> Result<(), &'static str> {
    let mut bytes = track.bytes();
    let Some(first) = bytes.next() else {
        return Err("read marker read_scope.track_name is invalid");
    };
    if !first.is_ascii_lowercase()
        || track.len() > 64
        || !bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err("read marker read_scope.track_name is invalid");
    }
    Ok(())
}

fn validate_read_cursor_hlc(hlc: &str) -> Result<(), &'static str> {
    let parts = hlc.split('-').collect::<Vec<_>>();
    if parts.len() != 3
        || parts[0].len() != 12
        || parts[1].len() != 4
        || parts[2].len() != 8
        || !parts.iter().all(|part| {
            part.bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        })
    {
        return Err("read marker position.hlc is invalid");
    }
    Ok(())
}
/// `relation.md` §2 stateless admission guard for `ak.relation.update`.
///
/// The create side is gone from this layer on purpose:
/// `event-payload.schema.json#/$defs/relation_create_object` now reuses
/// `relation.schema.json` and additionally forbids `id`, `type` and
/// `effective_scope`, so the SDK artifact schema that runs immediately before
/// this validator already rejects an actor-supplied `effective_scope` on
/// `payload.relation`. Re-checking it here would be a second, drifting copy of
/// a criterion the schema owns.
///
/// The update side stays because `payload.patch` is the generic
/// `ak.schema.patch.v1` document, which cannot express a per-object forbidden
/// set. The set is read from the SDK projection of
/// `registry/reducer-managed-path-registry.json`; this module never spells its
/// own list.
///
/// Derived-edge admission (`watches`, container `contains`), endpoint scope and
/// every tombstone decision need the Relation pre-state, so they live solely in
/// `ProjectionState::check_relation_invariants`, which submit calls before any
/// persistent effect.
pub(crate) fn validate_relation_operation_payload(
    operation: &Operation,
) -> Result<(), &'static str> {
    let Some(patch) = operation.payload.get("patch").and_then(Value::as_object) else {
        return Ok(());
    };
    for path in patch.keys() {
        if let Some(reason) = arkret_wire::patch::reducer_managed_patch_reason("relation", path) {
            return Err(reason);
        }
    }
    Ok(())
}

pub(crate) fn validate_morph_update_payload(operation: &Operation) -> Result<(), &'static str> {
    let Some(patch) = operation.payload.get("patch").and_then(Value::as_object) else {
        return Ok(());
    };
    if patch.contains_key("content") && patch.contains_key("encrypted_content") {
        return Err("morph_content_carrier_conflict");
    }
    if patch.contains_key("metadata") && patch.contains_key("encrypted_metadata") {
        return Err("morph_metadata_carrier_conflict");
    }
    // Forbidden-wire and reducer-managed patch paths (`morph.md` §2 / §4:
    // create-locked `morph_kind` / `schema_refs`, the `ak.morph.stage.set`-owned
    // stage axis, and the reserved `fields.*` business-field set) are enforced
    // by `validate_operation_patch_semantics` against the SDK projections of
    // `registry/forbidden-wire-fields.json` and
    // `registry/reducer-managed-path-registry.json`; no hand-copied list lives
    // here.
    Ok(())
}

pub(crate) fn validate_morph_create_payload(operation: &Operation) -> Result<(), &'static str> {
    let Some(object) = operation.payload.get("object").and_then(Value::as_object) else {
        return Err("morph_create_object_invalid");
    };
    if object.contains_key("content") && object.contains_key("encrypted_content") {
        return Err("morph_content_carrier_conflict");
    }
    if object.contains_key("metadata") && object.contains_key("encrypted_metadata") {
        return Err("morph_metadata_carrier_conflict");
    }
    if let Some(metadata) = object.get("metadata").and_then(Value::as_object) {
        reject_morph_metadata_business_fields(metadata)?;
    }
    Ok(())
}

/// Current-v1 View definitions removed presentation-local write policy and
/// make lifecycle timestamps reducer-owned. Admission rejects the retired
/// fields instead of silently preserving them in generic JSON maps.
pub(crate) fn validate_view_payload(operation: &Operation) -> Result<(), &'static str> {
    fn contains_retired_field(value: &Value) -> bool {
        match value {
            Value::Object(fields) => fields.iter().any(|(key, value)| {
                matches!(
                    key.as_str(),
                    "selection_policy" | "page_size" | "wip_limit_enforcement" | "state_changed_at"
                ) || contains_retired_field(value)
            }),
            Value::Array(values) => values.iter().any(contains_retired_field),
            _ => false,
        }
    }

    for field in ["object", "definition", "patch"] {
        if let Some(value) = operation.payload.get(field) {
            if value.get("visibility").and_then(Value::as_str) == Some("private") {
                return Err("private_view_requires_account_data");
            }
            if contains_retired_field(value) {
                return Err(arkret_wire::ErrorCode::SCHEMA_VIOLATION);
            }
            if let Some(state) = value.get("state")
                && !matches!(state.as_str(), Some("active" | "tombstoned"))
            {
                return Err(arkret_wire::ErrorCode::SCHEMA_VIOLATION);
            }
        }
    }
    if operation.payload.get("visibility").and_then(Value::as_str) == Some("private") {
        return Err("private_view_requires_account_data");
    }
    Ok(())
}

fn reject_morph_metadata_business_fields(
    metadata: &serde_json::Map<String, Value>,
) -> Result<(), &'static str> {
    for field in [
        "id",
        "schema",
        "realm_id",
        "scope_circle_id",
        "schema_refs",
        "morph_kind",
        "facets",
        "fields",
        "stage",
        "stage_changed_at",
        "state",
        "state_changed_at",
        "created_by",
        "created_at",
        "updated_by",
        "updated_at",
        "content",
        "encrypted_content",
        "encrypted_payload",
    ] {
        if metadata.contains_key(field) {
            return Err("morph_metadata_business_field");
        }
    }
    Ok(())
}

pub(crate) fn validate_device_authorize_payload(operation: &Operation) -> Result<(), &'static str> {
    let payload = operation
        .typed_payload::<arkret_wire::event_spec::DeviceAuthorize>()
        .map_err(|_| "ak.device.authorize payload violates SDK artifact schema")?;
    payload.validate_wire_constraints()
}

#[cfg(test)]
pub fn validate_encrypted_payload_envelope(
    content: &serde_json::Value,
) -> Result<(), &'static str> {
    arkret_models_crypto::parse_and_validate_encrypted_envelope(content.clone())
        .map(|_| ())
        .map_err(|_| "encrypted content envelope violates SDK schema")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::validate_encrypted_payload_envelope;

    #[test]
    fn account_data_rejects_the_deleted_holder_mirror_even_for_tombstones() {
        let mut operation = arkret_event_draft::test_support::raw_projected_operation(
            arkret_wire::OperationId::new("ak:operation:01904100-0000-7000-8000-000000000002")
                .unwrap(),
            arkret_wire::RealmId::new("ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K")
                .unwrap(),
            arkret_wire::EventKind::AccountDataSet.as_str(),
            json!({"key": "ak.dnd_schedule", "expected_server_revision": 0, "tombstone": true}),
        );
        assert_eq!(super::validate_account_data_set_payload(&operation), Ok(()));
        operation.payload["unknown_holder_field"] = json!("ak:did_core:web:other-holder.example");
        assert_eq!(
            super::validate_account_data_set_payload(&operation),
            Err("account_data.set payload violates SDK artifact schema")
        );
    }

    #[test]
    fn encrypted_payload_envelope_accepts_only_the_minimal_closed_wire() {
        let envelope = json!({
            "version": "1.0",
            "content_type": "application/json",
            "encryption_context": {
                "epoch": (7u64).to_string(),
                "group_state_ref": "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            },
            "ciphertext": "Y2lwaGVydGV4dA",
        });

        assert_eq!(validate_encrypted_payload_envelope(&envelope), Ok(()));

        for forbidden in ["counter", "scheme"] {
            let mut widened = envelope.clone();
            widened["encryption_context"][forbidden] = json!(9u64);
            assert_eq!(
                validate_encrypted_payload_envelope(&widened),
                Err("encrypted content envelope violates SDK schema"),
                "{forbidden} must not widen the closed encryption context"
            );
        }

        for forbidden in ["scheme", "group_id", "aad", "payload_digest"] {
            let mut widened = envelope.clone();
            widened[forbidden] = json!("forbidden");
            assert_eq!(
                validate_encrypted_payload_envelope(&widened),
                Err("encrypted content envelope violates SDK schema"),
                "{forbidden} must not be duplicated on the wire"
            );
        }
    }
}
