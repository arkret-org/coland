use super::*;

pub(crate) async fn scope_has_accepted_mls_genesis(
    state: &AppState,
    scope: &arkret_wire::ScopeRef,
) -> Result<bool, &'static str> {
    state
        .mls_groups()
        .current(scope)
        .await
        .map(|current| current.is_some())
        .map_err(|_| "mls_activation_state_unavailable")
}

pub fn message_operation_is_encrypted(operation: &Operation) -> bool {
    operation.payload.get("encrypted_content").is_some()
}

pub async fn known_realm_denies_plaintext_service(state: &AppState, realm_id: &str) -> bool {
    state
        .realms()
        .realm_metadata(realm_id)
        .await
        .ok()
        .flatten()
        .is_some_and(|record| {
            !record.allows_plaintext_data_class(
                state.service_id(),
                arkret_wire::PlaintextDataClassKind::MessageContent,
            )
        })
}

pub fn validate_content_blocks(content: &serde_json::Value) -> Result<(), &'static str> {
    validate_content_block(content)
}

/// Canonical mention admission for a Message Content Block tree.
///
/// The only admissible shapes are the spec AST nodes — `{"kind":"mention"}`
/// with a complete `AccountId` `subject_account_id` and
/// `{"kind":"audience_mention"}` with a closed `audience` — both parsed by the
/// SDK models that own the wire types.
pub fn validate_mentions(content: &serde_json::Value) -> Result<(), &'static str> {
    arkret_models_collaboration::events_payloads::collect_mention_nodes(content)
        .map(|_| ())
        .map_err(|error| error.message())
}

pub(crate) fn operation_audience_mentions(
    operation: &Operation,
) -> Result<Vec<arkret_models_collaboration::events_payloads::AudienceMention>, &'static str> {
    let mentions = match operation.payload.get("content") {
        Some(content) => audience_mention_nodes(content)?,
        None => Vec::new(),
    };
    Ok(mentions)
}

/// Complete direct-mention subject accounts carried by a Message Content Block
/// tree.
///
/// Callers MUST match these against a candidate's whole `AccountId`; the same
/// principal hosted by another Station is a different subject
/// (`identity-handles.md §3.8`).
pub(crate) fn mention_subject_account_ids(
    content: &serde_json::Value,
) -> Result<Vec<arkret_wire::AccountId>, &'static str> {
    arkret_models_collaboration::events_payloads::collect_mention_subject_account_ids(content)
        .map_err(|error| error.message())
}

fn audience_mention_nodes(
    content: &serde_json::Value,
) -> Result<Vec<arkret_models_collaboration::events_payloads::AudienceMention>, &'static str> {
    arkret_models_collaboration::events_payloads::collect_audience_mention_nodes(content)
        .map_err(|error| error.message())
}

/// Which object kind an object-patch Event kind writes, when the kind names one.
///
/// This is payload knowledge - which object family the Event patches - and
/// deliberately NOT a copy of any reducer-managed path list: the paths stay in
/// `arkret_wire::patch::reducer_managed_patch_reason`, whose canonical source is
/// `registry/reducer-managed-path-registry.json`. Knowing the kind is what lets
/// the registered per-kind carve-outs through; the object-agnostic superset has
/// none, so it refuses the `ak.view.update` patch that `views.md` 3.1 defines as
/// the only way to tombstone a shared View.
pub(crate) fn patched_object_kind(kind: &arkret_wire::EventKind) -> Option<&'static str> {
    match kind {
        arkret_wire::EventKind::ProfileUpdate => Some("actor_profile"),
        arkret_wire::EventKind::CircleUpdate => Some("circle"),
        arkret_wire::EventKind::MorphUpdate => Some("morph"),
        arkret_wire::EventKind::RelationUpdate => Some("relation"),
        arkret_wire::EventKind::SpaceUpdate => Some("space"),
        arkret_wire::EventKind::StrandUpdate | arkret_wire::EventKind::StrandTracksUpdate => {
            Some("strand")
        }
        arkret_wire::EventKind::ViewUpdate => Some("view"),
        _ => None,
    }
}

pub(crate) fn validate_operation_patch_semantics(
    kind: &arkret_wire::EventKind,
    operation: &Operation,
) -> Result<(), &'static str> {
    let Some(patch) = operation.payload.get("patch").and_then(Value::as_object) else {
        return Ok(());
    };
    coland_domain::reducer::validate_patch_semantic_safety(patch, patched_object_kind(kind))
}

pub fn validate_canonical_json_value(value: &serde_json::Value) -> Result<(), &'static str> {
    validate_canonical_json_value_inner(value, true)
}

pub fn validate_canonical_json_value_inner(
    value: &serde_json::Value,
    root: bool,
) -> Result<(), &'static str> {
    match value {
        serde_json::Value::Number(number)
            if number.as_i64().is_none() && number.as_u64().is_none() =>
        {
            return Err("canonical JSON does not allow floating point numbers");
        }
        serde_json::Value::Array(values) => {
            for value in values {
                validate_canonical_json_value_inner(value, false)?;
            }
        }
        serde_json::Value::Object(object) => {
            // Field-name constraints belong to JSON Schema declarations, not
            // canonical JSON bytes. The kind-specific schema pass owns Arkret
            // property names and map-key grammars; raw external documents must
            // retain their native field names.
            for value in object.values() {
                validate_canonical_json_value_inner(value, false)?;
            }
            // Generic payload traversal accepts the two canonical timestamp
            // profiles used by v1: ordinary artifact fields use whole seconds,
            // while Event-bound create-object fields use fixed milliseconds so
            // `payload.object.created_at == Event.created_at` remains possible.
            // Kind-specific validators still enforce the narrower profile for
            // fields such as invite expiry.
            for (key, value) in object {
                if key.ends_with("_at")
                    && let Some(s) = value.as_str()
                {
                    let canonical_seconds =
                        arkret_canonical::validate_timestamp_canonical(s).is_ok();
                    let canonical_millis =
                        arkret_canonical::validate_timestamp_canonical(s).is_ok();
                    if !canonical_seconds && !canonical_millis {
                        return Err(
                            "timestamp must use canonical RFC 3339 UTC whole-second or fixed-millisecond form",
                        );
                    }
                }
            }
        }
        _ => {}
    }
    // At the top level, attempt a canonical byte roundtrip to ensure full compliance.
    if root && arkret_canonical::canonical_json_bytes(value).is_err() {
        return Err("value fails canonical JSON byte serialization");
    }
    Ok(())
}

pub fn validate_content_block(block: &serde_json::Value) -> Result<(), &'static str> {
    arkret_models_collaboration::events_payloads::validate_content_block(block)
        .map_err(|error| error.message())
}
