//! Strand / Morph patch + object-field helpers and push-route cell helpers.
//!
//! Split out of the `reducer` mod file; re-exported there so sibling
//! `apply_*` modules' `super::*` access and the
//! `crate::reducer::REALM_DESTROY_FANOUT_WINDOW_DAYS` path stay unchanged.

use std::collections::BTreeMap;

use arkret_event_draft::ProjectedEventOperation as Operation;
use serde_json::Value;

use super::DocumentVersionProjection;

pub(crate) fn utc_timestamp_z(now: chrono::DateTime<chrono::Utc>) -> String {
    arkret_canonical::format_timestamp_canonical(now)
}

/// Strand placement is owned exclusively by `ak.strand.move` / reorder and the
/// `ak.component.strand.position.v1` cell. A create payload carrying any of the
/// old metadata aliases is rejected, even on reducer replay paths that bypass
/// schema validation.
pub(crate) fn strand_position_from_create_payload(
    object: &serde_json::Map<String, Value>,
) -> Result<Option<(String, String, String)>, &'static str> {
    let Some(fields) = object
        .get("metadata")
        .and_then(Value::as_object)
        .and_then(|metadata| metadata.get("fields"))
        .and_then(Value::as_object)
    else {
        return Ok(None);
    };
    if ["board_space_id", "list_space_id", "rank"]
        .iter()
        .any(|field| fields.contains_key(*field))
    {
        return Err("schema_violation");
    }
    Ok(None)
}

/// Forbidden-wire fields (`registry/forbidden-wire-fields.json`, context
/// `strand_payload`) are rejected at create, even on reducer replay paths
/// that bypass schema validation: no registered object-root key (for example
/// `discussion_space_ref`) and no registered `metadata.fields` key may
/// appear. The reason is the registered `unknown_field`, whose description
/// names the forbidden-wire registry.
pub(crate) fn strand_forbidden_wire_field_in_create_payload(
    object: &serde_json::Map<String, Value>,
) -> Result<(), &'static str> {
    for key in object.keys() {
        if arkret_wire::forbidden_wire::forbidden_wire_path_hard_reject("strand_payload", key) {
            return Err(arkret_wire::ReasonCode::UNKNOWN_FIELD);
        }
    }
    let Some(fields) = object
        .get("metadata")
        .and_then(Value::as_object)
        .and_then(|metadata| metadata.get("fields"))
        .and_then(Value::as_object)
    else {
        return Ok(());
    };
    for key in fields.keys() {
        let path = format!("metadata.fields.{key}");
        if arkret_wire::forbidden_wire::forbidden_wire_path_hard_reject("strand_payload", &path) {
            return Err(arkret_wire::ReasonCode::UNKNOWN_FIELD);
        }
    }
    Ok(())
}

/// Forbidden-wire fields (`registry/forbidden-wire-fields.json`, context
/// `morph_payload`) are rejected at create: no registered object-root key and
/// no registered `fields` key (`fields.stage`, `fields.stage_note`, ...) may
/// appear. The reason is the registered `unknown_field`, whose description
/// names the forbidden-wire registry.
pub(crate) fn morph_forbidden_wire_field_in_create_payload(
    object: &serde_json::Map<String, Value>,
) -> Result<(), &'static str> {
    for key in object.keys() {
        if arkret_wire::forbidden_wire::forbidden_wire_path_hard_reject("morph_payload", key) {
            return Err(arkret_wire::ReasonCode::UNKNOWN_FIELD);
        }
    }
    let Some(fields) = object.get("fields").and_then(Value::as_object) else {
        return Ok(());
    };
    for key in fields.keys() {
        let path = format!("fields.{key}");
        if arkret_wire::forbidden_wire::forbidden_wire_path_hard_reject("morph_payload", &path) {
            return Err(arkret_wire::ReasonCode::UNKNOWN_FIELD);
        }
    }
    Ok(())
}

pub(crate) fn strand_position_from_lifecycle_payload(
    payload: &Value,
) -> Option<(String, String, Option<String>)> {
    let board_space_id = payload
        .get("board_space_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())?
        .to_owned();
    let list_space_id = payload
        .get("target_space_id")
        .or_else(|| payload.get("space_id"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())?
        .to_owned();
    let rank = payload
        .get("rank")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned);
    Some((board_space_id, list_space_id, rank))
}

pub(crate) enum PatchAction<'a> {
    Set(&'a Value),
    Unset,
    Ignore,
}

pub(crate) fn patch_action(value: &Value) -> PatchAction<'_> {
    let Some(object) = value.as_object() else {
        return PatchAction::Set(value);
    };
    let Some(op) = object.get("$op").and_then(Value::as_str) else {
        return PatchAction::Set(value);
    };
    match op {
        "set" | "add" => object
            .get("value")
            .map(PatchAction::Set)
            .unwrap_or(PatchAction::Ignore),
        "unset" | "remove" => PatchAction::Unset,
        _ => PatchAction::Ignore,
    }
}

pub(crate) fn patch_string_value(
    patch: &serde_json::Map<String, Value>,
    path: &str,
) -> Option<Option<String>> {
    match patch.get(path).map(patch_action)? {
        PatchAction::Set(value) => value
            .as_str()
            .filter(|value| !value.trim().is_empty())
            .map(|value| Some(value.to_owned())),
        PatchAction::Unset => Some(None),
        PatchAction::Ignore => None,
    }
}

pub fn validate_patch_semantic_safety(
    patch: &serde_json::Map<String, Value>,
    object_kind: Option<&str>,
) -> Result<(), &'static str> {
    for (path, value) in patch {
        if patch_path_targets_reducer_managed(path, object_kind) {
            return Err(arkret_wire::ReasonCode::PATCH_PATH_REDUCER_MANAGED);
        }
        if patch_op_removes_value(value) && patch_path_targets_redactable_unset(path) {
            return Err(arkret_wire::ReasonCode::PATCH_UNSET_REDACTABLE_FIELD);
        }
        if patch_entry_targets_forbidden_wire(path, value, object_kind) {
            return Err(arkret_wire::ReasonCode::PATCH_PATH_REDUCER_MANAGED);
        }
    }
    Ok(())
}

/// Whether a patch path addresses a field the generic update surface does not
/// own, decided against the registered set of `object_kind` when it is known.
///
/// The path set is the canonical projection of
/// `registry/reducer-managed-path-registry.json` and is owned by
/// `arkret_wire::patch::reducer_managed_patch_reason`; this module never spells
/// its own list. The full normalized dotted path is handed over (never just
/// the root segment) so registered dotted paths and their descendants match.
/// `None` means the object kind was not proven, so the conservative
/// object-agnostic superset applies with the same descendant-cover rule and no
/// registered carve-out is honoured (`event-and-patch.md` 4.2.5).
fn patch_path_targets_reducer_managed(path: &str, object_kind: Option<&str>) -> bool {
    let Some(subject) = normalized_patch_subject(path) else {
        return false;
    };
    if let Some(object_kind) = object_kind {
        return arkret_wire::patch::reducer_managed_patch_reason(object_kind, &subject).is_some();
    }
    arkret_wire::generated::REDUCER_MANAGED_ANY_OBJECT_PATCH_PATHS
        .iter()
        .any(|registered| arkret_wire::patch::patch_path_covers(registered, &subject))
}

/// Normalize a wire patch path to the dotted subject the registries address:
/// selector suffixes are stripped per segment, a backtick-quoted segment cannot
/// match a registered snake_case path and voids the match, and a leading
/// `object.` wrapper addresses the same fields one segment deeper.
fn normalized_patch_subject(path: &str) -> Option<String> {
    let mut segments = Vec::new();
    for segment in path.split('.') {
        segments.push(patch_segment_head(segment)?);
    }
    if segments.first() == Some(&"object") {
        segments.remove(0);
    }
    if segments.is_empty() {
        return None;
    }
    Some(segments.join("."))
}

/// The forbidden-wire contexts the generic object-patch surface enforces per
/// object kind: the payload context (dotted ids naming create-time forbidden
/// fields) plus the patch payload context (`patch:`-prefixed ids naming
/// forbidden patch paths). The sets are read from the SDK projection of
/// `registry/forbidden-wire-fields.json`; this module never spells its own
/// list.
fn forbidden_wire_contexts(object_kind: Option<&str>) -> &'static [&'static str] {
    match object_kind {
        Some("strand") => &["strand_payload", "strand_patch_payload"],
        Some("morph") => &["morph_payload", "morph_update_payload"],
        _ => &[],
    }
}

/// Whether one patch entry hits a `hard_reject` forbidden-wire entry, in any
/// representation: the dotted path itself, or a key inside a whole-object set
/// value (which the dotted path grammar cannot name).
fn patch_entry_targets_forbidden_wire(
    path: &str,
    value: &Value,
    object_kind: Option<&str>,
) -> bool {
    let contexts = forbidden_wire_contexts(object_kind);
    if contexts.is_empty() {
        return false;
    }
    let Some(subject) = normalized_patch_subject(path) else {
        return false;
    };
    if forbidden_wire_path_hit(contexts, &subject) {
        return true;
    }
    if let PatchAction::Set(Value::Object(object)) = patch_action(value) {
        return object
            .iter()
            .any(|(key, nested)| forbidden_wire_set_value_hit(contexts, &subject, key, nested));
    }
    false
}

/// Descend a whole-object set value: `{"metadata": {"fields": {"status": _}}}`
/// is judged by the same registry entries as the dotted
/// `metadata.fields.status` form.
fn forbidden_wire_set_value_hit(
    contexts: &[&'static str],
    prefix: &str,
    key: &str,
    value: &Value,
) -> bool {
    let path = format!("{prefix}.{key}");
    if forbidden_wire_path_hit(contexts, &path) {
        return true;
    }
    match value {
        Value::Object(object) => object
            .iter()
            .any(|(key, nested)| forbidden_wire_set_value_hit(contexts, &path, key, nested)),
        _ => false,
    }
}

fn forbidden_wire_path_hit(contexts: &[&'static str], path: &str) -> bool {
    contexts
        .iter()
        .any(|context| arkret_wire::forbidden_wire::forbidden_wire_path_hard_reject(context, path))
}

/// Whether a patch path addresses a registered redactable content-carrier slot.
///
/// The slot set is the canonical projection of
/// `registry/redactable-field-registry.json`; this module never spells its own
/// list. `metadata`, `metadata.summary`, `encrypted_metadata`, `body` and
/// `attachments` are ordinary optional members, not content slots, so their
/// `$op="unset"` MUST be accepted (`event-and-patch.md` §4.2.4).
fn patch_path_targets_redactable_unset(path: &str) -> bool {
    arkret_wire::generated::REDACTABLE_FIELD_PATHS
        .iter()
        .any(|slot| path == *slot || path.starts_with(&format!("{slot}.")))
}

fn patch_segment_head(segment: &str) -> Option<&str> {
    if segment.starts_with('`') {
        return None;
    }
    let head = segment.split_once('[').map_or(segment, |(head, _)| head);
    (!head.is_empty()).then_some(head)
}

fn patch_op_removes_value(value: &Value) -> bool {
    value
        .as_object()
        .and_then(|object| object.get("$op").and_then(Value::as_str))
        .is_some_and(|op| matches!(op, "unset" | "remove"))
}

pub(crate) fn patch_metadata_string_value(
    patch: &serde_json::Map<String, Value>,
    key: &str,
) -> Option<Option<String>> {
    let dotted = format!("metadata.{key}");
    if let Some(value) = patch_string_value(patch, &dotted) {
        return Some(value);
    }
    patch
        .get("metadata")
        .and_then(|metadata_patch| match patch_action(metadata_patch) {
            PatchAction::Set(value) => value.get(key).and_then(|value| {
                value
                    .as_str()
                    .filter(|value| !value.trim().is_empty())
                    .map(|value| Some(value.to_owned()))
            }),
            PatchAction::Unset => Some(None),
            PatchAction::Ignore => None,
        })
}

pub(crate) fn strand_metadata_fields_value(value: &Value) -> Option<BTreeMap<String, Value>> {
    value.as_object().map(|fields| {
        fields
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<BTreeMap<_, _>>()
    })
}

pub(crate) fn apply_metadata_fields_value(fields: &mut BTreeMap<String, Value>, value: &Value) {
    if let Some(values) = strand_metadata_fields_value(value) {
        for (field_name, field_value) in values {
            fields.insert(field_name, field_value);
        }
    }
}

pub(crate) fn strand_id_from_payload(payload: &Value) -> Option<&str> {
    payload
        .get("strand_id")
        .and_then(Value::as_str)
        .filter(|value| value.starts_with("ak:strand:"))
}

pub(crate) fn apply_strand_fields_patch(
    fields: &mut BTreeMap<String, Value>,
    patch: &serde_json::Map<String, Value>,
) {
    for (path, value) in patch {
        if path == "metadata" {
            match patch_action(value) {
                PatchAction::Set(Value::Object(metadata)) => {
                    if let Some(value) = metadata.get("fields") {
                        apply_metadata_fields_value(fields, value);
                    }
                }
                PatchAction::Unset => fields.clear(),
                PatchAction::Set(_) | PatchAction::Ignore => {}
            }
            continue;
        }
        if path == "metadata.fields" {
            match patch_action(value) {
                PatchAction::Set(value) => apply_metadata_fields_value(fields, value),
                PatchAction::Unset => fields.clear(),
                PatchAction::Ignore => {}
            }
            continue;
        }
        let Some(field_name) = path.strip_prefix("metadata.fields.") else {
            continue;
        };
        if field_name.is_empty() {
            continue;
        }
        match patch_action(value) {
            PatchAction::Set(value) => {
                fields.insert(field_name.to_owned(), value.clone());
            }
            PatchAction::Unset => {
                fields.remove(field_name);
            }
            PatchAction::Ignore => {}
        }
    }
}

/// Apply a `ak.strand.update`-style patch to a Morph's `fields` map. Unlike Strand
/// (whose profile fields moved under `metadata.fields` in spec 9dabf26), the
/// Morph object keeps `fields` at the object root (morph.schema.json), so its
/// patch paths are root-level `fields` / `fields.<name>`.
pub(crate) fn apply_morph_fields_patch(
    fields: &mut BTreeMap<String, Value>,
    patch: &serde_json::Map<String, Value>,
) {
    for (path, value) in patch {
        if path == "fields" {
            match patch_action(value) {
                PatchAction::Set(value) => apply_metadata_fields_value(fields, value),
                PatchAction::Unset => fields.clear(),
                PatchAction::Ignore => {}
            }
            continue;
        }
        let Some(field_name) = path.strip_prefix("fields.") else {
            continue;
        };
        if field_name.is_empty() {
            continue;
        }
        match patch_action(value) {
            PatchAction::Set(value) => {
                fields.insert(field_name.to_owned(), value.clone());
            }
            PatchAction::Unset => {
                fields.remove(field_name);
            }
            PatchAction::Ignore => {}
        }
    }
}

pub(crate) fn object_map_to_fields(object: Option<&Value>) -> BTreeMap<String, Value> {
    object
        .and_then(Value::as_object)
        .map(|fields| {
            fields
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default()
}

pub(crate) fn string_array_field(
    object: &serde_json::Map<String, Value>,
    key: &str,
) -> Vec<String> {
    let Some(value) = object.get(key) else {
        return Vec::new();
    };
    if let Some(items) = value.as_array() {
        return items
            .iter()
            .filter_map(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
    }
    value
        .as_object()
        .map(|items| {
            items
                .iter()
                .filter_map(|(facet, enabled)| enabled.as_bool().unwrap_or(true).then_some(facet))
                .filter(|value| !value.trim().is_empty())
                .cloned()
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

pub(crate) fn projection_object_realm_id(
    object: &serde_json::Map<String, Value>,
    operation: &Operation,
) -> String {
    object
        .get("realm_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| operation.realm_id.to_string())
}

pub fn morph_document_body(fields: &BTreeMap<String, Value>) -> Option<Value> {
    fields
        .get("document")
        .or_else(|| fields.get("body"))
        .cloned()
        .filter(|value| !value.is_null())
}

pub(crate) fn document_version_from_operation(
    morph_id: &str,
    operation: &Operation,
    body: Value,
) -> DocumentVersionProjection {
    let event_id = operation.context.event_id.to_string();
    let body_digest = arkret_canonical::canonical_sha256(&body)
        .unwrap_or_else(|_| arkret_canonical::sha256_digest(body.to_string().as_bytes()));
    DocumentVersionProjection {
        version_id: format!("{morph_id}:version:{event_id}"),
        event_id,
        author: operation.context.sender.to_string(),
        created_at: operation.created_at,
        body_digest,
        body,
    }
}

/// Spec T07 — federation fanout window for erasure receipts emitted by
/// `ak.realm.destroy`. Spec: 30 days.
pub const REALM_DESTROY_FANOUT_WINDOW_DAYS: i64 = 30;

/// Human-facing redaction justification. Both redaction payload classes
/// (`message_redact_payload`, `cross_object_redaction_payload`) are closed and
/// register exactly one such member, `reason`; alternative spellings are not
/// wire-reachable.
pub(crate) fn redaction_human_reason(payload: &Value) -> Option<String> {
    payload
        .get("reason")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn patch(value: Value) -> serde_json::Map<String, Value> {
        value.as_object().expect("patch object").clone()
    }

    #[test]
    fn forbidden_wire_dotted_path_is_rejected_for_strand() {
        let patch = patch(json!({"metadata.fields.status": "done"}));
        assert_eq!(
            validate_patch_semantic_safety(&patch, Some("strand")),
            Err(arkret_wire::ReasonCode::PATCH_PATH_REDUCER_MANAGED)
        );
    }

    #[test]
    fn forbidden_wire_whole_fields_set_is_rejected_for_strand() {
        let patch = patch(json!({
            "metadata.fields": {"jira_status": "open", "status": "done"}
        }));
        assert_eq!(
            validate_patch_semantic_safety(&patch, Some("strand")),
            Err(arkret_wire::ReasonCode::PATCH_PATH_REDUCER_MANAGED)
        );
    }

    #[test]
    fn forbidden_wire_nested_metadata_set_is_rejected_for_strand() {
        let patch = patch(json!({
            "metadata": {"fields": {"stage_reason": "because"}}
        }));
        assert_eq!(
            validate_patch_semantic_safety(&patch, Some("strand")),
            Err(arkret_wire::ReasonCode::PATCH_PATH_REDUCER_MANAGED)
        );
    }

    #[test]
    fn forbidden_wire_patch_only_paths_are_rejected_for_strand() {
        for value in [
            json!({"fields.assignee": "ak:actor:someone"}),
            json!({"fields": {"assignees": ["ak:actor:someone"]}}),
        ] {
            let patch = patch(value);
            assert_eq!(
                validate_patch_semantic_safety(&patch, Some("strand")),
                Err(arkret_wire::ReasonCode::PATCH_PATH_REDUCER_MANAGED)
            );
        }
    }

    #[test]
    fn ordinary_strand_patch_paths_are_accepted() {
        for value in [
            json!({"metadata.title": "renamed"}),
            json!({"metadata.fields.jira_status": "open"}),
            json!({"metadata": {"fields": {"jira_status": "open"}}}),
        ] {
            let patch = patch(value);
            assert_eq!(
                validate_patch_semantic_safety(&patch, Some("strand")),
                Ok(())
            );
        }
    }

    #[test]
    fn forbidden_wire_paths_are_rejected_for_morph() {
        for value in [
            json!({"fields.stage": "seedling"}),
            json!({"fields": {"stage_note": "note", "title": "kept"}}),
        ] {
            let patch = patch(value);
            assert_eq!(
                validate_patch_semantic_safety(&patch, Some("morph")),
                Err(arkret_wire::ReasonCode::PATCH_PATH_REDUCER_MANAGED)
            );
        }
        let patch = patch(json!({"fields": {"title": "kept"}}));
        assert_eq!(
            validate_patch_semantic_safety(&patch, Some("morph")),
            Ok(())
        );
    }

    #[test]
    fn forbidden_wire_check_is_a_no_op_without_a_proven_object_kind() {
        // `metadata.fields.status` is forbidden for strands only; with no
        // proven kind the conservative reducer-managed superset still applies
        // but the forbidden-wire contexts do not.
        let patch = patch(json!({"metadata.fields.status": "done"}));
        assert_eq!(validate_patch_semantic_safety(&patch, None), Ok(()));
    }

    #[test]
    fn strand_create_payload_rejects_registered_forbidden_fields() {
        for object in [
            json!({"metadata": {"fields": {"status": "done"}}}),
            json!({"metadata": {"fields": {"assigned_to": "ak:actor:someone"}}}),
            json!({"discussion_space_ref": "ak:space:some"}),
        ] {
            let object = object.as_object().expect("create object");
            assert_eq!(
                strand_forbidden_wire_field_in_create_payload(object),
                Err(arkret_wire::ReasonCode::UNKNOWN_FIELD)
            );
        }
        let object = json!({"metadata": {"title": "t", "fields": {"jira_status": "open"}}});
        let object = object.as_object().expect("create object");
        assert_eq!(
            strand_forbidden_wire_field_in_create_payload(object),
            Ok(())
        );
    }

    #[test]
    fn morph_create_payload_rejects_registered_forbidden_fields() {
        for leaf in [
            "lifecycle",
            "progress_state",
            "stage",
            "stage_changed_at",
            "stage_note",
            "stage_reason",
        ] {
            let object = json!({"fields": {leaf: "x"}});
            let object = object.as_object().expect("create object");
            assert_eq!(
                morph_forbidden_wire_field_in_create_payload(object),
                Err(arkret_wire::ReasonCode::UNKNOWN_FIELD),
                "fields.{leaf} is hard_reject in morph_payload"
            );
        }
        let object = json!({"fields": {"title": "kept"}, "morph_kind": "document"});
        let object = object.as_object().expect("create object");
        assert_eq!(morph_forbidden_wire_field_in_create_payload(object), Ok(()));
    }
}
