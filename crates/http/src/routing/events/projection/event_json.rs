use arkret_event_draft::ProjectedEventOperation as Operation;
use coland_services::events::ProjectedEvent as ProjectionEventRecord;
use serde_json::json;

use super::*;

pub fn projection_event_json(event: &ProjectionEventRecord) -> serde_json::Value {
    let strand_id = strand_id_for_projection_event(event);
    let track = discussion_track_for_projection_event(event, strand_id.as_deref());
    let mut value = json!({
        "event_id": event.event_id,
        "message_id": message_id_from_event_id(&event.event_id),
        "realm_id": event.realm_id,
        "event_kind": event.event_kind.as_str(),
        "operation_kind": event.operation_kind,
        "operation_id": event.operation_id,
        "sender": event.sender,
        "payload": event.payload,
        "created_at": event.created_at,
    });
    if let Some(object) = value.as_object_mut() {
        if let Some(sender) = event.sender.as_deref().filter(|sender| !sender.is_empty()) {
            object.insert("actor_id".to_owned(), json!(sender));
            object.insert("sender_actor_id".to_owned(), json!(sender));
        }
        if let Some(strand_id) = strand_id {
            object.insert("strand_id".to_owned(), json!(strand_id));
        }
        if let Some(track) = track {
            object.insert("track_name".to_owned(), track);
        }
    }
    value
}

pub fn operation_event_id(operation: &Operation) -> String {
    operation.context.event_id.to_string()
}

pub fn operation_type_string(operation: &Operation) -> String {
    serde_json::to_value(&operation.operation_kind)
        .ok()
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .unwrap_or_else(|| "create".to_owned())
}
