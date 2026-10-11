use arkret_event_draft::ProjectedEventOperation as Operation;
use coland_services::events::ProjectedEvent as ProjectionEventRecord;

use super::*;

pub fn projection_event_from_operation(
    operation: &Operation,
    _sender_fallback: Option<&str>,
) -> ProjectionEventRecord {
    let event_id = operation_event_id(operation);
    ProjectionEventRecord {
        event_id,
        realm_id: operation.realm_id.to_string(),
        event_kind: operation.event_kind.clone(),
        operation_kind: operation_type_string(operation),
        operation_id: Some(operation.operation_id.to_string()),
        sender: Some(operation.context.sender.to_string()),
        payload: operation.payload.clone(),
        created_at: operation.created_at,
        received_at: now(),
    }
}
