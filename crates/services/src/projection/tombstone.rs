use std::collections::HashMap;

use serde_json::{Value, json};

use crate::events::ProjectedEvent as ProjectionEventRecord;
use crate::governance::RetentionTombstoneRecord;

/// Marker retained for decoding projection rows written by older runtimes.
/// Current v1 erasure receipts are durable facts and do not synthesize this
/// value into the shared current projection.
pub const ERASED_USER_PLACEHOLDER: &str = "[user erased]";
pub const RETENTION_EXPIRED_PLACEHOLDER: &str = "[expired]";

const TOMBSTONE_DERIVED_FIELD_KEYS: &[&str] = &[
    "attachment_preview",
    "attachment_preview_key",
    "attachments",
    "blob_preview",
    "blob_preview_bytes",
    "blob_preview_key",
    "blob_preview_key_ref",
    "blob_refs",
    "comment_summary",
    "content",
    "encrypted_content",
    "in_reply_to",
    "media",
    "mentions",
    "message_key",
    "message_key_ref",
    "poll",
    "preview",
    "push_snippet",
    "push_snippet_plaintext",
    "reaction_summary",
    "reactions",
    "redacted_at",
    "redaction",
    "redaction_ref",
    "relations",
    "reply_to",
    "search_terms",
    "search_tokens",
    "search_index",
    "search_index_entries",
    "search_index_manifest",
    "snippet",
    "thumbnails",
];

#[derive(Clone, Debug)]
pub struct MessageRedactionMarker {
    pub redacted_at: chrono::DateTime<chrono::Utc>,
    pub redaction_event_id: String,
}

pub fn message_redactions_from_events(
    events: &[ProjectionEventRecord],
    projection: &coland_domain::reducer::ProjectionState,
) -> HashMap<String, MessageRedactionMarker> {
    let mut redactions = HashMap::new();
    for redaction_event in events
        .iter()
        .filter(|event| arkret_wire::events::kinds::is_redaction_kind(&event.event_kind))
    {
        let Some(target_ref) =
            coland_domain::reducer::message_redaction_target_ref(&redaction_event.payload)
        else {
            continue;
        };
        let target_message_id = projection
            .messages
            .values()
            .find(|message| {
                message.message_id == target_ref
                    || message.event_id == target_ref
                    || message.event_id == target_ref.replacen("ak:message:", "ak:event:", 1)
            })
            .map(|message| message.message_id.as_str())
            .unwrap_or(target_ref.as_str());
        let marker = MessageRedactionMarker {
            redacted_at: redaction_event.created_at,
            redaction_event_id: redaction_event.event_id.clone(),
        };
        let mut matched = false;
        for message in projection
            .messages
            .values()
            .filter(|message| message.message_id == target_message_id)
        {
            redactions.insert(message.event_id.clone(), marker.clone());
            matched = true;
        }
        if !matched && target_ref.starts_with("ak:message:") {
            redactions.insert(
                target_ref.replacen("ak:message:", "ak:event:", 1),
                marker.clone(),
            );
        }
        // Canonical scans may have no persisted message projection at all.
        // Every accepted revision of the target keeps a redacted history slot.
        for event in events {
            if matches!(
                event.event_kind,
                arkret_wire::EventKind::MessageCreate | arkret_wire::EventKind::MessageRevise
            ) && (event.event_id == target_ref
                || event.event_id == target_ref.replacen("ak:message:", "ak:event:", 1)
                || event.payload.get("message_id").and_then(Value::as_str)
                    == Some(target_message_id))
            {
                redactions.insert(event.event_id.clone(), marker.clone());
            }
        }
    }
    redactions
}

pub fn event_is_visible(event: &ProjectionEventRecord) -> bool {
    // A redaction Event is durable audit history, but the projected timeline
    // exposes its target slots after applying tombstones rather than adding a
    // second visible timeline row for the reducer command itself.
    !arkret_wire::events::kinds::is_redaction_kind(&event.event_kind)
}

pub fn tombstone_projection_event_for_message_redaction(
    projection: &coland_domain::reducer::ProjectionState,
    durable_redactions: &HashMap<String, MessageRedactionMarker>,
    event: &mut ProjectionEventRecord,
) {
    if !matches!(
        &event.event_kind,
        arkret_wire::EventKind::MessageCreate | arkret_wire::EventKind::MessageRevise
    ) {
        return;
    }
    let cell = projection
        .messages
        .get(&event.event_id)
        .and_then(|message| projection.redaction_cell_for_message(message));
    let durable = durable_redactions.get(&event.event_id);
    let Some(redacted_at) = cell
        .map(|cell| cell.redacted_at)
        .or_else(|| durable.map(|marker| marker.redacted_at))
    else {
        return;
    };
    let redaction_ref = cell
        .and_then(|cell| cell.redaction_event_id.as_deref())
        .or_else(|| durable.map(|marker| marker.redaction_event_id.as_str()));
    arkret_models_collaboration::events_payloads::redaction::redaction_tombstone_message_value(
        &mut event.payload,
        redacted_at,
        redaction_ref,
    );
}

pub fn tombstone_projection_event_for_retention(
    event: &mut ProjectionEventRecord,
    tombstone: &RetentionTombstoneRecord,
) {
    event.payload = retention_tombstone_payload_value(&event.payload, tombstone);
}

pub fn stub_pin_projection_event_for_invisible_target(
    projection: &coland_domain::reducer::ProjectionState,
    event: &mut ProjectionEventRecord,
) {
    if !arkret_wire::events::kinds::is_pin_kind(&event.event_kind) {
        return;
    }
    let Some(target_ref) = event.payload.get("target_ref").and_then(Value::as_str) else {
        event.payload = pin_target_locked_stub_payload(&event.payload);
        return;
    };
    if projection.pin_target_is_visible_for_projection(target_ref) {
        return;
    }
    event.payload = pin_target_locked_stub_payload(&event.payload);
}

pub fn retention_tombstone_payload_value(
    payload: &Value,
    tombstone: &RetentionTombstoneRecord,
) -> Value {
    let mut value = payload.clone();
    let Some(object) = value.as_object_mut() else {
        return json!({
            "content": placeholder_content(RETENTION_EXPIRED_PLACEHOLDER),
            "retention_tombstone": true,
            "retention_state": "tombstoned",
            "retention_reason": tombstone.reason.as_str(),
            "retention_expired_at": arkret_canonical::format_timestamp_canonical(
                tombstone.expired_at
            ),
            "retention_tombstoned_at": arkret_canonical::format_timestamp_canonical(
                tombstone.tombstoned_at
            ),
            "retention_seal_preserved": tombstone.sealed,
            "physical_delete": false,
            "retention_risk_ui": tombstone.sealed,
            "retention_risk_audit": tombstone.sealed,
            "retention_risk_reason": retention_risk_reason(tombstone),
        });
    };
    strip_tombstone_derived_fields(object);
    object.insert("retention_tombstone".to_owned(), json!(true));
    object.insert("retention_state".to_owned(), json!("tombstoned"));
    object.insert(
        "retention_reason".to_owned(),
        json!(tombstone.reason.as_str()),
    );
    object.insert(
        "retention_expired_at".to_owned(),
        json!(arkret_canonical::format_timestamp_canonical(
            tombstone.expired_at
        )),
    );
    object.insert(
        "retention_tombstoned_at".to_owned(),
        json!(arkret_canonical::format_timestamp_canonical(
            tombstone.tombstoned_at
        )),
    );
    object.insert(
        "retention_seal_preserved".to_owned(),
        json!(tombstone.sealed),
    );
    object.insert("physical_delete".to_owned(), json!(false));
    insert_retention_risk_markers(object, tombstone);
    object.insert(
        "content".to_owned(),
        placeholder_content(RETENTION_EXPIRED_PLACEHOLDER),
    );
    object.insert("encrypted".to_owned(), json!(false));
    value
}

fn strip_tombstone_derived_fields(object: &mut serde_json::Map<String, Value>) {
    for key in TOMBSTONE_DERIVED_FIELD_KEYS {
        object.remove(*key);
    }
}

fn insert_retention_risk_markers(
    object: &mut serde_json::Map<String, Value>,
    tombstone: &RetentionTombstoneRecord,
) {
    object.insert(
        "retention_risk_ui".to_owned(),
        json!(retention_risk_ui_flag(tombstone)),
    );
    object.insert(
        "retention_risk_audit".to_owned(),
        json!(retention_risk_audit_flag(tombstone)),
    );
    object.insert(
        "retention_risk_reason".to_owned(),
        json!(retention_risk_reason(tombstone)),
    );
}

pub fn retention_risk_ui_flag(tombstone: &RetentionTombstoneRecord) -> bool {
    tombstone.sealed
}

pub fn retention_risk_audit_flag(tombstone: &RetentionTombstoneRecord) -> bool {
    tombstone.sealed
}

pub fn retention_risk_reason(tombstone: &RetentionTombstoneRecord) -> &'static str {
    if tombstone.sealed {
        "sealed_history_or_backup_may_retain_ciphertext"
    } else {
        "none"
    }
}

fn placeholder_content(body: &str) -> Value {
    arkret_models_collaboration::events_payloads::message::ContentBlock::text(body)
        .to_value()
        .expect("ContentBlock text serialization is infallible")
}

fn pin_target_locked_stub_payload(payload: &Value) -> Value {
    let pin_scope = payload.get("pin_scope").cloned().unwrap_or(Value::Null);
    json!({
        "pin_scope": pin_scope,
        "target": {
            "visibility": "locked"
        },
        "target_stub": true
    })
}

#[cfg(test)]
mod tests {
    use coland_domain::reducer::{MessageState, ProjectionState, RedactionCellValue};

    use super::*;

    fn fixed_time(value: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(value)
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

    fn retention_tombstone(
        event_id: &str,
        realm_id: &str,
        sealed: bool,
    ) -> RetentionTombstoneRecord {
        RetentionTombstoneRecord {
            event_id: event_id.to_owned(),
            realm_id: realm_id.to_owned(),
            reason: "retention_policy.ttl".to_owned(),
            policy_ttl_seconds: 60,
            expired_at: fixed_time("2020-01-01T00:01:00.000Z"),
            tombstoned_at: fixed_time("2020-01-01T00:02:00.000Z"),
            sealed,
        }
    }

    #[test]
    fn retention_tombstone_strips_derived_surfaces_and_marks_risk() {
        let event_id = "ak:event:Adpb76fsaup_4Y_cV39of-L1_k6Nv1kSoCzXa9TM4szu";
        let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
        let tombstone = retention_tombstone(event_id, realm_id, true);
        let payload = json!({
            "content": {"kind": "ak.content.text", "body": "secret"},
            "search_index": {"terms": ["secret"]},
            "push_snippet": "secret push",
            "blob_preview_key": "secret-preview-key",
            "blob_preview_bytes": "secret-preview-bytes",
            "blob_preview": {"caption": "secret"},
            "message_key": "secret-message-key",
        });

        let payload = retention_tombstone_payload_value(&payload, &tombstone);

        assert_eq!(payload["retention_tombstone"], json!(true));
        assert_eq!(payload["retention_state"], json!("tombstoned"));
        assert_eq!(payload["retention_risk_ui"], json!(true));
        assert_eq!(payload["retention_risk_audit"], json!(true));
        assert_eq!(
            payload["retention_risk_reason"],
            json!("sealed_history_or_backup_may_retain_ciphertext")
        );
        assert_eq!(
            payload["content"]["body"],
            json!(RETENTION_EXPIRED_PLACEHOLDER)
        );
        assert!(payload.get("search_index").is_none());
        assert!(payload.get("push_snippet").is_none());
        assert!(payload.get("blob_preview_key").is_none());
        assert!(payload.get("blob_preview_bytes").is_none());
        assert!(payload.get("blob_preview").is_none());
        assert!(payload.get("message_key").is_none());
        assert!(payload.get("cache_invalidation").is_none());
    }

    #[test]
    fn durable_redaction_event_tombstones_message_when_live_cell_is_unavailable() {
        let event_id = "ak:event:AYqEzQ3jW02EHkMjxFQTlyeowxPQXJE4fI6JGOnzi23t";
        let redaction_event_id = "ak:event:Adpb76fsaup_4Y_cV39of-L1_k6Nv1kSoCzXa9TM4szu";
        let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
        let now = fixed_time("2020-01-01T00:00:00.000Z");
        let mut projection = ProjectionState::new();
        let message_id = coland_domain::reducer::message_id_from_event_id(event_id);
        projection.messages.insert(
            event_id.to_owned(),
            MessageState {
                event_id: event_id.to_owned(),
                message_id: message_id.clone(),
                realm_id: realm_id.to_owned(),
                sender: "did:web:alice.example".to_owned(),
                thread_id: realm_id.to_owned(),
                content: json!({"kind": "ak.content.text", "body": "secret"}),
                encrypted: false,
                operation_id: "ak:operation:01904100-0000-7000-8000-0000000000a2".to_owned(),
                created_at: now,
                revision_of: None,
                redacted_at: None,
            },
        );
        let mut message_event = ProjectionEventRecord {
            event_id: event_id.to_owned(),
            realm_id: realm_id.to_owned(),
            event_kind: arkret_wire::EventKind::MessageCreate,
            operation_kind: "create".to_owned(),
            operation_id: None,
            sender: Some("did:web:alice.example".to_owned()),
            payload: json!({"content": {"kind": "ak.content.text", "body": "secret"}}),
            created_at: now,
            received_at: now,
        };
        let redaction_event = ProjectionEventRecord {
            event_id: redaction_event_id.to_owned(),
            realm_id: realm_id.to_owned(),
            event_kind: arkret_wire::EventKind::MessageRedact,
            operation_kind: "redact".to_owned(),
            operation_id: None,
            sender: Some("did:web:alice.example".to_owned()),
            payload: json!({"message_id": message_id}),
            created_at: now,
            received_at: now,
        };

        let redactions =
            message_redactions_from_events(&[message_event.clone(), redaction_event], &projection);
        tombstone_projection_event_for_message_redaction(
            &projection,
            &redactions,
            &mut message_event,
        );

        assert_eq!(message_event.payload["redacted"], json!(true));
        assert_eq!(message_event.payload["state"], json!("redacted"));
        assert_eq!(
            message_event.payload["redaction_ref"],
            json!(redaction_event_id)
        );
        assert!(!message_event.payload.to_string().contains("secret"));
    }

    #[test]
    fn pin_projection_event_for_redacted_target_is_stubbed() {
        let event_id = "ak:event:AYqEzQ3jW02EHkMjxFQTlyeowxPQXJE4fI6JGOnzi23t";
        let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
        let now = chrono::Utc::now();
        let mut projection = ProjectionState::new();
        projection.messages.insert(
            event_id.to_owned(),
            MessageState {
                event_id: event_id.to_owned(),
                message_id: coland_domain::reducer::message_id_from_event_id(event_id),
                realm_id: realm_id.to_owned(),
                sender: "did:web:alice.example".to_owned(),
                thread_id: realm_id.to_owned(),
                content: json!({"kind": "ak.content.text", "body": "secret"}),
                encrypted: false,
                operation_id: "ak:operation:01904100-0000-7000-8000-0000000000a2".to_owned(),
                created_at: now,
                revision_of: None,
                redacted_at: Some(now),
            },
        );
        projection.redaction_cells.insert(
            event_id.to_owned(),
            RedactionCellValue {
                redacted_at: now,
                by: "did:web:alice.example".to_owned(),
                reason: Some("policy".to_owned()),
                redaction_event_id: None,
            },
        );
        let mut event = ProjectionEventRecord {
            event_id: "ak:operation:01904100-0000-7000-8000-0000000000a3".to_owned(),
            realm_id: realm_id.to_owned(),
            event_kind: arkret_wire::EventKind::PinAdd,
            operation_kind: "create".to_owned(),
            operation_id: None,
            sender: Some("did:web:alice.example".to_owned()),
            payload: json!({
                "pin_scope": {"kind": "realm", "id": realm_id},
                "target_ref": event_id,
                "rank": "a0",
                "note": "secret note"
            }),
            created_at: now,
            received_at: now,
        };

        stub_pin_projection_event_for_invisible_target(&projection, &mut event);

        assert_eq!(event.payload["target_stub"], json!(true));
        assert_eq!(event.payload["target"]["visibility"], json!("locked"));
        assert!(event.payload.get("target_ref").is_none());
        assert!(event.payload.get("note").is_none());
    }
}
