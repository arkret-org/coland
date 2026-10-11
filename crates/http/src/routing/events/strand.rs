//! Strand ID derivation + discussion-track projection helpers.
//!
//! Realm companion Strand IDs are obtained only by re-tagging an already
//! validated canonical Realm ID. Invalid input fails closed; it is never hashed
//! into a string that merely looks like a protocol Strand ID. v1 Message
//! payloads expose the discussion track as the const string `discussion`.
//!
//! All fns are `pub` because sync/projection writers consume them.
//! This is a derivation layer the server fakes for clients that already
//! speak the strand protocol; a future real `ak.strand.*` reducer state
//! will replace it once the wire schema lands.
//!
//! Naming boundary: a Strand is the object/container projected for a Realm.
//! Message `thread_id` is a message-layer discussion grouping within that
//! container; it is not a synonym for `strand_id`.

use coland_services::events::ProjectedEvent as ProjectionEventRecord;
use serde_json::json;

use super::{now, realm_discoverability};
use crate::state::AppState;

pub fn retag_typed_id(value: &str, from_prefix: &str, to_prefix: &str) -> Option<String> {
    value
        .strip_prefix(from_prefix)
        .map(|suffix| format!("{to_prefix}{suffix}"))
}

pub fn strand_id_from_realm_id(realm_id: &str) -> Option<String> {
    let realm_id = arkret_identifiers::RealmId::new(realm_id.to_owned()).ok()?;
    retag_typed_id(realm_id.as_str(), "ak:realm:", "ak:strand:")
}

pub fn message_id_from_event_id(event_id: &str) -> String {
    retag_typed_id(event_id, "ak:event:", "ak:message:")
        .unwrap_or_else(|| format!("ak:message:{event_id}"))
}

pub fn default_discussion_track(_strand_id: &str, _track_id: &str) -> serde_json::Value {
    json!("discussion")
}

pub fn strand_id_for_projection_event(event: &ProjectionEventRecord) -> Option<String> {
    event
        .payload
        .get("strand_id")
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned)
        .or_else(|| strand_id_from_realm_id(&event.realm_id))
}

pub fn discussion_track_for_projection_event(
    event: &ProjectionEventRecord,
    strand_id: Option<&str>,
) -> Option<serde_json::Value> {
    let strand_id = strand_id?;
    Some(default_discussion_track(strand_id, event.realm_id.as_str()))
}

pub async fn strand_history_access_for_realm(state: &AppState, realm_id: &str) -> &'static str {
    if realm_discoverability(state, realm_id).await == "public" {
        "shared"
    } else {
        "joined"
    }
}

pub async fn strand_projection_for_realm(
    state: &AppState,
    realm_id: &str,
    title: &str,
    summary: Option<&str>,
) -> Option<serde_json::Value> {
    let strand_id = strand_id_from_realm_id(realm_id)?;
    let meta = state.realms().realm_metadata(realm_id).await.ok().flatten();
    let owner = match meta.as_ref() {
        Some(meta) => serde_json::from_str::<arkret_wire::ActorId>(&meta.owner).ok()?,
        None => arkret_wire::ActorId::service(
            arkret_wire::DidCoreId::new(state.service_id().clone()).ok()?,
        ),
    };
    let created_at = meta
        .as_ref()
        .map(|meta| meta.created_at)
        .unwrap_or_else(now);
    let updated_at = meta
        .as_ref()
        .map(|meta| meta.updated_at)
        .unwrap_or(created_at);
    let deleted = meta.as_ref().is_some_and(|meta| meta.deleted);
    let history_access = strand_history_access_for_realm(state, realm_id).await;
    // `kind: "room"` and `room_kind` were removed in revision 0a5ab85; Realm
    // is the v1 boundary and the Strand.kind discriminator MUST be a v1 value
    // (e.g. "discussion").
    Some(json!({
        "id": strand_id,
        "strand_id": strand_id,
        "type": "strand",
        "schema": arkret_wire::SchemaId::STRAND_V1,
        "realm_id": realm_id,
        "kind": "discussion",
        "title": title,
        "description": summary,
        "state": if deleted { "archived" } else { "active" },
        "primary_track": "discussion",
        "tracks": {
            "synthesis": {
                "enabled": false,
                "fields": {}
            },
            "discussion": {
                "enabled": true,
                "track_kind": "discussion",
                "history_access": history_access,
                "fields": {}
            }
        },
        "created_by": owner,
        "created_at": created_at,
        "updated_by": owner,
        "updated_at": updated_at
    }))
}

#[cfg(test)]
mod tests {
    use super::strand_id_from_realm_id;

    #[test]
    fn realm_companion_strand_retags_only_a_canonical_realm_id() {
        let realm_id = "ak:realm:AfCuujQKAeVc_PA4WCk3VM9_LohZEwMUV5MMDJNVbFze";
        assert_eq!(
            strand_id_from_realm_id(realm_id).as_deref(),
            Some("ak:strand:AfCuujQKAeVc_PA4WCk3VM9_LohZEwMUV5MMDJNVbFze")
        );
    }

    #[test]
    fn invalid_realm_never_becomes_a_strand_shaped_hash_fallback() {
        assert_eq!(strand_id_from_realm_id("invalid-realm-row"), None);
        assert_eq!(strand_id_from_realm_id("ak:realm:not-a-token"), None);
    }
}
