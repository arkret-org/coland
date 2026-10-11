//! Media aggregation and Realm `media_service` admin projections.
//!
//! Shared by the coland producer
//! (`coland/crates/http/src/routing/admin/media.rs`) and the codmin
//! operator console, so a field rename breaks both sides at compile time.

use std::collections::BTreeMap;

use arkret_models_collaboration::events_payloads::MediaServiceFocus;
use serde::{Deserialize, Serialize};

/// Blob count and byte total for one grouping key.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AdminMediaBucket {
    pub count: u64,
    pub total_size: u64,
}

/// Per-uploader media roll-up row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AdminMediaByActorRow {
    pub actor_id: String,
    pub display_name: Option<String>,
    pub blob_count: u64,
    pub total_size: u64,
}

/// `GET /_coland/admin/media/statistics` response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AdminMediaStatistics {
    pub total_blobs: u64,
    pub total_size: u64,
    pub encrypted_count: u64,
    /// Always `0` today: coland has no quarantine store for blobs, so the
    /// counter is reported rather than invented.
    pub quarantined_count: u64,
    pub by_media_type: BTreeMap<String, AdminMediaBucket>,
    pub by_realm: BTreeMap<String, AdminMediaBucket>,
    pub by_actor: Vec<AdminMediaByActorRow>,
}

/// `GET /_coland/admin/media/by-actor` response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AdminMediaByActorList {
    pub data: Vec<AdminMediaByActorRow>,
    pub total: usize,
    pub next_cursor: Option<String>,
}

/// Effective `ak.component.realm.media_service.v1` cell for a Realm,
/// surfaced read-only. `foci` is reducer-projected; nothing here is
/// operator-mutable, so the console renders it without an edit affordance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AdminRealmMediaService {
    /// Realm identifier (security boundary).
    pub realm_id: String,
    /// Media service DID the foci are sealed to; absent until the Realm
    /// commits a media_service epoch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub foci: Vec<MediaServiceFocus>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn media_service_without_epoch_serializes_sparsely() {
        let wire = serde_json::to_value(AdminRealmMediaService {
            realm_id: "ak:realm:1".to_owned(),
            service_id: None,
            foci: Vec::new(),
        })
        .expect("serialize");
        assert_eq!(wire, serde_json::json!({ "realm_id": "ak:realm:1" }));
    }
}
