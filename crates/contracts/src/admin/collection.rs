//! Rows served by the deployment-local admin collection snapshot
//! (`GET /_coland/admin/{resource}`) plus the Realm detail endpoints
//! (`GET /_coland/admin/realms/{realm_id}` and `.../members`).
//!
//! Every row below is the single definition shared by the coland producer
//! (`coland/crates/http/src/routing/admin/collection.rs`) and the codmin
//! operator console. Renaming a field here is a compile error on both
//! sides, which is the whole point: the previous hand-mirrored DTOs let a
//! server-side rename pass compilation and blank the column at runtime.
//!
//! All rows are `deny_unknown_fields`, so a producer that grows a field
//! without updating this contract fails the consumer at the boundary
//! instead of silently dropping it.

use arkret_identifiers::DidCoreId;
use arkret_wire::{Discoverability, EventKind, JoinRule, OperationId, OperationKind, RealmId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Realm classification (`realm-and-space.md`). Closed set: an unknown wire
/// value fails deserialization, and the producer projects an unrecognised
/// stored class as `None` rather than emitting a value the console cannot
/// parse.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RealmClass {
    PrincipalControl,
    Collaboration,
}

impl RealmClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrincipalControl => "principal_control",
            Self::Collaboration => "collaboration",
        }
    }

    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "principal_control" => Some(Self::PrincipalControl),
            "collaboration" => Some(Self::Collaboration),
            _ => None,
        }
    }
}

/// One Realm row. A Realm is the security boundary; Space containers are
/// separate navigation containers and are projected by [`AdminSpaceView`].
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AdminRealmItem {
    /// Discriminator carried by every collection row (`"realm"`).
    pub kind: String,
    pub id: String,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub strand: Value,
    pub strand_id: String,
    pub realm_id: String,
    pub title: String,
    pub topic: Option<String>,
    pub category: Option<String>,
    /// `None` when the directory holds no class or an unrecognised one.
    pub realm_class: Option<RealmClass>,
    /// Discoverability is a closed registry value; the producer projects an
    /// unrecognised stored string as `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub discoverability: Option<Discoverability>,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub default_join_rule: Option<JoinRule>,
    pub tags: Vec<String>,
    pub public: bool,
    pub member_count: usize,
    pub members: Vec<String>,
    pub created_by: Option<DidCoreId>,
    pub history_access: Option<String>,
    pub is_encrypted: bool,
    /// Mirrors `deleted`; kept because the console renders a blocked badge.
    pub is_blocked: bool,
    pub plaintext_visible_services: Vec<String>,
    pub deleted: bool,
    #[serde(
        default,
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(
        default,
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub updated_at: Option<DateTime<Utc>>,
}

/// Lifecycle state of a Space container, mirroring the reducer's
/// `SpaceContainerLifecycleState`. Closed set; unknown wire values fail
/// deserialization.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum SpaceHealth {
    Active,
    Archived,
    Tombstoned,
}

impl SpaceHealth {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Archived => "archived",
            Self::Tombstoned => "tombstoned",
        }
    }
}

/// One Space container row. Spaces are authorization-transparent navigation
/// containers; `realm_id` names the Realm that owns the security boundary.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AdminSpaceView {
    pub id: String,
    pub name: String,
    /// Home Realm of the container — the security boundary the Space
    /// inherits authorization from.
    pub realm_id: String,
    /// Container kind as declared by the space component cell.
    pub kind: String,
    pub member_count: usize,
    pub health: SpaceHealth,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    pub parent_space_id: Option<String>,
}

/// One federated operation row. `GET /_coland/admin/federation` streams
/// operations, not peer-health rows.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AdminFederationOperation {
    /// Discriminator carried by every collection row
    /// (`"federation_operation"`).
    pub kind: String,
    /// Stable identifier for the operation; also the detail-page key.
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub operation_id: OperationId,
    /// Realm the operation belongs to. Always present — a projected
    /// operation is always Realm-scoped.
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub realm_id: RealmId,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub operation_kind: OperationKind,
    /// Canonical Event kind the operation projects into.
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub canonical_kind: EventKind,
    /// Discussion strand the operation projects into, when derivable.
    pub strand_id: Option<String>,
    /// Discussion track, when the operation projects into a strand.
    pub track: Option<String>,
    /// Operation digest; `None` when digest computation failed server-side.
    pub digest: Option<String>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
}

/// One stored blob row of `GET /_coland/admin/media`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AdminMediaView {
    /// Discriminator carried by every collection row (`"media"`).
    pub kind: String,
    /// Content digest of the blob — the durable row identity.
    pub sha256: String,
    pub media_type: String,
    pub filename: Option<String>,
    pub realm_id: Option<String>,
    pub encrypted: bool,
    pub uploaded_by: DidCoreId,
    pub size_bytes: u64,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn realm_class_is_a_closed_set() {
        assert_eq!(
            RealmClass::from_wire("principal_control"),
            Some(RealmClass::PrincipalControl)
        );
        assert!(RealmClass::from_wire("PrincipalControl").is_none());
        assert!(serde_json::from_value::<RealmClass>(serde_json::json!("nope")).is_err());
    }

    #[test]
    fn space_row_rejects_unknown_health_and_unknown_fields() {
        let base = serde_json::json!({
            "id": "ak:space:1",
            "name": "Space",
            "realm_id": "ak:realm:1",
            "kind": "list",
            "member_count": 1,
            "health": "archived",
            "created_at": "2026-08-14T00:00:00.000Z",
            "parent_space_id": null,
        });
        let row: AdminSpaceView = serde_json::from_value(base.clone()).expect("row parses");
        assert_eq!(row.health, SpaceHealth::Archived);

        let mut unknown_health = base.clone();
        unknown_health["health"] = serde_json::json!("garbage");
        assert!(serde_json::from_value::<AdminSpaceView>(unknown_health).is_err());

        let mut extra = base;
        extra["surprise"] = serde_json::json!(true);
        assert!(serde_json::from_value::<AdminSpaceView>(extra).is_err());
    }

    #[test]
    fn media_row_carries_its_content_digest_identity() {
        let row: AdminMediaView = serde_json::from_value(serde_json::json!({
            "kind": "media",
            "sha256": "9f2c",
            "media_type": "image/png",
            "filename": null,
            "realm_id": null,
            "encrypted": true,
            "uploaded_by": "ak:did_core:web:alice.example",
            "size_bytes": 42,
            "created_at": "2026-08-14T00:00:00.000Z",
        }))
        .expect("media row parses");
        assert_eq!(row.sha256, "9f2c");
        assert_eq!(row.size_bytes, 42);
    }
}
