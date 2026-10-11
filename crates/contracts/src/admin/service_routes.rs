//! Deployment-local, read-only service-route operations projection.
//!
//! These DTOs expose only state already verified and persisted by Coland.
//! They are not Arkret discovery artifacts and carry no authorization.

use arkret_wire::DidCoreId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AdminServiceRouteSummary {
    pub service_id: DidCoreId,
    pub service_kind: String,
    pub known: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method_history_head: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_expires_at: Option<DateTime<Utc>>,
    pub quarantined: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AdminServiceRouteList {
    #[serde(default)]
    pub routes: Vec<AdminServiceRouteSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AdminServiceMethodState {
    pub did: String,
    pub method_history_head: String,
    pub version_id: String,
    pub verified_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AdminServiceRouteCurrent {
    pub did: String,
    pub method_history_head: String,
    pub version_id: String,
    pub base_url: String,
    pub verified_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AdminServiceRouteCache {
    pub verified_at: DateTime<Utc>,
    pub cache_expires_at: DateTime<Utc>,
    pub routable_at_observed_at: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AdminServiceRouteQuarantine {
    pub version_id: String,
    pub accepted_digest: String,
    pub conflicting_digest: String,
    pub quarantined_at: DateTime<Utc>,
    /// Admin-private local diagnostic context. It is never protocol evidence.
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub diagnostic: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AdminServiceRouteDetail {
    pub service_id: DidCoreId,
    pub service_kind: String,
    /// False means no locally persisted verified state exists for this key.
    pub known: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method_state: Option<AdminServiceMethodState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_route: Option<AdminServiceRouteCurrent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache: Option<AdminServiceRouteCache>,
    #[serde(default)]
    pub quarantine: Vec<AdminServiceRouteQuarantine>,
    pub quarantine_truncated: bool,
    pub observed_at: DateTime<Utc>,
    pub authority: String,
}
