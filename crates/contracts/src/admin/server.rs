//! Operator dashboard projections for `GET /_coland/admin/server/*`.
//!
//! Shared by the coland producer
//! (`coland/crates/http/src/routing/admin/server_ops.rs`) and the codmin
//! operator console.

use arkret_identifiers::DidCoreId;
use serde::{Deserialize, Serialize};

/// `GET /_coland/admin/server/info` — node version / build / key config the
/// operator dashboard surfaces at a glance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AdminServerInfo {
    pub server_version: String,
    pub protocol_version: Option<String>,
    pub server_name: Option<String>,
    /// Process uptime in seconds. `None` — coland does not track a start
    /// instant, so the field is reported as unknown rather than as `0`.
    pub uptime: Option<u64>,
    pub service_id: DidCoreId,
    pub trust_domain: String,
    pub development_mode: bool,
    /// Whether the deployment accepts public self-registration according to
    /// the canonical account registration policy.
    pub allow_public_registration: bool,
}

/// `GET /_coland/admin/server/stats` — best-effort snapshot counters off the
/// live persistence / projection stores. Unavailable counters fall back to 0.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AdminServerStats {
    pub actor_count: u64,
    pub active_actor_count: u64,
    pub realm_count: u64,
    pub device_count: u64,
    pub report_count: u64,
    pub federation_peer_count: u64,
    pub applet_count: u64,
    pub blob_count: u64,
    pub blob_total_size: u64,
    pub generated_at: String,
}

/// Row counts embedded in [`AdminServerStatus`]. `None` means the store
/// could not answer — never a defaulted `0`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AdminServerStatusCounts {
    pub accounts: Option<usize>,
    pub devices: Option<usize>,
    pub realms: usize,
}

/// `GET /_coland/admin/server/status` — reachability probe plus the
/// deployment posture the console banners depend on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AdminServerStatus {
    /// [`AdminServerStatus::OK`] when the node answered the probe. The
    /// endpoint runs no component health checks, so this is reachability
    /// only — the console must not present it as a component roll-up.
    pub status: String,
    pub service_id: DidCoreId,
    pub storage: String,
    pub development_mode: bool,
    pub checked_by: DidCoreId,
    pub generated_at: String,
    pub counts: AdminServerStatusCounts,
}

impl AdminServerStatus {
    /// The only status the probe reports; a node that cannot answer fails
    /// the request instead.
    pub const OK: &'static str = "ok";

    pub fn is_ok(&self) -> bool {
        self.status == Self::OK
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_counts_keep_unavailable_stores_distinct_from_zero() {
        let status: AdminServerStatus = serde_json::from_value(serde_json::json!({
            "status": "ok",
            "service_id": "ak:did_core:web:coland.local",
            "storage": "postgres",
            "development_mode": false,
            "checked_by": "ak:did_core:web:alice.example",
            "generated_at": "2026-08-14T00:00:00.000Z",
            "counts": { "accounts": null, "devices": 3, "realms": 7 },
        }))
        .expect("status parses");

        assert!(status.is_ok());
        assert_eq!(status.counts.accounts, None);
        assert_eq!(status.counts.devices, Some(3));
        assert_eq!(status.counts.realms, 7);
    }

    #[test]
    fn server_info_rejects_unknown_fields() {
        let wire = serde_json::json!({
            "server_version": "0.3.0",
            "protocol_version": "1.0",
            "server_name": "coland.local",
            "uptime": null,
            "service_id": "ak:did_core:web:coland.local",
            "trust_domain": "ak:trust_domain:coland.local",
            "development_mode": false,
            "allow_public_registration": true,
            "surprise": 1,
        });
        assert!(serde_json::from_value::<AdminServerInfo>(wire).is_err());
    }
}
