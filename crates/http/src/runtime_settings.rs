//! Deployment-wide **dynamic** operational settings.
//!
//! [`AppConfig`](crate::config::AppConfig) is the immutable *boot* config —
//! bind address, `DATABASE_URL`, service DID, TLS paths, and signing seeds
//! are read once from env and never change while the process runs. Those are
//! either secrets or needed before the database is up, so they stay in env.
//!
//! [`RuntimeSettings`] is the mutable overlay: the subset of operational
//! knobs an operator wants to change **without a restart** — the admin
//! allowlist, rate-limit ceilings, federation peer set, trusted push-bridge
//! services, and a couple of product feature toggles. It is seeded from
//! `AppConfig` at boot (so an all-env deployment behaves exactly as before),
//! then overlaid by the singleton `server_settings` DB row if present, and
//! swapped atomically by the admin settings endpoint.
//!
//! It is stored behind an [`arc_swap::ArcSwap`] on `AppState` so every
//! request observes a consistent snapshot and a `PUT /_coland/admin/settings`
//! takes effect on the very next request with no lock contention.

use arkret_identifiers::DidCoreId;
use coland_http::ratelimit::RateLimiterConfig;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::{AppConfig, FederationFanoutTopology};

/// Rate-limit ceilings, per endpoint class, as a serializable snapshot.
/// Mirrors the fields of [`RateLimiterConfig`] but is `Serialize`/
/// `Deserialize` for DB persistence and the admin wire surface.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct RateLimitSettings {
    /// Sliding-window length in seconds.
    pub window_seconds: u32,
    /// Fallback ceiling for the `other` (non-`/_arkret/*`) class.
    pub default_per_minute: u32,
    /// Strict ceiling for the credential/bearer-issuing `auth` class.
    pub auth_per_minute: u32,
    /// Moderate ceiling for the rest of `/_arkret/*`.
    pub api_per_minute: u32,
    /// Generous ceiling for the public `/_arkret/describe` probe.
    pub probe_per_minute: u32,
}

impl RateLimitSettings {
    /// Snapshot the effective ceilings out of a [`RateLimiterConfig`]
    /// (already resolved for dev/prod posture + `COLAND_RATE_LIMIT_*`).
    pub fn from_limiter_config(config: &RateLimiterConfig) -> Self {
        Self {
            window_seconds: u32::try_from(config.window.as_secs())
                .unwrap_or(u32::MAX)
                .max(1),
            default_per_minute: config.max_request_count,
            auth_per_minute: config.auth_max_requests,
            api_per_minute: config.api_max_requests,
            probe_per_minute: config.probe_max_requests,
        }
    }

    /// Rebuild a [`RateLimiterConfig`] the limiter middleware can enforce
    /// against, from the current snapshot.
    pub fn to_limiter_config(&self) -> RateLimiterConfig {
        RateLimiterConfig {
            max_request_count: self.default_per_minute,
            window: std::time::Duration::from_secs(u64::from(self.window_seconds.max(1))),
            auth_max_requests: self.auth_per_minute,
            api_max_requests: self.api_per_minute,
            probe_max_requests: self.probe_per_minute,
        }
    }
}

/// The mutable operational overlay. See the module docs for the boundary
/// against [`AppConfig`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct RuntimeSettings {
    /// Stable principal IDs allowed to call the production-gated admin surfaces
    /// when `development_mode` is false.
    pub admin_principal_ids: Vec<DidCoreId>,
    /// Federation broadcast / hub-upstream target set. Boot config may contain
    /// endpoints only; runtime discovery replaces them with
    /// `base_url|service_id` entries before use.
    pub federation_peers: Vec<String>,
    /// Mesh vs hub outbound fanout topology.
    pub federation_fanout_topology: FederationFanoutTopology,
    /// Rate-limit ceilings.
    pub rate_limit: RateLimitSettings,
}

impl RuntimeSettings {
    /// Seed the overlay from boot config. An all-env deployment (no DB row)
    /// runs with exactly these values, so behavior is unchanged from before
    /// dynamic settings existed.
    pub fn from_config(config: &AppConfig) -> Self {
        Self {
            admin_principal_ids: config.admin_principal_ids.clone(),
            federation_peers: config.federation_peers.clone(),
            federation_fanout_topology: config.federation_fanout_topology,
            rate_limit: RateLimitSettings::from_limiter_config(&config.rate_limiter),
        }
    }

    /// Whether `actor` is in the runtime admin allowlist.
    pub fn is_admin_principal(&self, actor: &str) -> bool {
        self.admin_principal_ids
            .iter()
            .any(|principal_id| principal_id.as_str() == actor)
    }

    /// Floor the rate-limit knobs so a stored override can never disable the
    /// limiter: a 0 ceiling would reject every request and a 0 window would
    /// collapse the sliding window.
    pub fn floor_rate_limit(&mut self) {
        self.rate_limit.window_seconds = self.rate_limit.window_seconds.max(1);
        self.rate_limit.default_per_minute = self.rate_limit.default_per_minute.max(1);
        self.rate_limit.auth_per_minute = self.rate_limit.auth_per_minute.max(1);
        self.rate_limit.api_per_minute = self.rate_limit.api_per_minute.max(1);
        self.rate_limit.probe_per_minute = self.rate_limit.probe_per_minute.max(1);
    }

    /// Apply one persisted override key onto this snapshot, replacing just that
    /// field. Used both when loading the overlay at boot and when an admin PUT
    /// changes a subset of keys. Unknown keys and shape-mismatched values are
    /// a hard error so a bad admin request is rejected; the boot loader logs
    /// and skips instead of bricking startup (see [`Self::apply_override_rows`]).
    pub fn apply_key(&mut self, key: &str, value: Value) -> anyhow::Result<()> {
        match key {
            keys::ADMIN_PRINCIPAL_IDS => self.admin_principal_ids = decode(key, value)?,
            keys::FEDERATION_PEERS => self.federation_peers = decode(key, value)?,
            keys::FEDERATION_FANOUT_TOPOLOGY => {
                self.federation_fanout_topology = decode(key, value)?
            }
            keys::RATE_LIMIT => {
                self.rate_limit = decode(key, value)?;
                self.floor_rate_limit();
            }
            other => anyhow::bail!("unknown setting key: {other}"),
        }
        Ok(())
    }

    /// Canonical JSON for one key, read out of the snapshot. Inverse of
    /// [`Self::apply_key`]; used to persist the post-normalization value so the
    /// stored row always matches the enforced value.
    pub fn key_value(&self, key: &str) -> anyhow::Result<Value> {
        let value = match key {
            keys::ADMIN_PRINCIPAL_IDS => serde_json::to_value(&self.admin_principal_ids),
            keys::FEDERATION_PEERS => serde_json::to_value(&self.federation_peers),
            keys::FEDERATION_FANOUT_TOPOLOGY => {
                serde_json::to_value(self.federation_fanout_topology)
            }
            keys::RATE_LIMIT => serde_json::to_value(self.rate_limit),
            other => anyhow::bail!("unknown setting key: {other}"),
        };
        value.map_err(|error| anyhow::anyhow!("encode setting `{key}`: {error}"))
    }

    /// Apply persisted override rows onto the boot seed, skipping (with a warn)
    /// any unknown key or shape-mismatched value so a single corrupt row can
    /// never brick startup — that key just falls back to its env default.
    pub fn apply_override_rows(&mut self, rows: Vec<(String, Value)>) {
        for (key, value) in rows {
            if let Err(error) = self.apply_key(&key, value) {
                tracing::warn!(%error, key, "skipping invalid server_settings override");
            }
        }
    }
}

/// Stable setting keys. One row per key in `server_settings`; the string is the
/// primary key and the admin wire contract, so these are append-only.
pub mod keys {
    pub const ADMIN_PRINCIPAL_IDS: &str = "admin_principal_ids";
    pub const FEDERATION_PEERS: &str = "federation_peers";
    pub const FEDERATION_FANOUT_TOPOLOGY: &str = "federation_fanout_topology";
    pub const RATE_LIMIT: &str = "rate_limit";

    /// Every recognized key, for validation / documentation.
    pub const ALL: &[&str] = &[
        ADMIN_PRINCIPAL_IDS,
        FEDERATION_PEERS,
        FEDERATION_FANOUT_TOPOLOGY,
        RATE_LIMIT,
    ];
}

fn decode<T: serde::de::DeserializeOwned>(key: &str, value: Value) -> anyhow::Result<T> {
    serde_json::from_value(value)
        .map_err(|error| anyhow::anyhow!("setting `{key}` has invalid shape: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> RuntimeSettings {
        RuntimeSettings {
            admin_principal_ids: vec![DidCoreId::new("ak:did_core:web:ops.example").unwrap()],
            federation_peers: vec!["https://peer.example|did:web:peer.example".to_owned()],
            federation_fanout_topology: FederationFanoutTopology::Hub,
            rate_limit: RateLimitSettings {
                window_seconds: 60,
                default_per_minute: 600,
                auth_per_minute: 60,
                api_per_minute: 300,
                probe_per_minute: 600,
            },
        }
    }

    #[test]
    fn runtime_settings_json_round_trips() {
        let original = sample();
        let json = serde_json::to_value(&original).expect("encode");
        // `federation_fanout_topology` serializes as a lowercase string, matching the
        // env grammar (`mesh` | `hub`).
        assert_eq!(json["federation_fanout_topology"], "hub");
        let decoded: RuntimeSettings = serde_json::from_value(json).expect("decode");
        assert_eq!(decoded, original);
    }

    #[test]
    fn rate_limit_settings_round_trip_through_limiter_config() {
        let settings = sample().rate_limit;
        let config = settings.to_limiter_config();
        assert_eq!(config.window, std::time::Duration::from_secs(60));
        assert_eq!(config.probe_max_requests, 600);
        let back = RateLimitSettings::from_limiter_config(&config);
        assert_eq!(back, settings);
    }

    #[test]
    fn apply_key_is_a_partial_override() {
        let mut settings = sample();
        settings
            .apply_key(
                keys::ADMIN_PRINCIPAL_IDS,
                serde_json::json!(["ak:did_core:web:a", "ak:did_core:web:b"]),
            )
            .expect("apply admin principal ids");
        // Only the targeted field changed.
        assert_eq!(
            settings.admin_principal_ids,
            vec![
                DidCoreId::new("ak:did_core:web:a").unwrap(),
                DidCoreId::new("ak:did_core:web:b").unwrap(),
            ]
        );
        assert_eq!(
            settings.federation_fanout_topology,
            FederationFanoutTopology::Hub
        );
    }

    #[test]
    fn apply_key_floors_rate_limit() {
        let mut settings = sample();
        settings
            .apply_key(
                keys::RATE_LIMIT,
                serde_json::json!({
                    "window_seconds": 0,
                    "default_per_minute": 0,
                    "auth_per_minute": 0,
                    "api_per_minute": 0,
                    "probe_per_minute": 0
                }),
            )
            .expect("apply rate limit");
        assert_eq!(settings.rate_limit.window_seconds, 1);
        assert_eq!(settings.rate_limit.probe_per_minute, 1);
    }

    #[test]
    fn apply_key_rejects_unknown_and_bad_shape() {
        let mut settings = sample();
        assert!(settings.apply_key("nope", serde_json::json!(1)).is_err());
    }

    #[test]
    fn key_value_round_trips_through_apply_key() {
        let settings = sample();
        for key in keys::ALL {
            let value = settings.key_value(key).expect("encode key");
            let mut fresh = RuntimeSettings {
                admin_principal_ids: vec![],
                federation_peers: vec![],
                federation_fanout_topology: FederationFanoutTopology::Mesh,
                rate_limit: RateLimitSettings {
                    window_seconds: 1,
                    default_per_minute: 1,
                    auth_per_minute: 1,
                    api_per_minute: 1,
                    probe_per_minute: 1,
                },
            };
            fresh.apply_key(key, value).expect("apply key back");
            assert_eq!(
                fresh.key_value(key).unwrap(),
                settings.key_value(key).unwrap()
            );
        }
    }
}
