//! Account aggregate + snapshot handlers + the cursor-helper machinery they share
//! with events and device-message modules.
//!
//! Surfaces for the current sync/event wire layout:
//! - `GET  /_arkret/self/account/describe`
//! - `GET  /_arkret/self/account/subscribe`       — `ak.self.account.stream.subscribe.v1`
//!   (account-aggregate NDJSON: timeline, account data, to_device).
//! - `POST /_arkret/self/signal`                  — `ak.self.signal.command.send.v1` (Signal
//!   Extension send rail; encrypted-only)
//! - `GET  /_arkret/self/signal/subscribe`        — `ak.self.signal.stream.subscribe.v1` (Signal
//!   Extension receive rail; verbatim envelope NDJSON)
//! - `GET  /_arkret/self/committed-events/subscribe` — committed Event live tail. Multi-Realm /
//!   multi-actor stream; frame `kind` field replaces `type`.
//! - `GET  /_arkret/self/realm-state-snapshot/head`
//! - `GET  /_arkret/self/realm-state-snapshot/{snapshot_id}` — exact issued by-ref read
//!
//! `SyncCursor`, `SyncCursorError`, `parse_and_validate_sync_cursor`,
//! `decode_sync_cursor_value`, `sync_token_for_client_sync`, `sync_filter_digest`,
//! are `pub` because sibling routing modules reuse them. They
//! live here because the cursor lifecycle is sealed to account subscribe.
//!
//! The implementation is split across submodules; this module file owns the
//! shared imports / constants, the protocol router, the scope-selector helpers,
//! and re-exports the per-topic items so `sync::xxx` paths and the `super::*`
//! views in `snapshot.rs` / `sync_tests.rs` keep resolving unchanged.

pub(crate) use std::collections::{BTreeMap, BTreeSet};
pub(crate) use std::time::Duration;

pub(crate) use arkret_identifiers::RealmId;
#[cfg(test)]
pub(crate) use base64::Engine;
#[cfg(test)]
pub(crate) use base64::engine::general_purpose::URL_SAFE_NO_PAD;
pub(crate) use bytes::Bytes;
pub(crate) use chrono::{DateTime, Utc};
#[cfg(test)]
pub(crate) use coland_domain::reducer::ProjectionState;
#[cfg(test)]
pub(crate) use coland_services::events::ProjectedEvent;
pub(crate) use coland_services::identity::SessionIdentityState;
pub(crate) use coland_services::sync::CursorState;
pub(crate) use futures_util::stream::StreamExt;
pub(crate) use salvo::http::{StatusCode, header};
pub(crate) use salvo::prelude::*;
pub(crate) use serde_json::{Value, json};
pub(crate) use tokio::sync::broadcast::error::RecvError;

#[cfg(test)]
use super::realm_event_visible_to_session;
use super::{
    authenticated_session, is_realm_deleted, now, query_param, realm_id_accessible,
    realm_state_snapshot_manifest_for_realm, render_error, sha256_hex,
};
pub(crate) use crate::ids;
pub(crate) use crate::state::AppState;
pub(crate) use crate::wire::SyncRequestBody;

/// Default reconnect guard advertised on subscribe terminal control frames.
/// Shared by `account_subscribe` (subscribe.rs) and `events_subscribe`
/// (events_query.rs).
pub(crate) const SUBSCRIBE_RECONNECT_AFTER_MS: u64 = 10_000;
/// Group revocations cover all issuances until the stream TTL hard cap.
pub(crate) const CURSOR_MAX_TTL_SECONDS: i64 = arkret_hlc::Cursor::STREAM_TTL_MAX_MS / 1000;
/// `account_data_tombstone_retention_ms` is 90 days. This dominates the
/// one-hour cursor TTL, so Station-CAS change records cannot be collected
/// before every valid cursor that could name them has expired.
const ACCOUNT_DATA_CHANGE_RETENTION_DAYS: i64 = 90;
const ACCOUNT_DATA_CHANGE_SWEEP_INTERVAL: Duration = Duration::from_secs(900);

mod snapshot;

pub(crate) use snapshot::*;
mod current_details;
mod cursor;
mod demand_list;
mod global_channels;
pub(crate) mod signal;
// `spawn_sync_cursor_ttl_sweeper` is `pub` (boot worker entry re-exported at
// `crate::routing::spawn_sync_cursor_ttl_sweeper` for `main`); the explicit
// `pub use` overrides the `pub(crate)` glob above for this one name.
pub use cursor::spawn_sync_cursor_ttl_sweeper;
pub fn spawn_account_data_change_retention_sweeper(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(ACCOUNT_DATA_CHANGE_SWEEP_INTERVAL);
        loop {
            ticker.tick().await;
            let cutoff =
                chrono::Utc::now() - chrono::Duration::days(ACCOUNT_DATA_CHANGE_RETENTION_DAYS);
            match state.account_data().prune_changes_before(cutoff).await {
                Ok(pruned) if pruned > 0 => {
                    tracing::info!(pruned, "pruned retained account-data change records");
                }
                Ok(_) => {}
                Err(error) => {
                    tracing::error!(%error, "failed to prune retained account-data change records");
                }
            }
        }
    })
}
pub(crate) use cursor::*;
mod subscribe;
pub(crate) use subscribe::*;
mod committed_subscription;
mod events_query;
pub(crate) mod websocket;
pub(crate) use events_query::*;

pub(super) fn protocol_router() -> Router {
    Router::new()
        .push(Router::with_path("account/describe").get(subscribe::account_describe))
        .push(Router::with_path("account/subscribe").get(subscribe::account_subscribe))
        .push(Router::with_path("account/cursor/revoke").post(cursor::account_cursor_revoke))
        .push(Router::with_path("signal").post(signal::submit_signal))
        .push(Router::with_path("signal/subscribe").get(signal::signal_subscribe))
        .push(
            Router::with_path("realm-state-snapshot/head")
                .get(events_query::realm_state_snapshot_head),
        )
        .push(
            Router::with_path("realm-state-snapshot/{snapshot_id}")
                .get(events_query::realm_state_snapshot_by_ref),
        )
}

pub(crate) fn scope_selector_to_realm_id(
    value: &str,
) -> Result<String, coland_http::error::AppError> {
    if RealmId::new(value.to_owned()).is_ok() {
        return Ok(value.to_owned());
    }
    Err(coland_http::error::AppError::param_invalid(
        "invalid realm_id",
    ))
}

#[cfg(test)]
#[path = "sync_tests.rs"]
mod tests;
