//! `GET`/`PUT /_coland/admin/settings` — read and hot-swap the mutable
//! operational overlay ([`crate::runtime_settings::RuntimeSettings`]).
//!
//! - `GET` returns the full **effective** settings (env defaults with any persisted overrides
//!   applied).
//! - `PUT` takes a **partial** `{ key: value }` object and changes only the keys present (PATCH
//!   semantics). Each changed key is upserted into its own `server_settings` row (keys never sent
//!   keep following their env default), then the whole snapshot is atomically hot-swapped via
//!   [`arc_swap::ArcSwap`] so the next request — rate limiter, admin allowlist, federation fanout —
//!   observes the change with no restart.
//!
//! Gated by the shared `RequireAdmin` hoop like the rest of `/_coland/admin/*`
//! (the same posture under which `control.rs` serves its admin writes).
//!
//! Boundary reminder: this endpoint deliberately does NOT touch Tier-1 boot
//! config (bind address, `DATABASE_URL`, service DID, TLS paths, signing
//! seeds). Those are secrets or pre-DB bootstrap and stay in env.

use coland_http::error::AppError;
use salvo::prelude::*;
use serde_json::{Map, Value};

use super::AdminAuth;
use crate::runtime_settings::RuntimeSettings;
use crate::state::AppState;
use crate::{JsonResult, json_ok};

pub(super) fn router() -> Router {
    Router::with_path("admin/settings")
        .get(get_settings)
        .put(put_settings)
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.coland.admin.settings.get",
    tags("coland_admin")
)]
async fn get_settings(depot: &mut Depot) -> JsonResult<RuntimeSettings> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let _session = AdminAuth::from_depot(depot).session()?;
    json_ok((*state.settings()).clone())
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.coland.admin.settings.update",
    tags("coland_admin")
)]
async fn put_settings(depot: &mut Depot, req: &mut Request) -> JsonResult<RuntimeSettings> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = AdminAuth::from_depot(depot).session()?;

    let patch: Map<String, Value> = req.parse_json().await.map_err(|error| {
        crate::app_error!(
            ParamInvalid,
            format!("settings body must be a JSON object of key -> value: {error}"),
        )
    })?;
    if patch.is_empty() {
        return Err(crate::app_error!(
            ParamInvalid,
            "settings patch must set at least one key".to_owned(),
        ));
    }

    // Validate the whole patch against a working copy before touching the DB,
    // so an unknown key or bad shape rejects the entire request atomically.
    let mut next = (*state.settings()).clone();
    for (key, value) in &patch {
        next.apply_key(key, value.clone())
            .map_err(|error| crate::app_error!(ParamInvalid, error.to_string()))?;
    }

    // Persist each changed key as its own row, using the post-normalization
    // canonical value so the stored row always matches what is enforced.
    // Memory-mode deployments use a no-op adapter and keep the swap only.
    for key in patch.keys() {
        let canonical = next
            .key_value(key)
            .map_err(|error| AppError::internal(format!("encode setting `{key}`: {error}")))?;
        state
            .governance()
            .store_runtime_setting(key, &canonical, &session.actor)
            .await
            .map_err(|error| AppError::internal(format!("persist setting `{key}`: {error}")))?;
    }
    state.replace_settings(next.clone());

    let changed_keys: Vec<&String> = patch.keys().collect();
    super::audit::append_audit_log(
        state,
        Some(&session.actor),
        "org.arkret.coland.admin.settings.update",
        serde_json::json!({ "changed_keys": changed_keys }),
        "ok",
    )
    .await;
    json_ok(next)
}
