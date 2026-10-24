//! Auth + session handlers and the session-validation helpers they rely on.
//!
//! Surfaces:
//! - `POST /_coland/gate/auth/dev-login` — dev-mode session credential issue
//! - `POST /_arkret/gate/account/session-grants` — coauth session-grant bridge
//! - `POST /_arkret/gate/account/logout` — spec `ak.gate.account.command.logout.v1`: revoke the
//!   presented session credential + queued to-device while preserving device authorization
//!
//! Internal helpers exported for the rest of `crate::routing`:
//! - `auth_or_render` — the standard "extract session or 401" wrapper used by nearly every
//!   protected handler
//! - `authenticated_session` — the underlying session-lookup pipeline
//! - `session_credential_hash` / `token_for` — credential derivation primitives

use arkret_models_identity::AccountLogoutResponseBody;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
#[cfg(any(test, feature = "conformance-harness"))]
use chrono::Duration;
use coland_http::error::{AppError, ErrorCode};
use coland_services::identity::SessionIdentityState as SessionRecord;
use salvo::http::StatusCode;
#[cfg(any(test, feature = "conformance-harness"))]
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::json;
use sha2::{Digest, Sha256};

use super::{append_audit_log, bearer_token, dpop_token, now, render_error};
#[cfg(any(test, feature = "conformance-harness"))]
use super::{handle_for_did, normalize_localpart, validate_device_id};
#[cfg(any(test, feature = "conformance-harness"))]
use crate::ids;
use crate::state::AppState;
#[cfg(any(test, feature = "conformance-harness"))]
use crate::wire::{DevLoginRequestBody, DevLoginResponseBody};
use crate::{JsonResult, json_ok};

mod login;
mod logout;
pub(crate) use logout::revoke_sessions_for_actor_device as revoke_sessions_for_hard_logout_device;
mod revocation;
mod sessions;

// Re-export submodule items so the original `identity::auth::*` paths keep
// resolving for external callers, and so private helpers shared between the
// submodules are visible to each submodule via its `use super::*;` glob.
//
// External-visibility surface (referenced from other modules at the original
// `identity::auth::<name>` path).
// Router-mounted handlers (used by the `*_router` fns below).
// Cross-submodule private helpers, re-exported at `pub(super)` so every
// submodule's `use super::*;` glob can see them.
pub(super) use login::account_existing_session_error;
#[cfg(any(test, feature = "conformance-harness"))]
use login::dev_login;
pub(crate) use revocation::purge_device_delivery_state;
#[cfg(any(test, feature = "conformance-harness"))]
pub use revocation::token_for;
pub use revocation::{
    revoke_devices_for_actor, revoke_sessions_for_actor, session_credential_hash,
};
pub(super) use sessions::request_requires_fresh_introspection;
pub use sessions::{auth_or_render, authenticated_session};
pub(crate) use sessions::{
    revalidate_current_read_session, revalidate_stream_session, websocket_session,
};

pub(super) fn router() -> Router {
    local_router()
}

pub(super) fn protocol_account_router() -> Router {
    Router::with_path("account")
        // Spec `ak.gate.account.command.logout.v1` — Station device
        // logout (account-lifecycle §4.1): revoke this session credential and
        // drop the device's queued to-device while preserving its durable
        // authorization. Canonical `/_arkret/gate/account/logout`; deployment
        // gateways route this longer prefix to coland even though `/_arkret/gate/`
        // otherwise goes to the Account Authority process.
        .push(Router::with_path("logout").post(logout::logout))
}

pub(super) fn local_router() -> Router {
    // Device logout is the spec op `ak.gate.account.command.logout.v1`, served at
    // the canonical `/_arkret/gate/account/logout` (see `protocol_account_router`).
    // Deployment gateways route that longer prefix to coland (the Station) even though
    // `/_arkret/gate/` otherwise goes to the Account Authority process, so no `/_coland/gate/
    // auth/logout` product alias is needed. ② (api-conventions.md §3.3): no local credential
    // issuance endpoint is mounted under `session-grants`. dev-login remains the only local
    // development session issuer; production clients present the grant + DPoP
    // directly to `/_arkret/self/*`.
    let router = Router::with_path("auth")
        .push(Router::with_path("bridge/describe").get(super::describe::auth_bridge_describe));
    #[cfg(any(test, feature = "conformance-harness"))]
    let router = router.push(Router::with_path("dev-login").post(dev_login));
    router
}

#[cfg(test)]
mod ownership_tests {
    use std::fs;
    use std::path::Path;

    fn assert_forbidden_absent(path: &Path, forbidden: &[String]) {
        for entry in fs::read_dir(path).expect("read HTTP source directory") {
            let entry = entry.expect("read HTTP source entry");
            let path = entry.path();
            if path.is_dir() {
                assert_forbidden_absent(&path, forbidden);
            } else if path.extension().and_then(|value| value.to_str()) == Some("rs") {
                let source = fs::read_to_string(&path).expect("read HTTP Rust source");
                for needle in forbidden {
                    assert!(
                        !source.contains(needle),
                        "Account Authority device-pairing ownership residual `{needle}` in {}",
                        path.display()
                    );
                }
            }
        }
    }

    #[test]
    fn station_has_no_account_authority_pairing_finalize_residual() {
        let forbidden = [
            ["account_handoff", "_introspection"].concat(),
            ["account_handoff", "_bound_account"].concat(),
            ["finalize_device", "_pairing"].concat(),
            ["DevicePairing", "Finalize"].concat(),
            ["with_path(\"final", "izations\")"].concat(),
            ["claim_device", "_pairing_code"].concat(),
            ["get_by_pairing", "_code"].concat(),
            ["with_path(\"code-", "claims\")"].concat(),
        ];
        assert_forbidden_absent(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            &forbidden,
        );
    }
}
