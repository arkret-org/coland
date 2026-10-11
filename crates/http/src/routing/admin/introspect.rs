//! Per-scope admin gating via SDK
//! [`arkret_models_identity::admin_grant::SessionGrantIntrospection`].
//!
//! The SDK provides a typed view of an OAuth-style introspection
//! response carrying `(principal_id, admin_scopes, expires_at,
//! device_id)`. This module wires that into coland:
//!
//! 1. [`introspect_admin_scopes`] talks to the configured `session_grant_introspection_url` over
//!    HTTP, returning the typed [`SessionGrantIntrospection`]. Results are cached per-token-hash
//!    with a short TTL so a single admin request doesn't fan out into multiple introspection calls.
//!
//! 2. [`require_admin_scope`] is the production-mode gate: it introspects the caller's bearer token
//!    and rejects the request unless the granted `admin_scopes` include the requested scope.
//!
//! In an explicit development harness (no introspection URL configured) the helpers
//! return a synthetic introspection asserting every well-known admin
//! scope for any stable ID in `admin_principal_ids` — keeps local smoke
//! tests working without an IdP dependency.

use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use arkret_identifiers::DidCoreId;
use arkret_models_collaboration::session_grants::{
    SessionGrantValidationByJwt, SessionGrantValidationInput, SessionGrantValidationOutcome,
};
use arkret_models_identity::admin_grant::{
    SessionGrantAdminIntrospectionStatus, SessionGrantIntrospection,
};
use coland_http::error::AppError;
use coland_services::identity::SessionIdentityState as SessionRecord;
use parking_lot::Mutex;
use salvo::prelude::Request;

use crate::state::AppState;

/// Maximum staleness of the administrative / status-query view.
///
/// `api-conventions.md` §3.3 keeps this deliberately stricter than the ≤120s
/// self-path bound, and the two surfaces MUST NOT be merged onto the looser
/// one. This cache, its key, its credential and its scope rules are separate
/// from the self path's for exactly that reason.
const INTROSPECTION_CACHE_TTL: Duration = Duration::from_secs(30);
const INTROSPECTION_CACHE_MAX_ENTRIES: usize = 1024;

/// Cache key of one admin introspection result.
///
/// `session.token_hash` is already `sha256(exact token ‖ this service id)`, so
/// it isolates the exact credential and the expected `audience_id`. §3.3 also
/// requires the authority configuration context, so a retargeted Account
/// Authority cannot answer out of the previous one's entries.
fn admin_cache_key(state: &AppState, token_hash: &str) -> String {
    format!(
        "{token_hash}\n{}",
        crate::routing::identity::auth_grant_dpop::introspection_authority_context(state)
    )
}

struct CacheEntry {
    grant: SessionGrantIntrospection,
    inserted_at: Instant,
}

fn cache() -> &'static Mutex<HashMap<String, CacheEntry>> {
    static CACHE: OnceLock<Mutex<HashMap<String, CacheEntry>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn read_cached(token_hash: &str) -> Option<SessionGrantIntrospection> {
    read_cached_at(token_hash, Instant::now())
}

fn read_cached_at(token_hash: &str, now: Instant) -> Option<SessionGrantIntrospection> {
    let mut cache = cache().lock();
    prune_cache_locked(&mut cache, now);
    let entry = cache.get(token_hash)?;
    if now.duration_since(entry.inserted_at) >= INTROSPECTION_CACHE_TTL {
        return None;
    }
    Some(entry.grant.clone())
}

fn cache_grant(token_hash: String, grant: SessionGrantIntrospection) {
    {
        let mut cache = cache().lock();
        prune_cache_locked(&mut cache, Instant::now());
        while cache.len() >= INTROSPECTION_CACHE_MAX_ENTRIES {
            let Some(oldest_key) = cache
                .iter()
                .min_by_key(|(_, entry)| entry.inserted_at)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            cache.remove(&oldest_key);
        }
        cache.insert(
            token_hash,
            CacheEntry {
                grant,
                inserted_at: Instant::now(),
            },
        );
    }
}

fn prune_cache_locked(cache: &mut HashMap<String, CacheEntry>, now: Instant) {
    cache.retain(|_, entry| now.duration_since(entry.inserted_at) < INTROSPECTION_CACHE_TTL);
}

fn session_grant_status_wire(status: SessionGrantAdminIntrospectionStatus) -> String {
    serde_json::to_value(status)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".to_owned())
}

fn admin_grant_from_introspection_outcome(
    outcome: SessionGrantValidationOutcome,
) -> Result<SessionGrantIntrospection, AppError> {
    if !outcome.active || outcome.status != SessionGrantAdminIntrospectionStatus::Active {
        return Err(crate::app_error!(
            CapabilityDenied,
            format!(
                "admin scope introspection returned inactive grant: {}",
                session_grant_status_wire(outcome.status)
            ),
        ));
    }

    let grant = outcome.grant.ok_or_else(|| {
        crate::app_error!(
            CapabilityDenied,
            "admin scope introspection omitted grant metadata".to_owned(),
        )
    })?;
    let principal_id = grant.account_id.principal_id;

    Ok(SessionGrantIntrospection {
        active: true,
        status: SessionGrantAdminIntrospectionStatus::Active,
        principal_id,
        admin_scopes: grant.scopes,
        expires_at: Some(arkret_canonical::normalize_timestamp_canonical(
            grant.expires_at,
        )),
        device_id: grant
            .device_id
            .map(|device_id| device_id.as_str().to_owned()),
        audit_context: serde_json::json!({
            "source": "deployment_private_session_grant_validation",
            "grant_id": grant.id.as_str(),
            "audience": grant.audience_id,
        }),
    })
}

/// Pull the presented session credential from the request's `Authorization`
/// header: a `DPoP`-scheme SessionGrant or a `Bearer` token. The admin scope
/// introspection names the exact credential the request authenticated with;
/// its DPoP proof was already verified (and consumed) by `RequireAdmin`.
fn session_credential_from_request(req: &Request) -> Option<String> {
    coland_http::util::dpop_token(req)
        .or_else(|| coland_http::util::bearer_token(req))
        .map(|token| token.trim().to_owned())
}

/// Synthetic introspection in an explicitly compiled harness when no upstream IdP
/// is configured. Grants every well-known admin scope to any DID listed
/// in `admin_principal_ids` (or any principal in development_mode).
#[cfg(any(test, feature = "conformance-harness"))]
fn synthetic_dev_admin_scopes() -> Vec<String> {
    use arkret_models_identity::admin_grant::admin_scopes::*;
    vec![
        AUTHORITY_HANDOFF.to_owned(),
        COMMIT_LOG_COMPACT.to_owned(),
        STREAM_REPAIR.to_owned(),
        ADMIN_READ.to_owned(),
    ]
}

#[cfg(any(test, feature = "conformance-harness"))]
fn synthetic_dev_grant(state: &AppState, session: &SessionRecord) -> SessionGrantIntrospection {
    let principal_id =
        arkret_identifiers::DidCoreId::new(session.actor.clone()).unwrap_or_else(|_| {
            // Dev-login actors may be handles rather than DIDs. Reuse the
            // configured, verified service did; never reconstruct one from
            // the service core_id.
            arkret_identifiers::DidCoreId::new(state.service_id().clone())
                .expect("configured service id is a validated core id")
        });
    SessionGrantIntrospection {
        active: true,
        status: SessionGrantAdminIntrospectionStatus::Active,
        principal_id,
        admin_scopes: synthetic_dev_admin_scopes(),
        expires_at: Some(arkret_canonical::normalize_timestamp_canonical(
            session.expires_at,
        )),
        device_id: Some(session.require_human_device_id().clone()),
        audit_context: serde_json::json!({ "synthetic": "development_mode" }),
    }
}

/// Resolve the caller's [`SessionGrantIntrospection`]. An explicit development harness
/// uses a local synthetic grant even when the joint harness also wires a
/// coauth introspection URL; dev-login bearers are local coland sessions,
/// not upstream session-grant tokens. Production mode POSTs the caller's
/// bearer token to `session_grant_introspection_url`.
pub(crate) async fn introspect_admin_scopes(
    state: &AppState,
    req: &Request,
    session: &SessionRecord,
) -> Result<SessionGrantIntrospection, AppError> {
    #[cfg(any(test, feature = "conformance-harness"))]
    if state.config().development_harness_enabled() {
        return Ok(synthetic_dev_grant(state, session));
    }

    let Some(url) = state.config().session_grant_introspection_url.as_deref() else {
        return Err(crate::app_error!(CapabilityDenied,
            "admin scope check requires COLAND_SESSION_GRANT_INTROSPECTION_URL outside the explicit development harness"
                .to_owned(),
        ));
    };

    // Cache hit — short-circuit the network call.
    let cache_key = admin_cache_key(state, &session.token_hash);
    if let Some(grant) = read_cached(&cache_key) {
        return Ok(grant);
    }

    let token = session_credential_from_request(req).ok_or_else(|| {
        crate::app_error!(
            Unauthenticated,
            "missing or malformed Authorization header for admin scope check".to_owned(),
        )
    })?;
    let audience = DidCoreId::new(state.service_id().clone()).map_err(|error| {
        AppError::internal(format!(
            "runtime principal service_id is not a core_id: {error}"
        ))
    })?;
    let request = SessionGrantValidationInput::ByJwt(SessionGrantValidationByJwt {
        grant_jwt: token,
        audience_id: Some(audience),
        proof: None,
    });
    let channel = state
        .config()
        .internal_authority_channel
        .as_ref()
        .ok_or_else(|| {
            crate::app_error!(
                InternalError,
                "session grant introspection requires a complete registered internal channel"
                    .to_owned()
            )
        })?;

    // SOL-03-002: pin validated IPs into the client to close the DNS-rebinding
    // TOCTOU window between the egress check and the connection.
    let (url, client) = crate::security::validate_http_url_for_egress_with_pinned_client(
        url,
        "admin session grant introspection",
        state.config().development_mode,
        Duration::from_secs(10),
    )
    .map_err(AppError::capability_denied)?;
    let response = client
        .post(url)
        .bearer_auth(channel.credential())
        .json(&request)
        .send()
        .await
        .map_err(|error| {
            crate::app_error!(
                TemporarilyUnavailable,
                format!("admin scope introspection request failed: {error}"),
            )
        })?;
    if !response.status().is_success() {
        return Err(crate::app_error!(
            CapabilityDenied,
            format!(
                "admin scope introspection rejected by IdP: HTTP {}",
                response.status()
            ),
        ));
    }
    let outcome = response
        .json::<SessionGrantValidationOutcome>()
        .await
        .map_err(|error| {
            crate::app_error!(
                TemporarilyUnavailable,
                format!("invalid admin scope introspection response: {error}"),
            )
        })?;
    let grant = admin_grant_from_introspection_outcome(outcome)?;

    let now_unix = chrono::Utc::now().timestamp();
    if !grant.is_currently_active(now_unix) {
        return Err(crate::app_error!(
            CapabilityDenied,
            "admin scope introspection returned an inactive grant".to_owned(),
        ));
    }

    cache_grant(cache_key, grant.clone());
    Ok(grant)
}

/// Gate the calling admin operation on a specific scope. Production
/// strand: introspect the bearer, ensure the grant carries `scope`. Dev
/// strand: synthetic grant accepts every well-known scope.
pub(crate) async fn require_admin_scope(
    state: &AppState,
    req: &Request,
    session: &SessionRecord,
    scope: &str,
) -> Result<SessionGrantIntrospection, AppError> {
    let grant = introspect_admin_scopes(state, req, session).await?;
    if !grant.has_admin_scope(scope) {
        return Err(crate::app_error!(
            CapabilityDenied,
            format!(
                "admin scope `{scope}` not granted to {}",
                grant.principal_id
            ),
        ));
    }
    Ok(grant)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_admin_grant() -> SessionGrantIntrospection {
        SessionGrantIntrospection {
            active: true,
            status: SessionGrantAdminIntrospectionStatus::Active,
            principal_id: DidCoreId::new("ak:did_core:web:admin.example").unwrap(),
            admin_scopes: vec!["arkret.admin.read".to_owned()],
            expires_at: Some(
                chrono::DateTime::parse_from_rfc3339("2099-01-01T00:00:00.000Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            ),
            device_id: Some("ak:device:0196419b-0000-7000-8000-000000000001".to_owned()),
            audit_context: serde_json::json!({"source": "controlled-admin-ttl-test"}),
        }
    }

    #[test]
    fn admin_introspection_cache_expires_at_exact_30_second_boundary() {
        let key = "controlled-admin-ttl";
        let inserted_at = Instant::now();
        cache().lock().insert(
            key.to_owned(),
            CacheEntry {
                grant: test_admin_grant(),
                inserted_at,
            },
        );
        assert!(
            read_cached_at(
                key,
                inserted_at + INTROSPECTION_CACHE_TTL - Duration::from_nanos(1)
            )
            .is_some()
        );
        assert!(read_cached_at(key, inserted_at + INTROSPECTION_CACHE_TTL).is_none());
        cache().lock().remove(key);
    }

    #[test]
    fn admin_adapter_uses_current_status_and_scope_vocabulary() {
        use arkret_models_identity::admin_grant::admin_scopes;

        assert_eq!(
            session_grant_status_wire(SessionGrantAdminIntrospectionStatus::Active),
            "active"
        );
        assert_eq!(
            synthetic_dev_admin_scopes(),
            vec![
                admin_scopes::AUTHORITY_HANDOFF.to_owned(),
                admin_scopes::COMMIT_LOG_COMPACT.to_owned(),
                admin_scopes::STREAM_REPAIR.to_owned(),
                admin_scopes::ADMIN_READ.to_owned(),
            ]
        );
    }
}
