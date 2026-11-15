//! `/_arkret/self/*` inbound credential: `ak.session.grant` + DPoP (RFC 9449).
//!
//! Per api-conventions.md §3.3 the Station (coland) no longer mints a
//! local credential from a session grant. The client
//! presents the `ak.session.grant` directly on every `/_arkret/self/*` request
//! as `Authorization: DPoP <ak.session.grant>` plus a sender-constrained
//! `DPoP` proof. coland validates and serves; the resulting `SessionRecord` is
//! request-scoped and is NEVER persisted as a local bearer.
//!
//! `api-conventions.md` §3.1/§3.3 makes this an **exact-token introspection
//! authority**: the complete token bytes plus this Station's own `audience_id`
//! go to the issuer ledger over the deployment-internal channel, and the
//! returned metadata is the authority. This Station MUST NOT derive authority
//! from the opaque secret locally or interpret it as claims. The issuer-scoped UUID7
//! reference and all non-secret metadata come from that authenticated result.
//!
//! One HTTP request takes **one** authoritative result, at the strictest
//! freshness any of its consumers needs, and passes it to every later gate
//! (§3.3 ruling 5). The per-request memo below is that carrier; the RFC 9421
//! `session_public_key` is read from the same result rather than from a second
//! independent introspection.
//!
//! Validation pipeline (any failure → `unauthenticated`, fail closed):
//!   1. grant active via session-grant introspection at coauth, with a small TTL (≤120s) cache
//!      keyed by the presented grant; sensitive operations bypass the cache and force a fresh
//!      introspection.
//!   2. DPoP signature valid against the grant's `cnf.jkt` (JWK SHA-256 thumbprint, RFC 7638) read
//!      from the introspection result.
//!   3. DPoP `htm` == request method, `htu` == request URL, `ath` == base64url(sha256(grant)).
//!   4. DPoP `jti` + `iat` freshness window for replay defense.
//!   5. grant audience == this service's `service_id`.
//!   6. human grants carry the exact typed holder/device binding; agent grants carry current
//!      runtime-key authorization metadata. Grant not expired.
//!
//! DPoP does NOT bind the request body — body integrity rides on TLS, same as
//! Matrix (api-conventions.md §3.3). Body-bound integrity is layered separately
//! by the RFC 9421 PoP hoop (`session_pop`).

use std::collections::HashMap;
use std::sync::{Arc, LazyLock};
use std::time::{Duration as StdDuration, Instant};

use arkret_identifiers::{DeviceId, DidCoreId, SessionGrantSecret};
use arkret_models_collaboration::session_grants::{
    SessionGrantValidationBinding, SessionGrantValidationBySecret,
};
use arkret_models_identity::session_credential::SessionGrantHolderBinding;
use arkret_wire::FreshnessState;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration, Utc};
use coland_services::identity::{
    AgentSessionState as AgentSessionRecord, SessionEndpointState,
    SessionIdentityState as SessionRecord,
};
use parking_lot::Mutex;
use salvo::http::StatusCode;
use salvo::prelude::Request;
use sha2::{Digest, Sha256};

use crate::state::AppState;
use crate::wire::{
    SessionGrantAdminIntrospectionStatus, SessionGrantValidationInput,
    SessionGrantValidationMetadata, SessionGrantValidationResponseBody,
};

/// TTL for the session-grant introspection cache (api-conventions.md §3.3 D2:
/// SHOULD ≤ 120s). The revocation-visibility upper bound equals this TTL;
/// sensitive operations bypass the cache entirely (`force_fresh`).
const INTROSPECTION_CACHE_TTL: StdDuration = StdDuration::from_secs(120);
const INTROSPECTION_CACHE_MAX_ENTRIES: usize = 4096;
const INTROSPECTION_HTTP_CLIENT_TTL: StdDuration = StdDuration::from_secs(300);
const INTROSPECTION_HTTP_CLIENT_MAX_ENTRIES: usize = 32;

/// DPoP proof freshness window. The proof's `iat` MUST be within
/// [now - WINDOW, now + skew]; combined with single-use `jti` tracking this
/// bounds replay to the same scale as the §3.2 / federation PoP windows.
const DPOP_MAX_AGE_SECONDS: i64 = 300;
const DPOP_MAX_FUTURE_SKEW_SECONDS: i64 = 30;
const DPOP_REPLAY_MAX_ENTRIES: usize = 50_000;

type AuthError = (StatusCode, &'static str, &'static str);

fn unauthenticated(message: &'static str) -> AuthError {
    (StatusCode::UNAUTHORIZED, "unauthenticated", message)
}

fn canonical_session_grant(secret: &str) -> Result<SessionGrantSecret, AuthError> {
    SessionGrantSecret::new(secret)
        .map_err(|_| unauthenticated("session grant is not a canonical opaque credential"))
}

async fn require_introspection_metadata_context(
    state: &AppState,
    grant: &SessionGrantValidationMetadata,
) -> Result<(), AuthError> {
    let issuer = crate::routing::events::peer::trusted_account_authority_id(state)
        .await
        .map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "trusted Account Authority binding is unavailable",
            )
        })?;
    if grant.issuer_id != issuer
        || grant.audience_id != configured_service_audience(state)?
        || grant.revoked_at.is_some()
        || grant.validate().is_err()
    {
        return Err(unauthenticated(
            "session grant issuer metadata does not bind this request",
        ));
    }
    let now = crate::wire::now();
    if grant.not_before > now {
        return Err(unauthenticated("session grant is not active yet"));
    }
    if grant.expires_at <= now {
        return Err((
            StatusCode::UNAUTHORIZED,
            "auth_expired",
            "session grant has expired",
        ));
    }
    Ok(())
}

fn configured_service_audience(state: &AppState) -> Result<DidCoreId, AuthError> {
    DidCoreId::new(state.service_id().clone()).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "runtime principal service_id is not a core_id",
        )
    })
}

// ── Introspection cache ──────────────────────────────────────────────────────

#[derive(Clone)]
struct CachedIntrospection {
    grant: SessionGrantValidationMetadata,
    inserted_at: Instant,
}

struct IntrospectionCacheSlot {
    identity: Arc<()>,
    last_used_at: Instant,
    cached: Option<CachedIntrospection>,
}

#[derive(Clone)]
struct IntrospectionReadLease {
    identity: Arc<()>,
    started_at: Instant,
}

/// Process-local introspection cache. Same in-memory trade-off as the other
/// coland reducer projections (`handle_releases`, `account_lifecycle`): a
/// restart drops the cache and the next request re-introspects. Keyed by a
/// service-DID-bound hash of the presented grant so cross-audience grants never
/// collide.
static INTROSPECTION_CACHE: LazyLock<Mutex<HashMap<String, IntrospectionCacheSlot>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[derive(Clone)]
struct CachedIntrospectionHttpClient {
    url: reqwest::Url,
    client: reqwest::Client,
    inserted_at: Instant,
}

/// Reuse the connection pool for the configured Account Authority process instead of
/// constructing a fresh reqwest client for every force-fresh introspection.
///
/// Sensitive self operations intentionally bypass the grant-result cache, so a
/// long-lived process can perform thousands of remote introspections. Creating
/// one client per request disables keep-alive and can exhaust ephemeral ports
/// under a full conformance run. The cache is bounded and keyed by the complete
/// configured URL plus the private-network posture; each cached client remains
/// pinned to the addresses that passed the egress guard when it was built.
static INTROSPECTION_HTTP_CLIENTS: LazyLock<Mutex<HashMap<String, CachedIntrospectionHttpClient>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// `api-conventions.md` §3.3: the cache key MUST isolate at least the exact
/// token, the expected `audience_id` and the authority configuration context.
/// It MUST NOT be the `jti` or the grant id — neither identifies the exact
/// credential that the ledger matched.
fn introspection_cache_key(grant_secret: &str, audience: &str, authority_context: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(audience.as_bytes());
    hasher.update(b":");
    hasher.update(authority_context.as_bytes());
    hasher.update(b":");
    hasher.update(grant_secret.as_bytes());
    format!(
        "grant-introspect:{}",
        URL_SAFE_NO_PAD.encode(hasher.finalize())
    )
}

/// The configured introspection authority this result came from. A retargeted
/// or reconfigured Account Authority is a different authority context, so its
/// answers never collide with the previous one's in the cache.
pub(crate) fn introspection_authority_context(state: &AppState) -> String {
    format!(
        "url={}\nprivate_networks={}\nauthority_url={}\nissuer={}\nauthority_domain={}\nauthority_key={}\nchannel_credential_digest={}",
        state
            .config()
            .session_grant_introspection_url
            .as_deref()
            .unwrap_or_default(),
        crate::security::private_networks_allowed(state.config().development_mode),
        state
            .config()
            .account_authority_url
            .as_deref()
            .unwrap_or_default(),
        state.service_core_id(),
        state
            .config()
            .internal_authority_channel
            .as_ref()
            .map(|channel| channel.account_authority_trust_domain().as_str())
            .unwrap_or_default(),
        state
            .config()
            .account_authority_public_key_multibase
            .as_deref()
            .unwrap_or_default(),
        state
            .config()
            .internal_authority_channel
            .as_ref()
            .map(
                |channel| arkret_canonical::sha256_digest(channel.credential().as_bytes())
                    .to_string()
            )
            .unwrap_or_default(),
    )
}

fn introspection_cache_key_for(state: &AppState, grant_secret: &str) -> String {
    introspection_cache_key(
        grant_secret,
        state.service_id(),
        &introspection_authority_context(state),
    )
}

fn cache_lookup(key: &str) -> Option<(SessionGrantValidationMetadata, IntrospectionReadLease)> {
    cache_lookup_at(key, Instant::now())
}

fn cache_lookup_at(
    key: &str,
    now: Instant,
) -> Option<(SessionGrantValidationMetadata, IntrospectionReadLease)> {
    let mut cache = INTROSPECTION_CACHE.lock();
    cache_lookup_locked(&mut cache, key, now)
}

fn cache_lookup_locked(
    cache: &mut HashMap<String, IntrospectionCacheSlot>,
    key: &str,
    now: Instant,
) -> Option<(SessionGrantValidationMetadata, IntrospectionReadLease)> {
    prune_introspection_cache_locked(cache, now);
    let entry = cache.get_mut(key)?;
    let cached = entry.cached.as_ref()?;
    if !now
        .checked_duration_since(cached.inserted_at)
        .is_some_and(|age| age < INTROSPECTION_CACHE_TTL)
    {
        entry.cached = None;
        return None;
    }
    Some((
        cached.grant.clone(),
        IntrospectionReadLease {
            identity: Arc::clone(&entry.identity),
            started_at: cached.inserted_at,
        },
    ))
}

fn begin_introspection_read_locked(
    cache: &mut HashMap<String, IntrospectionCacheSlot>,
    key: &str,
    now: Instant,
    capacity: usize,
) -> IntrospectionReadLease {
    assert!(capacity > 0, "the introspection cache capacity is nonzero");
    prune_introspection_cache_locked(cache, now);
    if !cache.contains_key(key) {
        while cache.len() >= capacity {
            let Some(oldest_key) = cache
                .iter()
                .min_by_key(|(_, entry)| entry.last_used_at)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            cache.remove(&oldest_key);
        }
        cache.insert(
            key.to_owned(),
            IntrospectionCacheSlot {
                identity: Arc::new(()),
                last_used_at: now,
                cached: None,
            },
        );
    }
    let entry = cache
        .get_mut(key)
        .expect("the bounded read slot was inserted");
    entry.last_used_at = now;
    entry.cached = None;
    IntrospectionReadLease {
        identity: Arc::clone(&entry.identity),
        started_at: now,
    }
}

fn introspection_read_is_current_locked(
    cache: &mut HashMap<String, IntrospectionCacheSlot>,
    key: &str,
    lease: &IntrospectionReadLease,
    now: Instant,
) -> bool {
    prune_introspection_cache_locked(cache, now);
    now.checked_duration_since(lease.started_at)
        .is_some_and(|age| age < INTROSPECTION_CACHE_TTL)
        && cache
            .get(key)
            .is_some_and(|entry| Arc::ptr_eq(&entry.identity, &lease.identity))
}

fn publish_introspection_locked(
    cache: &mut HashMap<String, IntrospectionCacheSlot>,
    key: &str,
    lease: &IntrospectionReadLease,
    grant: SessionGrantValidationMetadata,
    now: Instant,
) -> bool {
    if !introspection_read_is_current_locked(cache, key, lease, now) {
        return false;
    }
    let entry = cache.get_mut(key).expect("the checked read slot exists");
    // A delayed response must not reset the lifetime of an older observation
    // or replace an already newer positive observation in this same epoch.
    if entry
        .cached
        .as_ref()
        .is_none_or(|cached| cached.inserted_at <= lease.started_at)
    {
        entry.cached = Some(CachedIntrospection {
            grant,
            inserted_at: lease.started_at,
        });
    }
    entry.last_used_at = now;
    true
}

fn prune_introspection_cache_locked(
    cache: &mut HashMap<String, IntrospectionCacheSlot>,
    now: Instant,
) {
    cache.retain(|_, entry| {
        now.checked_duration_since(entry.last_used_at)
            .is_some_and(|age| age < INTROSPECTION_CACHE_TTL)
    });
}

fn introspection_http_client(
    raw_url: &str,
    development_mode: bool,
) -> Result<(reqwest::Url, reqwest::Client), String> {
    let cache_key = introspection_http_client_cache_key(raw_url, development_mode);
    let mut clients = INTROSPECTION_HTTP_CLIENTS.lock();
    let reusable = clients
        .get(&cache_key)
        .filter(|cached| cached.inserted_at.elapsed() < INTROSPECTION_HTTP_CLIENT_TTL)
        .map(|cached| (cached.url.clone(), cached.client.clone()));
    if let Some(cached) = reusable {
        return Ok(cached);
    }
    clients.remove(&cache_key);

    let (url, client) = crate::security::validate_http_url_for_egress_with_pinned_client(
        raw_url,
        "session grant introspection",
        development_mode,
        StdDuration::from_secs(10),
    )?;
    while clients.len() >= INTROSPECTION_HTTP_CLIENT_MAX_ENTRIES {
        let Some(oldest_key) = clients
            .iter()
            .min_by_key(|(_, cached)| cached.inserted_at)
            .map(|(key, _)| key.clone())
        else {
            break;
        };
        clients.remove(&oldest_key);
    }
    clients.insert(
        cache_key,
        CachedIntrospectionHttpClient {
            url: url.clone(),
            client: client.clone(),
            inserted_at: Instant::now(),
        },
    );
    Ok((url, client))
}

fn introspection_http_client_cache_key(raw_url: &str, development_mode: bool) -> String {
    let private_networks_allowed = crate::security::private_networks_allowed(development_mode);
    format!("{raw_url}\nprivate_networks={private_networks_allowed}")
}

fn invalidate_introspection_http_client(raw_url: &str, development_mode: bool) {
    let cache_key = introspection_http_client_cache_key(raw_url, development_mode);
    INTROSPECTION_HTTP_CLIENTS.lock().remove(&cache_key);
}

/// Drop any cached introspection entry for `grant_secret`. Called by logout so the
/// next introspection of that grant goes to coauth and observes `active=false`
/// (account-lifecycle.md §4.1 step 3 — the local-side invalidation).
pub(crate) fn invalidate_cached_grant(state: &AppState, grant_secret: &str) {
    let key = introspection_cache_key_for(state, grant_secret);
    {
        let mut cache = INTROSPECTION_CACHE.lock();
        cache.remove(&key);
    }
}

/// Reusable coauth session-grant introspection with the ≤120s TTL cache.
///
/// `force_fresh = true` bypasses the cache (sensitive operations, §3.3 D2) and
/// re-introspects against coauth, refreshing the cached value on success.
/// Returns the active grant's full metadata (subject / device_id / audience /
/// scopes / expiry / session_public_key / cnf_jkt). An inactive / unknown grant
/// is an `unauthenticated` error, not `Ok(None)`.
pub(crate) async fn introspect_session_grant_cached(
    state: &AppState,
    grant_secret: &str,
    force_fresh: bool,
) -> Result<SessionGrantValidationMetadata, AuthError> {
    canonical_session_grant(grant_secret)?;
    let key = introspection_cache_key_for(state, grant_secret);
    if !force_fresh && let Some((grant, lease)) = cache_lookup(&key) {
        // Cached grants can still expire between introspection and use.
        require_introspection_metadata_context(state, &grant).await?;
        if !introspection_read_is_current_locked(
            &mut INTROSPECTION_CACHE.lock(),
            &key,
            &lease,
            Instant::now(),
        ) {
            return Err(retired_introspection_read());
        }
        return Ok(grant);
    }
    let lease = begin_introspection_read_locked(
        &mut INTROSPECTION_CACHE.lock(),
        &key,
        Instant::now(),
        INTROSPECTION_CACHE_MAX_ENTRIES,
    );
    let Some(grant) = introspect_session_grant_remote(state, grant_secret).await? else {
        // A typed, authenticated inactive observation retires every earlier
        // read of this exact key, regardless of response arrival order. There
        // is no tombstone: a later read creates a distinct Arc identity.
        INTROSPECTION_CACHE.lock().remove(&key);
        return Err(unauthenticated("session grant is not active"));
    };
    if !publish_introspection_locked(
        &mut INTROSPECTION_CACHE.lock(),
        &key,
        &lease,
        grant.clone(),
        Instant::now(),
    ) {
        return Err(retired_introspection_read());
    }
    Ok(grant)
}

fn retired_introspection_read() -> AuthError {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
        "session grant introspection result was retired while in flight",
    )
}

// ── One authoritative result per request ─────────────────────────────────────

/// The single authoritative introspection result of one inbound HTTP request.
///
/// `api-conventions.md` §3.3: a request MUST determine the strictest freshness
/// any of its consumers needs, take **one** authoritative result at that
/// freshness, and hand that same result to every later gate. It MUST NOT
/// introspect a second, independent time — in particular the high-security
/// RFC 9421 `session_public_key` MUST come from this result rather than from
/// its own lookup.
///
/// The memo is request-scoped by construction: it lives in the request's own
/// extension map and dies with the request, so nothing here can turn into a
/// cross-request "already verified" flag.
#[derive(Clone)]
struct RequestAuthoritativeGrant {
    /// The exact presented token these metadata belong to.
    grant_secret: String,
    /// Whether the result was taken with the cache bypassed. A memo taken
    /// fresh also satisfies a later consumer that only needs the cached
    /// freshness; the reverse is not true and re-introspects.
    taken_fresh: bool,
    authority_context: String,
    grant: SessionGrantValidationMetadata,
}

/// Record this request's single authoritative result. Called from the one place
/// that holds `&mut Request` before any handler runs (the RFC 9421 PoP hoop).
pub(crate) async fn take_request_authoritative_grant(
    state: &AppState,
    req: &mut Request,
    grant_secret: &str,
    force_fresh: bool,
) -> Result<SessionGrantValidationMetadata, AuthError> {
    if let Some(grant) = memoized_grant(state, req, grant_secret, force_fresh) {
        require_introspection_metadata_context(state, &grant).await?;
        return Ok(grant);
    }
    let grant = introspect_session_grant_cached(state, grant_secret, force_fresh).await?;
    req.extensions_mut().insert(RequestAuthoritativeGrant {
        grant_secret: grant_secret.to_owned(),
        taken_fresh: force_fresh,
        authority_context: introspection_authority_context(state),
        grant: grant.clone(),
    });
    Ok(grant)
}

/// Reuse this request's authoritative result when one was already taken at a
/// freshness at least as strict as the caller needs; otherwise introspect.
async fn request_authoritative_grant(
    state: &AppState,
    req: &Request,
    grant_secret: &str,
    force_fresh: bool,
) -> Result<SessionGrantValidationMetadata, AuthError> {
    if let Some(grant) = memoized_grant(state, req, grant_secret, force_fresh) {
        require_introspection_metadata_context(state, &grant).await?;
        return Ok(grant);
    }
    introspect_session_grant_cached(state, grant_secret, force_fresh).await
}

fn memoized_grant(
    state: &AppState,
    req: &Request,
    grant_secret: &str,
    force_fresh: bool,
) -> Option<SessionGrantValidationMetadata> {
    let memo = req.extensions().get::<RequestAuthoritativeGrant>()?;
    // The memo belongs to the exact token it was taken for. A request that
    // somehow presents a different credential gets its own authoritative read.
    if memo.grant_secret != grant_secret
        || (force_fresh && !memo.taken_fresh)
        || memo.authority_context != introspection_authority_context(state)
    {
        return None;
    }
    Some(memo.grant.clone())
}

/// Raw coauth introspection (no cache). Reads `cnf_jkt`, `session_public_key`,
/// scopes, subject, device_id and expiry off the introspection response.
async fn introspect_session_grant_remote(
    state: &AppState,
    grant_secret: &str,
) -> Result<Option<SessionGrantValidationMetadata>, AuthError> {
    let Some(introspection_url) = state.config().session_grant_introspection_url.as_deref() else {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "session grant introspection URL is not configured",
        ));
    };
    let Some(channel) = state.config().internal_authority_channel.as_ref() else {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "session grant introspection internal channel is not configured",
        ));
    };
    let presented = canonical_session_grant(grant_secret)?;
    let audience = configured_service_audience(state)?;
    let expected_issuer = crate::routing::events::peer::trusted_account_authority_id(state)
        .await
        .map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "trusted Account Authority binding is unavailable",
            )
        })?;
    let request = SessionGrantValidationInput::BySecret(SessionGrantValidationBySecret {
        session_grant: presented.clone(),
        audience_id: audience.clone(),
        // The Account Authority returns non-secret grant metadata over this
        // authenticated S2S channel; holder possession is verified below by the
        // request's DPoP proof against the returned `cnf_jkt`.
        proof: None,
    });
    // SOL-03-002: pin validated IPs into the client to close the DNS-rebinding
    // TOCTOU window between the egress check and the connection.
    // Introspection is read-only. A pooled keep-alive connection can be closed
    // by the Account Authority process between requests, especially during long conformance
    // runs that force fresh introspection on every sensitive operation. Retry
    // one transport failure after discarding the pinned client; URL validation
    // and address pinning are repeated before the replacement connection is
    // used. Authentication/protocol failures below remain single-shot.
    let mut response = None;
    for attempt in 0..2 {
        let (validated_url, client) =
            introspection_http_client(introspection_url, state.config().development_mode).map_err(
                |_| {
                    (
                        StatusCode::SERVICE_UNAVAILABLE,
                        "temporarily_unavailable",
                        "session grant introspection service unavailable",
                    )
                },
            )?;
        match client
            .post(validated_url)
            .bearer_auth(channel.credential())
            .json(&request)
            .send()
            .await
        {
            Ok(value) => {
                response = Some(value);
                break;
            }
            Err(_) if attempt == 0 => {
                invalidate_introspection_http_client(
                    introspection_url,
                    state.config().development_mode,
                );
            }
            Err(_) => {
                return Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "session grant introspection request failed",
                ));
            }
        }
    }
    let response = response.ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
        "session grant introspection request failed",
    ))?;
    require_successful_introspection(response.status().as_u16())?;
    let outcome = response
        .json::<SessionGrantValidationResponseBody>()
        .await
        .map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "session grant introspection response was invalid",
            )
        })?;
    let binding = SessionGrantValidationBinding::from_authenticated_response(
        &request,
        &expected_issuer,
        outcome,
    )
    .map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "issuer returned inconsistent exact credential metadata",
        )
    })?;
    let outcome = binding.response();
    if !outcome.active || outcome.status != SessionGrantAdminIntrospectionStatus::Active {
        return Ok(None);
    }
    let grant = outcome.grant.clone().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
        "session grant introspection omitted grant metadata",
    ))?;
    require_introspection_metadata_context(state, &grant).await?;
    binding
        .validate_request_binding(
            &presented,
            &expected_issuer,
            &grant.account_id,
            &audience,
            crate::wire::now(),
        )
        .map_err(|_| unauthenticated("exact credential result does not bind this request"))?;
    Ok(Some(grant))
}

fn require_successful_introspection(
    status: u16,
) -> Result<(), (StatusCode, &'static str, &'static str)> {
    if (200..300).contains(&status) {
        Ok(())
    } else {
        tracing::warn!(
            upstream_status = status,
            "session grant introspection returned no authoritative outcome"
        );
        Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "session grant introspection service did not return an authoritative outcome",
        ))
    }
}

// ── DPoP replay defense ──────────────────────────────────────────────────────

/// Single-use `jti` ledger for DPoP replay defense. An entry is the jti's
/// `iat`-bounded expiry; once past it, the jti is swept and re-usable only
/// because the `iat` freshness check would have already rejected it. Same
/// process-local trade-off as the introspection cache.
struct DpopReplayLedger {
    entries: HashMap<String, DateTime<Utc>>,
    next_sweep_at: DateTime<Utc>,
}

static DPOP_REPLAY: LazyLock<Mutex<DpopReplayLedger>> = LazyLock::new(|| {
    Mutex::new(DpopReplayLedger {
        entries: HashMap::new(),
        next_sweep_at: DateTime::<Utc>::MIN_UTC,
    })
});

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DpopReplayRegistration {
    Accepted,
    Replay,
    Full,
}

/// Record `jti` as seen. Sweeps expired entries opportunistically and fails
/// closed when the bounded replay ledger is full.
fn register_dpop_jti(jti: &str, expires_at: DateTime<Utc>) -> DpopReplayRegistration {
    let now = crate::wire::now();
    let mut ledger = DPOP_REPLAY.lock();
    let sweep_expired = now >= ledger.next_sweep_at;
    if sweep_expired {
        ledger.next_sweep_at = now + Duration::seconds(1);
    }
    register_dpop_jti_locked(
        &mut ledger.entries,
        jti,
        expires_at,
        now,
        DPOP_REPLAY_MAX_ENTRIES,
        sweep_expired,
    )
}

fn register_dpop_jti_locked(
    seen: &mut HashMap<String, DateTime<Utc>>,
    jti: &str,
    expires_at: DateTime<Utc>,
    now: DateTime<Utc>,
    max_entries: usize,
    sweep_expired: bool,
) -> DpopReplayRegistration {
    if sweep_expired || seen.len() >= max_entries {
        seen.retain(|_, expiry| *expiry > now);
    }
    if seen.contains_key(jti) {
        return DpopReplayRegistration::Replay;
    }
    if seen.len() >= max_entries {
        return DpopReplayRegistration::Full;
    }
    seen.insert(jti.to_owned(), expires_at);
    DpopReplayRegistration::Accepted
}

// ── DPoP proof verification ──────────────────────────────────────────────────

/// Read the verbatim `DPoP` header value.
pub(crate) fn dpop_header(req: &Request) -> Option<String> {
    req.headers()
        .get("dpop")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

// ── Orchestration ────────────────────────────────────────────────────────────

/// Whether an `ak.session.grant` is presented through the RFC 9449 token
/// scheme. Proof presence is validated separately so `Authorization: DPoP`
/// without a `DPoP` header fails as an incomplete grant presentation.
pub(crate) fn is_grant_dpop_presentation(req: &Request) -> bool {
    coland_http::util::dpop_token(req).is_some()
}

fn session_binding_from_introspection(
    grant: &SessionGrantValidationMetadata,
) -> Result<SessionEndpointState, AuthError> {
    grant.validate().map_err(|_| {
        unauthenticated("session grant introspection authorization metadata is incomplete")
    })?;
    let authority = grant.account_id();
    if authority.station_id != grant.audience_id {
        return Err(unauthenticated(
            "session grant authority context does not match its subject/audience",
        ));
    }
    if let SessionGrantHolderBinding::AgentRuntime { agent_id, .. } = &grant.holder_binding {
        // The wire DTO closes agent grants to the self-contained typed holder
        // binding: top-level `device_id`/`device_binding` are the human-device
        // shape and MUST be absent. Agent authority is the exact principal,
        // method and accepted key-authorization Event triple.
        if agent_id != &grant.account_id.principal_id {
            return Err(unauthenticated(
                "agent holder binding does not match the introspected subject",
            ));
        }
        return Ok(SessionEndpointState::AgentRuntime {
            state: AgentSessionRecord {
                metadata: grant.metadata.clone(),
                freshness_state: FreshnessState::Fresh,
            },
        });
    }

    if let SessionGrantHolderBinding::RecoveryCandidateDevice { device_id } = &grant.holder_binding
    {
        if grant.credential_class
            != arkret_models_identity::SessionGrantCredentialClass::RecoverySession
            || grant.device_binding.is_some()
            || grant.device_id.as_ref() != Some(device_id)
        {
            return Err(unauthenticated(
                "recovery session grant has an invalid candidate-device binding",
            ));
        }
        return Ok(SessionEndpointState::HumanDevice {
            device_id: device_id.to_string(),
        });
    }

    let binding = grant.human_device_authorization_selector().map_err(|_| {
        unauthenticated("human session grant omitted its device authority selector")
    })?;
    let SessionGrantHolderBinding::HumanDevice { device_binding } = &grant.holder_binding else {
        return Err(unauthenticated("unsupported session grant holder binding"));
    };
    let holder_device_id = DeviceId::new(device_binding.clone())
        .map_err(|_| unauthenticated("session grant holder binding has an invalid device id"))?;
    // `api-conventions.md` §3.3 states two separate MUSTs, both fail-closed as
    // `unauthenticated`. First: the device authorization selector MUST name the
    // same device as the signed typed `holder_binding`.
    if binding.device_id != holder_device_id {
        return Err(unauthenticated(
            "session grant device selector does not match its holder binding",
        ));
    }
    // Second: when introspection also returns top-level device metadata, that
    // metadata MUST equal the signed holder binding verbatim. It is compared
    // against the signed binding itself, never against the selector, so the
    // clause never depends on the selector check having passed.
    if grant.device_id.as_ref() != Some(&holder_device_id) {
        return Err(unauthenticated(
            "session grant device metadata does not match its holder binding",
        ));
    }
    Ok(SessionEndpointState::HumanDevice {
        device_id: binding.device_id.to_string(),
    })
}

pub(crate) fn session_record_from_introspected_grant_for_logout(
    state: &AppState,
    grant_secret: &str,
    grant: &SessionGrantValidationMetadata,
) -> Result<SessionRecord, AuthError> {
    if grant.audience_id.as_str() != state.service_id() {
        return Err(unauthenticated(
            "session grant audience does not match this Station",
        ));
    }
    let endpoint = session_binding_from_introspection(grant)?;
    let token_hash =
        crate::routing::identity::auth::session_credential_hash(grant_secret, state.service_id());
    Ok(SessionRecord {
        token_hash,
        account_pk: None,
        actor: grant.account_id.principal_id.to_string(),
        endpoint,
        audience: state.service_id().clone(),
        session_public_key: Some(grant.session_public_key.as_str().to_owned()),
        session_grant: Some(grant.clone()),
        expires_at: grant.expires_at,
        created_at: crate::wire::now(),
        revoked_at: None,
    })
}

pub(crate) fn verify_grant_dpop_request(
    state: &AppState,
    req: &Request,
    grant_secret: &str,
    cnf_jkt: Option<&str>,
) -> Result<(), AuthError> {
    verify_grant_dpop_request_at_base(req, grant_secret, cnf_jkt, &state.config().public_base_url)
}

pub(crate) fn verify_grant_dpop_request_at_base(
    req: &Request,
    grant_secret: &str,
    cnf_jkt: Option<&str>,
    public_base_url: &str,
) -> Result<(), AuthError> {
    let dpop = dpop_header(req).ok_or_else(|| unauthenticated("missing DPoP proof"))?;
    let cnf_jkt = cnf_jkt.filter(|jkt| !jkt.is_empty()).ok_or_else(|| {
        unauthenticated("session grant introspection omitted cnf_jkt; cannot bind DPoP")
    })?;
    let expected_htu = format!(
        "{}{}",
        public_base_url.trim_end_matches('/'),
        req.uri().path()
    );
    let now = crate::wire::now();
    let verified = arkret_signatures::dpop::verify_dpop_proof(
        &arkret_signatures::dpop::DpopVerificationRequest {
            proof_jwt: &dpop,
            method: req.method().as_str(),
            htu: &expected_htu,
            access_token: Some(grant_secret),
            now,
            max_age: Duration::seconds(DPOP_MAX_AGE_SECONDS),
            max_future_skew: Duration::seconds(DPOP_MAX_FUTURE_SKEW_SECONDS),
            expected_nonce: None,
        },
    )
    .map_err(|_| unauthenticated("DPoP proof validation failed"))?;
    if verified.jkt != cnf_jkt {
        return Err(unauthenticated(
            "DPoP proof key thumbprint does not match the grant's cnf.jkt",
        ));
    }

    let iat = DateTime::<Utc>::from_timestamp(verified.claims.iat, 0)
        .expect("SDK verifier accepts only representable DPoP timestamps");
    let jti_expiry = iat + Duration::seconds(DPOP_MAX_AGE_SECONDS + DPOP_MAX_FUTURE_SKEW_SECONDS);
    match register_dpop_jti(&verified.claims.jti, jti_expiry) {
        DpopReplayRegistration::Accepted => {}
        DpopReplayRegistration::Replay => {
            return Err(unauthenticated(
                "DPoP proof jti has already been used (replay)",
            ));
        }
        DpopReplayRegistration::Full => {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "DPoP replay cache is at capacity",
            ));
        }
    }
    Ok(())
}

/// Validate a presented `ak.session.grant` + DPoP and synthesize a
/// request-scoped `SessionRecord`. Not persisted as a local bearer.
///
/// `force_fresh` forces a non-cached introspection (sensitive operations,
/// §3.3 D2).
pub(crate) async fn grant_dpop_session(
    state: &AppState,
    req: &Request,
    grant_secret: &str,
    force_fresh: bool,
) -> Result<SessionRecord, AuthError> {
    // 1. grant active (cached ≤120s; sensitive ops force fresh). Reads cnf_jkt, session_public_key,
    //    scopes, subject, device_id, expiry.
    //
    //    This is the request's single authoritative result: when the RFC 9421
    //    PoP hoop already took one for this request at this freshness or
    //    stricter, that exact result is reused instead of introspecting again.
    let grant = request_authoritative_grant(state, req, grant_secret, force_fresh).await?;

    // 5. audience == this service's service_id.
    if grant.audience_id.as_str() != state.service_id() {
        return Err(unauthenticated(
            "session grant audience does not match this Station",
        ));
    }

    // 6a/6b. Human/device and agent grants carry closed typed holder bindings.
    let endpoint = session_binding_from_introspection(&grant)?;

    // 6c. grant not expired.
    if grant.expires_at <= crate::wire::now() {
        return Err((
            StatusCode::UNAUTHORIZED,
            "auth_expired",
            "session grant has expired",
        ));
    }

    // 2. DPoP signature valid against the grant's cnf.jkt.
    verify_grant_dpop_request(state, req, grant_secret, Some(&grant.cnf_jkt))?;

    Ok(session_from_verified_grant(
        state,
        grant_secret,
        grant,
        endpoint,
    ))
}

/// Native, non-transferable authentication material constructed only by the
/// original exact-token/DPoP request boundary. Not a serializable allow ticket.
/// Issuer observation precedes acquisition of every local held reply cut.
pub(crate) struct NativeReplyAuthenticatedSession {
    session: SessionRecord,
}
impl NativeReplyAuthenticatedSession {
    pub(crate) fn session(&self) -> &SessionRecord {
        &self.session
    }
}

pub(crate) async fn authenticate_native_reply_session(
    state: &AppState,
    req: &mut Request,
    grant_secret: &str,
) -> Result<NativeReplyAuthenticatedSession, AuthError> {
    // The standard RFC 9421 request hoop must already have verified the request.
    // This takes (or reuses) the same strict request memo for DPoP and downstream
    // actor/ceiling checks, rather than independently parsing a JWT locally.
    take_request_authoritative_grant(state, req, grant_secret, true).await?;
    let session = grant_dpop_session(state, req, grant_secret, true).await?;
    if session.agent_session().is_none()
        || session.revoked_at.is_some()
        || !matches!(
            session.session_grant.as_ref().map(|g| &g.holder_binding),
            Some(SessionGrantHolderBinding::AgentRuntime { .. })
        )
    {
        return Err(unauthenticated(
            "native reply requires an authenticated Agent runtime",
        ));
    }
    Ok(NativeReplyAuthenticatedSession { session })
}

/// Synthesize the request- or connection-scoped `SessionRecord` from an
/// already-verified grant. Not persisted as a local bearer.
///
/// `token_hash` carries a stable, grant-derived value so downstream code that
/// keys on it (e.g. self-path session-revoke of the calling session) resolves
/// to this grant.
pub(crate) fn session_from_verified_grant(
    state: &AppState,
    grant_secret: &str,
    grant: SessionGrantValidationMetadata,
    endpoint: SessionEndpointState,
) -> SessionRecord {
    let grant_context = grant.clone();
    SessionRecord {
        token_hash: crate::routing::identity::auth::session_credential_hash(
            grant_secret,
            state.service_id(),
        ),
        account_pk: None,
        actor: grant.account_id.principal_id.to_string(),
        endpoint,
        audience: state.service_id().clone(),
        session_public_key: Some(grant.session_public_key.as_str().to_owned()),
        session_grant: Some(grant_context),
        expires_at: grant.expires_at,
        created_at: crate::wire::now(),
        revoked_at: None,
    }
}

/// Resolve the exact account authority retained from the authenticated credential.
/// A principal string is never sufficient to reconstruct a missing Station.
pub(crate) async fn authenticated_session_account_id(
    state: &AppState,
    session: &SessionRecord,
) -> Result<arkret_wire::AccountId, coland_http::error::AppError> {
    use coland_http::error::AppError;
    let unauthenticated = || {
        crate::app_error!(
            Unauthenticated,
            "authenticated session has no exact account authority",
        )
    };
    let signed_account = session
        .session_grant
        .as_ref()
        .map(|grant| &grant.account_id);
    let persisted_account = match session.account_pk {
        Some(account_pk) => Some(
            state
                .identities()
                .account_by_id(account_pk)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?
                .ok_or_else(unauthenticated)?
                .account_id,
        ),
        None => None,
    };
    if let (Some(signed), Some(persisted)) = (signed_account, persisted_account.as_ref())
        && signed != persisted
    {
        return Err(unauthenticated());
    }
    let account_id = signed_account
        .cloned()
        .or(persisted_account)
        .ok_or_else(unauthenticated)?;
    account_id.validate().map_err(|_| unauthenticated())?;
    if account_id.principal_id.as_str() != session.actor {
        return Err(unauthenticated());
    }
    Ok(account_id)
}

/// The §6a/§6b session binding of an introspected grant, exposed for the
/// WebSocket binding which validates its holder proof out of band.
pub(crate) fn grant_session_binding(
    grant: &SessionGrantValidationMetadata,
) -> Result<SessionEndpointState, AuthError> {
    session_binding_from_introspection(grant)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use arkret_identifiers::SessionGrantId;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    async fn read_mock_http_request(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
        let mut request = Vec::new();
        let mut content_length = None;
        let mut header_end = None;
        loop {
            let mut chunk = [0_u8; 2048];
            let read = stream.read(&mut chunk).await.expect("read mock request");
            assert!(read > 0, "mock request ended before its body");
            request.extend_from_slice(&chunk[..read]);
            if header_end.is_none()
                && let Some(index) = request.windows(4).position(|part| part == b"\r\n\r\n")
            {
                let end = index + 4;
                let headers = String::from_utf8_lossy(&request[..end]);
                content_length = Some(
                    headers
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .and_then(|value| value.trim().parse::<usize>().ok())
                        })
                        .unwrap_or(0),
                );
                header_end = Some(end);
            }
            if header_end
                .zip(content_length)
                .is_some_and(|(end, length)| request.len() >= end + length)
            {
                let (end, length) = header_end.zip(content_length).unwrap();
                return request[end..end + length].to_vec();
            }
        }
    }

    async fn spawn_counting_introspection_mock(
        outcome: SessionGrantValidationResponseBody,
        expected_secret: SessionGrantSecret,
    ) -> (
        String,
        Arc<AtomicUsize>,
        Arc<Mutex<SessionGrantValidationResponseBody>>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind introspection mock");
        let address = listener.local_addr().expect("mock address");
        let count = Arc::new(AtomicUsize::new(0));
        let observed = count.clone();
        let expected_audience = outcome.grant.as_ref().unwrap().audience_id.clone();
        let slot = Arc::new(Mutex::new(outcome));
        let answers = slot.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let request = read_mock_http_request(&mut stream).await;
                let SessionGrantValidationInput::BySecret(input) =
                    serde_json::from_slice(&request).unwrap()
                else {
                    panic!("request must introspect the exact opaque secret");
                };
                assert_eq!(input.session_grant, expected_secret);
                assert_eq!(input.audience_id, expected_audience);
                assert!(
                    input.proof.is_none(),
                    "holder proof is verified at the request gate"
                );
                let body = serde_json::to_vec(&*answers.lock()).unwrap();
                observed.fetch_add(1, Ordering::SeqCst);
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("write headers");
                stream.write_all(&body).await.expect("write body");
            }
        });
        (format!("http://{address}/introspect"), count, slot, task)
    }

    enum GatedIntrospectionReply {
        Outcome(Box<SessionGrantValidationResponseBody>),
        Failure(u16),
        Close,
    }

    async fn spawn_gated_introspection_mock(
        expected_secret: SessionGrantSecret,
        expected_audience: DidCoreId,
    ) -> (
        String,
        tokio::sync::mpsc::UnboundedReceiver<tokio::sync::oneshot::Sender<GatedIntrospectionReply>>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (observed, requests) = tokio::sync::mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            let mut handlers = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    connection = listener.accept() => {
                        let (mut stream, _) = connection.unwrap();
                        let observed = observed.clone();
                        let expected_secret = expected_secret.clone();
                        let expected_audience = expected_audience.clone();
                        handlers.spawn(async move {
                            let request = tokio::time::timeout(
                                StdDuration::from_secs(5),
                                read_mock_http_request(&mut stream),
                            ).await.unwrap();
                            let SessionGrantValidationInput::BySecret(input) =
                                serde_json::from_slice(&request).unwrap()
                            else {
                                panic!("the real reader must send the exact opaque secret");
                            };
                            assert_eq!(input.session_grant, expected_secret);
                            assert_eq!(input.audience_id, expected_audience);
                            assert!(input.proof.is_none());
                            let (reply, response) = tokio::sync::oneshot::channel();
                            observed.send(reply).unwrap();
                            let reply = tokio::time::timeout(StdDuration::from_secs(10), response)
                                .await.unwrap().unwrap();
                            let (status, body) = match reply {
                                GatedIntrospectionReply::Outcome(outcome) =>
                                    (200, serde_json::to_vec(&outcome).unwrap()),
                                GatedIntrospectionReply::Failure(status) => (status, Vec::new()),
                                GatedIntrospectionReply::Close => return,
                            };
                            let headers = format!(
                                "HTTP/1.1 {status} mock\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                                body.len(),
                            );
                            stream.write_all(headers.as_bytes()).await.unwrap();
                            stream.write_all(&body).await.unwrap();
                        });
                    }
                    completed = handlers.join_next(), if !handlers.is_empty() => {
                        completed.unwrap().unwrap();
                    }
                }
            }
        });
        (format!("http://{address}/introspect"), requests, task)
    }

    async fn next_gated_introspection_reply(
        requests: &mut tokio::sync::mpsc::UnboundedReceiver<
            tokio::sync::oneshot::Sender<GatedIntrospectionReply>,
        >,
    ) -> tokio::sync::oneshot::Sender<GatedIntrospectionReply> {
        tokio::time::timeout(StdDuration::from_secs(5), requests.recv())
            .await
            .unwrap()
            .expect("the real HTTP reader must reach the issuer")
    }

    fn start_gated_introspection(
        state: &Arc<AppState>,
        secret: &SessionGrantSecret,
    ) -> tokio::task::JoinHandle<Result<SessionGrantValidationMetadata, AuthError>> {
        let state = Arc::clone(state);
        let secret = secret.clone();
        tokio::spawn(
            async move { introspect_session_grant_cached(&state, secret.as_str(), true).await },
        )
    }

    #[test]
    fn jti_replay_is_rejected_within_window() {
        let expiry = crate::wire::now() + Duration::seconds(60);
        let jti = "test-jti-unique-001";
        assert_eq!(
            register_dpop_jti(jti, expiry),
            DpopReplayRegistration::Accepted
        );
        assert_eq!(
            register_dpop_jti(jti, expiry),
            DpopReplayRegistration::Replay
        );
    }

    #[test]
    fn jti_replay_capacity_fails_closed() {
        let now = crate::wire::now();
        let expiry = now + Duration::seconds(60);
        let mut seen = HashMap::new();
        for index in 0..3 {
            assert_eq!(
                register_dpop_jti_locked(
                    &mut seen,
                    &format!("capacity-jti-{index}"),
                    expiry,
                    now,
                    3,
                    true,
                ),
                DpopReplayRegistration::Accepted
            );
        }

        assert_eq!(
            register_dpop_jti_locked(&mut seen, "capacity-overflow", expiry, now, 3, true),
            DpopReplayRegistration::Full
        );
        assert!(!seen.contains_key("capacity-overflow"));
    }

    #[test]
    fn introspection_failure_never_claims_the_user_grant_is_invalid() {
        for status in [400, 401, 403, 404, 429, 500, 502, 503, 504] {
            let error = require_successful_introspection(status).unwrap_err();
            assert_eq!(error.0, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(error.1, "temporarily_unavailable");
        }
        assert!(require_successful_introspection(200).is_ok());
    }

    #[test]
    fn introspection_cache_key_isolates_token_audience_and_authority_context() {
        let base = introspection_cache_key("grant", "did:web:a", "url=https://aa.example");
        // Expected audience.
        assert_ne!(
            base,
            introspection_cache_key("grant", "did:web:b", "url=https://aa.example")
        );
        // Exact token bytes: a grant that shares a `jti` or a grant id but not
        // the exact credential must never reuse this entry.
        assert_ne!(
            base,
            introspection_cache_key("grant2", "did:web:a", "url=https://aa.example")
        );
        // Authority configuration context.
        assert_ne!(
            base,
            introspection_cache_key("grant", "did:web:a", "url=https://other.example")
        );
    }

    /// `api-conventions.md` §3.3: one request takes one authoritative result at
    /// the strictest freshness it needs and passes that result on. The memo
    /// must therefore be reusable only for the exact token it was taken for,
    /// and only when it is at least as fresh as the later consumer requires —
    /// a cached result never satisfies a force-fresh consumer.
    #[test]
    fn request_memo_reuses_only_the_same_token_at_sufficient_freshness() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            coland_storage_postgres::Db { pool: None },
        );
        let grant = test_introspection_grant();
        let mut cached = Request::default();
        cached.extensions_mut().insert(RequestAuthoritativeGrant {
            grant_secret: "token-a".to_owned(),
            taken_fresh: false,
            authority_context: introspection_authority_context(&state),
            grant: grant.clone(),
        });
        assert!(memoized_grant(&state, &cached, "token-a", false).is_some());
        assert!(
            memoized_grant(&state, &cached, "token-a", true).is_none(),
            "a cached result must not be reused for a force-fresh consumer",
        );
        assert!(memoized_grant(&state, &cached, "token-b", false).is_none());

        let mut fresh = Request::default();
        fresh.extensions_mut().insert(RequestAuthoritativeGrant {
            grant_secret: "token-a".to_owned(),
            taken_fresh: true,
            authority_context: introspection_authority_context(&state),
            grant,
        });
        assert!(memoized_grant(&state, &fresh, "token-a", true).is_some());
        assert!(memoized_grant(&state, &fresh, "token-a", false).is_some());
        assert!(memoized_grant(&state, &fresh, "token-b", true).is_none());
        assert!(memoized_grant(&state, &Request::default(), "token-a", false).is_none());
    }

    #[tokio::test]
    async fn request_memo_cache_and_force_fresh_count_real_http_round_trips() {
        let grant = test_introspection_grant();
        let outcome = SessionGrantValidationResponseBody {
            active: true,
            status: SessionGrantAdminIntrospectionStatus::Active,
            proof_required: false,
            one_time_use_consumed: false,
            grant: Some(grant),
        };
        let secret = SessionGrantSecret::from_bytes(
            sha2::Sha256::digest(uuid::Uuid::now_v7().as_bytes()).into(),
        );
        let (url, count, _, mock) =
            spawn_counting_introspection_mock(outcome, secret.clone()).await;
        let mut config = crate::config::AppConfig::test_default();
        config.development_mode = true;
        config.seed_demo_data = false;
        config.session_grant_introspection_url = Some(url.clone());
        config.account_authority_url = Some(url.trim_end_matches("/introspect").to_owned());
        config.register_test_internal_authority_channel("counting-mock-secret");
        let state = AppState::new(config, coland_storage_postgres::Db { pool: None });
        let token = secret.into_string();
        let key = introspection_cache_key_for(&state, &token);
        INTROSPECTION_CACHE.lock().remove(&key);
        invalidate_introspection_http_client(&url, true);

        let mut request = Request::default();
        take_request_authoritative_grant(&state, &mut request, &token, false)
            .await
            .expect("first consumer introspects");
        request_authoritative_grant(&state, &request, &token, false)
            .await
            .expect("second consumer reuses request memo");
        assert_eq!(count.load(Ordering::SeqCst), 1, "two consumers use one RTT");

        let mut warm_request = Request::default();
        take_request_authoritative_grant(&state, &mut warm_request, &token, false)
            .await
            .expect("warm cache serves low-sensitivity request");
        assert_eq!(count.load(Ordering::SeqCst), 1, "warm cache adds no RTT");

        take_request_authoritative_grant(&state, &mut warm_request, &token, true)
            .await
            .expect("force-fresh consumer bypasses cached memo");
        request_authoritative_grant(&state, &warm_request, &token, true)
            .await
            .expect("later force-fresh consumer reuses fresh memo");
        assert_eq!(
            count.load(Ordering::SeqCst),
            2,
            "force-fresh adds exactly one RTT"
        );

        INTROSPECTION_CACHE.lock().remove(&key);
        invalidate_introspection_http_client(&url, true);
        mock.abort();
    }

    fn state_for_introspection(url: &str) -> AppState {
        let mut config = crate::config::AppConfig::test_default();
        config.development_mode = true;
        config.seed_demo_data = false;
        config.session_grant_introspection_url = Some(url.to_owned());
        config.account_authority_url = Some(url.trim_end_matches("/introspect").to_owned());
        config.register_test_internal_authority_channel("opaque-consumer-test");
        AppState::new(config, coland_storage_postgres::Db { pool: None })
    }

    fn active_outcome(grant: SessionGrantValidationMetadata) -> SessionGrantValidationResponseBody {
        SessionGrantValidationResponseBody {
            active: true,
            status: SessionGrantAdminIntrospectionStatus::Active,
            proof_required: false,
            one_time_use_consumed: false,
            grant: Some(grant),
        }
    }

    #[tokio::test]
    async fn fresh_revocation_removes_the_previous_positive_cache_entry() {
        let grant = test_introspection_grant();
        let secret = SessionGrantSecret::from_bytes(
            sha2::Sha256::digest(uuid::Uuid::now_v7().as_bytes()).into(),
        );
        let (url, count, slot, task) =
            spawn_counting_introspection_mock(active_outcome(grant.clone()), secret.clone()).await;
        let state = state_for_introspection(&url);
        introspect_session_grant_cached(&state, secret.as_str(), false)
            .await
            .unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 1);
        let mut revoked = grant;
        revoked.revoked_at = Some(crate::wire::now());
        *slot.lock() = SessionGrantValidationResponseBody {
            active: false,
            status: SessionGrantAdminIntrospectionStatus::Revoked,
            proof_required: false,
            one_time_use_consumed: false,
            grant: Some(revoked),
        };
        assert_eq!(
            introspect_session_grant_cached(&state, secret.as_str(), true)
                .await
                .unwrap_err()
                .0,
            StatusCode::UNAUTHORIZED
        );
        assert!(
            !INTROSPECTION_CACHE
                .lock()
                .contains_key(&introspection_cache_key_for(&state, secret.as_str()))
        );
        assert_eq!(
            introspect_session_grant_cached(&state, secret.as_str(), false)
                .await
                .unwrap_err()
                .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            count.load(Ordering::SeqCst),
            3,
            "an ordinary read cannot resurrect the old positive result"
        );
        invalidate_introspection_http_client(&url, true);
        task.abort();
    }

    #[tokio::test]
    async fn issuer_response_cannot_establish_its_own_trust_or_bypass_validity() {
        for (case, expected_status) in [
            ("issuer", StatusCode::SERVICE_UNAVAILABLE),
            ("future", StatusCode::UNAUTHORIZED),
            ("expired", StatusCode::UNAUTHORIZED),
        ] {
            let mut grant = test_introspection_grant();
            match case {
                "issuer" => {
                    grant.metadata.issuer_id =
                        DidCoreId::new("ak:did_core:web:untrusted.example").unwrap()
                }
                "future" => grant.metadata.not_before = crate::wire::now() + Duration::minutes(1),
                "expired" => {
                    grant.metadata.not_before = crate::wire::now() - Duration::minutes(2);
                    grant.metadata.expires_at = crate::wire::now() - Duration::minutes(1);
                }
                _ => unreachable!(),
            }
            let secret = SessionGrantSecret::from_bytes(
                sha2::Sha256::digest(uuid::Uuid::now_v7().as_bytes()).into(),
            );
            let (url, count, _, task) =
                spawn_counting_introspection_mock(active_outcome(grant), secret.clone()).await;
            let state = state_for_introspection(&url);
            let error = introspect_session_grant_cached(&state, secret.as_str(), false)
                .await
                .unwrap_err();
            assert_eq!(error.0, expected_status, "{case}");
            assert_eq!(count.load(Ordering::SeqCst), 1);
            assert!(cache_lookup(&introspection_cache_key_for(&state, secret.as_str())).is_none());
            invalidate_introspection_http_client(&url, true);
            task.abort();
        }
    }

    #[test]
    fn dpop_ath_binds_the_canonical_ascii_secret() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[0x71; 32]);
        let secret = SessionGrantSecret::from_bytes([0xf1; 32]);
        let jwk = arkret_signatures::JsonWebKey::from_ed25519_verifying_key(&key.verifying_key());
        let thumbprint = arkret_signatures::dpop::dpop_jwk_thumbprint(&jwk).unwrap();
        let proof = arkret_signatures::dpop::build_dpop_proof(
            &arkret_signatures::dpop::DpopProofRequest::new(
                "GET",
                "https://station.example/_arkret/self/account/viewer",
            )
            .access_token(secret.as_str()),
            &key,
        )
        .unwrap();
        let claims: serde_json::Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(proof.header_value.split('.').nth(1).unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            claims["ath"],
            URL_SAFE_NO_PAD.encode(Sha256::digest(secret.as_str().as_bytes()))
        );
        assert_ne!(
            claims["ath"],
            URL_SAFE_NO_PAD.encode(Sha256::digest([0xf1; 32])),
            "ath hashes the ASCII representation rather than decoded secret bytes"
        );
        let mut request = Request::default();
        request
            .uri_mut()
            .clone_from(&"/_arkret/self/account/viewer".parse().unwrap());
        request
            .headers_mut()
            .insert("dpop", proof.header_value.parse().unwrap());
        verify_grant_dpop_request_at_base(
            &request,
            secret.as_str(),
            Some(&thumbprint),
            "https://station.example",
        )
        .unwrap();
        assert!(
            verify_grant_dpop_request_at_base(
                &request,
                SessionGrantSecret::from_bytes([0xf2; 32]).as_str(),
                Some(&thumbprint),
                "https://station.example"
            )
            .is_err(),
            "the proof cannot bind another opaque secret"
        );
    }

    #[test]
    fn self_introspection_cache_expires_at_exact_120_second_boundary() {
        let key = "controlled-self-ttl";
        let inserted_at = Instant::now();
        let mut cache = HashMap::new();
        let lease = begin_introspection_read_locked(&mut cache, key, inserted_at, 2);
        assert!(publish_introspection_locked(
            &mut cache,
            key,
            &lease,
            test_introspection_grant(),
            inserted_at,
        ));
        assert!(
            cache_lookup_locked(
                &mut cache,
                key,
                inserted_at + INTROSPECTION_CACHE_TTL - StdDuration::from_nanos(1)
            )
            .is_some()
        );
        assert!(
            cache_lookup_locked(&mut cache, key, inserted_at + INTROSPECTION_CACHE_TTL,).is_none()
        );
    }

    #[tokio::test]
    async fn a_terminal_observation_retires_every_older_inflight_active_result() {
        for status in [
            SessionGrantAdminIntrospectionStatus::Revoked,
            SessionGrantAdminIntrospectionStatus::Superseded,
        ] {
            let grant = test_introspection_grant();
            let secret = SessionGrantSecret::from_bytes(
                sha2::Sha256::digest(uuid::Uuid::now_v7().as_bytes()).into(),
            );
            let (url, mut requests, mock) =
                spawn_gated_introspection_mock(secret.clone(), grant.audience_id.clone()).await;
            let state = Arc::new(state_for_introspection(&url));
            let first = start_gated_introspection(&state, &secret);
            let first_reply = next_gated_introspection_reply(&mut requests).await;
            let terminal = start_gated_introspection(&state, &secret);
            let terminal_reply = next_gated_introspection_reply(&mut requests).await;
            // This third read starts later but also sampled active before the
            // terminal observation. A request-start counter alone is insufficient.
            let later = start_gated_introspection(&state, &secret);
            let later_reply = next_gated_introspection_reply(&mut requests).await;
            let mut inactive = grant.clone();
            if status == SessionGrantAdminIntrospectionStatus::Revoked {
                inactive.revoked_at = Some(crate::wire::now());
            }
            terminal_reply
                .send(GatedIntrospectionReply::Outcome(Box::new(
                    SessionGrantValidationResponseBody {
                        active: false,
                        status,
                        proof_required: false,
                        one_time_use_consumed: false,
                        grant: Some(inactive),
                    },
                )))
                .unwrap_or_else(|_| panic!("terminal reader closed early"));
            assert_eq!(
                terminal.await.unwrap().unwrap_err().0,
                StatusCode::UNAUTHORIZED
            );
            first_reply
                .send(GatedIntrospectionReply::Outcome(Box::new(active_outcome(
                    grant.clone(),
                ))))
                .unwrap_or_else(|_| panic!("first reader closed early"));
            later_reply
                .send(GatedIntrospectionReply::Outcome(Box::new(active_outcome(
                    grant,
                ))))
                .unwrap_or_else(|_| panic!("later reader closed early"));
            for read in [first, later] {
                assert_eq!(
                    read.await.unwrap().unwrap_err().1,
                    "temporarily_unavailable",
                    "retired active bytes cannot be returned or cached",
                );
            }
            assert!(cache_lookup(&introspection_cache_key_for(&state, secret.as_str())).is_none());
            invalidate_introspection_http_client(&url, true);
            mock.abort();
        }
    }

    #[tokio::test]
    async fn explicit_invalidation_cannot_be_undone_after_a_new_slot_is_created() {
        let grant = test_introspection_grant();
        let secret = SessionGrantSecret::from_bytes(
            sha2::Sha256::digest(uuid::Uuid::now_v7().as_bytes()).into(),
        );
        let (url, mut requests, mock) =
            spawn_gated_introspection_mock(secret.clone(), grant.audience_id.clone()).await;
        let state = Arc::new(state_for_introspection(&url));
        let old = start_gated_introspection(&state, &secret);
        let old_reply = next_gated_introspection_reply(&mut requests).await;
        invalidate_cached_grant(&state, secret.as_str());
        let current = start_gated_introspection(&state, &secret);
        let current_reply = next_gated_introspection_reply(&mut requests).await;
        current_reply
            .send(GatedIntrospectionReply::Outcome(Box::new(active_outcome(
                grant.clone(),
            ))))
            .unwrap_or_else(|_| panic!("current reader closed early"));
        current.await.unwrap().unwrap();
        old_reply
            .send(GatedIntrospectionReply::Outcome(Box::new(active_outcome(
                grant,
            ))))
            .unwrap_or_else(|_| panic!("old reader closed early"));
        assert_eq!(old.await.unwrap().unwrap_err().1, "temporarily_unavailable");
        assert!(cache_lookup(&introspection_cache_key_for(&state, secret.as_str())).is_some());
        invalidate_cached_grant(&state, secret.as_str());
        invalidate_introspection_http_client(&url, true);
        mock.abort();
    }

    #[tokio::test]
    async fn transport_and_protocol_failures_do_not_invent_a_terminal_observation() {
        for close_transport in [false, true] {
            let grant = test_introspection_grant();
            let secret = SessionGrantSecret::from_bytes(
                sha2::Sha256::digest(uuid::Uuid::now_v7().as_bytes()).into(),
            );
            let (url, mut requests, mock) =
                spawn_gated_introspection_mock(secret.clone(), grant.audience_id.clone()).await;
            let state = Arc::new(state_for_introspection(&url));
            let active = start_gated_introspection(&state, &secret);
            let active_reply = next_gated_introspection_reply(&mut requests).await;
            let failed = start_gated_introspection(&state, &secret);
            for _ in 0..if close_transport { 2 } else { 1 } {
                let reply = next_gated_introspection_reply(&mut requests).await;
                reply
                    .send(if close_transport {
                        GatedIntrospectionReply::Close
                    } else {
                        GatedIntrospectionReply::Failure(503)
                    })
                    .unwrap_or_else(|_| panic!("failing reader closed early"));
            }
            assert_eq!(
                failed.await.unwrap().unwrap_err().1,
                "temporarily_unavailable"
            );
            active_reply
                .send(GatedIntrospectionReply::Outcome(Box::new(active_outcome(
                    grant,
                ))))
                .unwrap_or_else(|_| panic!("active reader closed early"));
            active.await.unwrap().unwrap();
            assert!(cache_lookup(&introspection_cache_key_for(&state, secret.as_str())).is_some());
            invalidate_cached_grant(&state, secret.as_str());
            invalidate_introspection_http_client(&url, true);
            mock.abort();
        }
    }

    #[test]
    fn cache_eviction_and_expiry_never_allow_an_old_lease_to_recreate_a_slot() {
        let mut cache = HashMap::new();
        let now = Instant::now();
        let old = begin_introspection_read_locked(&mut cache, "a", now, 1);
        let _other =
            begin_introspection_read_locked(&mut cache, "b", now + StdDuration::from_millis(1), 1);
        let current =
            begin_introspection_read_locked(&mut cache, "a", now + StdDuration::from_millis(2), 1);
        assert_eq!(cache.len(), 1);
        assert!(!publish_introspection_locked(
            &mut cache,
            "a",
            &old,
            test_introspection_grant(),
            now + StdDuration::from_millis(3),
        ));
        assert!(publish_introspection_locked(
            &mut cache,
            "a",
            &current,
            test_introspection_grant(),
            now + StdDuration::from_millis(4),
        ));
        assert!(!publish_introspection_locked(
            &mut cache,
            "a",
            &current,
            test_introspection_grant(),
            now + StdDuration::from_millis(2) + INTROSPECTION_CACHE_TTL,
        ));
        assert!(
            cache_lookup_locked(
                &mut cache,
                "a",
                now + StdDuration::from_millis(2) + INTROSPECTION_CACHE_TTL,
            )
            .is_none()
        );
    }

    #[test]
    fn a_late_active_result_preserves_the_newer_observation_and_original_ttl() {
        let mut cache = HashMap::new();
        let now = Instant::now();
        let old = begin_introspection_read_locked(&mut cache, "a", now, 2);
        let current =
            begin_introspection_read_locked(&mut cache, "a", now + StdDuration::from_secs(1), 2);
        assert!(publish_introspection_locked(
            &mut cache,
            "a",
            &current,
            test_introspection_grant(),
            now + StdDuration::from_secs(2),
        ));
        assert!(publish_introspection_locked(
            &mut cache,
            "a",
            &old,
            test_introspection_grant(),
            now + StdDuration::from_secs(3),
        ));
        assert_eq!(
            cache["a"].cached.as_ref().unwrap().inserted_at,
            current.started_at
        );
        assert!(
            cache_lookup_locked(
                &mut cache,
                "a",
                current.started_at + INTROSPECTION_CACHE_TTL,
            )
            .is_none()
        );
    }

    #[test]
    fn introspection_http_client_reuses_the_pinned_connection_pool() {
        let raw_url = "http://127.0.0.1:65530/_arkret/admin/session-grants/introspect";
        let cache_key = introspection_http_client_cache_key(raw_url, true);
        INTROSPECTION_HTTP_CLIENTS.lock().remove(&cache_key);

        introspection_http_client(raw_url, true).unwrap();
        let first_inserted_at = INTROSPECTION_HTTP_CLIENTS
            .lock()
            .get(&cache_key)
            .expect("client cached after first construction")
            .inserted_at;

        introspection_http_client(raw_url, true).unwrap();
        let second_inserted_at = INTROSPECTION_HTTP_CLIENTS
            .lock()
            .get(&cache_key)
            .expect("client remains cached")
            .inserted_at;

        assert_eq!(first_inserted_at, second_inserted_at);
        INTROSPECTION_HTTP_CLIENTS.lock().remove(&cache_key);
    }

    #[test]
    fn introspection_http_client_rebuilds_an_expired_pinned_client() {
        let raw_url = "http://127.0.0.1:65529/_arkret/admin/session-grants/introspect";
        let cache_key = introspection_http_client_cache_key(raw_url, true);
        INTROSPECTION_HTTP_CLIENTS.lock().remove(&cache_key);

        introspection_http_client(raw_url, true).unwrap();
        {
            let mut clients = INTROSPECTION_HTTP_CLIENTS.lock();
            clients
                .get_mut(&cache_key)
                .expect("client cached after first construction")
                .inserted_at = Instant::now() - INTROSPECTION_HTTP_CLIENT_TTL;
        }
        let expired_inserted_at = INTROSPECTION_HTTP_CLIENTS
            .lock()
            .get(&cache_key)
            .expect("expired client remains present until next lookup")
            .inserted_at;

        introspection_http_client(raw_url, true).unwrap();
        let rebuilt_inserted_at = INTROSPECTION_HTTP_CLIENTS
            .lock()
            .get(&cache_key)
            .expect("expired client was rebuilt")
            .inserted_at;

        assert!(rebuilt_inserted_at > expired_inserted_at);
        INTROSPECTION_HTTP_CLIENTS.lock().remove(&cache_key);
    }

    pub(crate) fn test_introspection_grant() -> SessionGrantValidationMetadata {
        let session_public_key = arkret_models_identity::session_credential::CanonicalSessionPublicJwk::new(
            r#"{"crv":"Ed25519","kty":"OKP","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
        ).unwrap();
        let station = crate::test_event::station_id();
        let device_id = DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000001").unwrap();
        SessionGrantValidationMetadata {
            metadata: arkret_models_identity::SessionGrantMetadata {
                id: SessionGrantId::new("ak:session_grant:0196419b-0000-7000-8000-000000000001")
                    .unwrap(),
                issuer_id: station.clone(),
                account_id: arkret_wire::AccountId::new(
                    DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                    station.clone(),
                ),
                device_id: Some(device_id.clone()),
                audience_id: station,
                scopes: vec!["ak.self.committed_event.read.scan.v1".to_owned()],
                not_before: crate::wire::now() - Duration::seconds(1),
                expires_at: crate::wire::now() + Duration::minutes(5),
                session_id: "fixture-session-1".to_owned(),
                cnf_jkt: session_public_key.thumbprint_sha256().unwrap(),
                session_public_key,
                credential_class: arkret_models_identity::SessionGrantCredentialClass::Standard,
                holder_binding: SessionGrantHolderBinding::HumanDevice {
                    device_binding: device_id.to_string(),
                },
                device_binding: Some(arkret_models_identity::SessionGrantDeviceBinding {
                    device_id,
                    authorization_event_id: arkret_identifiers::EventId::from_digest(
                        arkret_canonical::DigestSuite::Sha256,
                        [0x42; 32],
                    ),
                    model_generation_ref: 1,
                }),
                proof_kind: None,
                scope_details: None,
            },
            revoked_at: None,
            revocation_ref: "fixture-revocation-1".to_owned(),
        }
    }

    pub(crate) fn test_agent_metadata(
        scopes: &[&str],
    ) -> arkret_models_identity::SessionGrantMetadata {
        let mut metadata = test_introspection_grant().metadata;
        metadata.device_id = None;
        metadata.device_binding = None;
        metadata.account_id.principal_id = DidCoreId::new("ak:did_core:web:agent.example").unwrap();
        metadata.scopes = scopes.iter().map(|value| (*value).to_owned()).collect();
        metadata.scopes.sort();
        metadata.scopes.dedup();
        metadata.holder_binding = SessionGrantHolderBinding::AgentRuntime {
            agent_id: metadata.account_id.principal_id.clone(),
            agent_key_authorization_ref: arkret_identifiers::EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [0x43; 32],
            ),
            verification_method: arkret_wire::DidUrl::new(
                "did:web:agent.example#runtime-1".to_owned(),
            )
            .unwrap(),
        };
        metadata.scope_details = Some(serde_json::from_value(serde_json::json!({
            "controller_principal_id":"ak:did_core:web:alice.example",
            "agent_key_authorization_ref": arkret_identifiers::EventId::from_digest(arkret_canonical::DigestSuite::Sha256,[0x43;32]),
            "realm_ids":[],"strand_ids":[],"resources":{"realm_ids":[],"strand_ids":[]},
            "constraints":{"allowed_tracks":["discussion"],"allowed_data_labels":[],"allowed_endpoints":[]},
            "capability_grant_refs":[],"policy_refs":[]
        })).unwrap());
        metadata
    }

    #[test]
    fn device_session_binding_rejects_metadata_mismatch() {
        let mut grant = test_introspection_grant();
        grant.metadata.device_id =
            Some(DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000002").unwrap());

        let err = session_binding_from_introspection(&grant).unwrap_err();

        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
        assert_eq!(err.1, "unauthenticated");
        assert_eq!(
            err.2,
            "session grant introspection authorization metadata is incomplete"
        );
    }

    #[tokio::test]
    async fn session_retains_signed_account_and_never_fills_a_missing_station() {
        let mut config = crate::config::AppConfig::test_default();
        config.seed_demo_data = false;
        let state = AppState::new(config, coland_storage_postgres::Db { pool: None });
        let mut grant = test_introspection_grant();
        grant.metadata.account_id.station_id =
            DidCoreId::new("ak:did_core:web:origin.example").unwrap();
        assert!(session_binding_from_introspection(&grant).is_err());
        grant.metadata.audience_id = grant.account_id.station_id.clone();
        let expected = grant.account_id.clone();
        let endpoint = session_binding_from_introspection(&grant).unwrap();
        let mut session = session_from_verified_grant(&state, "test-grant", grant, endpoint);
        // This is a foreign credential snapshot, not authentication at this
        // ambient Station; its audience remains bound to its signed authority.
        session.audience = expected.station_id.to_string();
        assert_eq!(
            authenticated_session_account_id(&state, &session)
                .await
                .unwrap(),
            expected
        );
        session.actor = "ak:did_core:web:other.example".to_owned();
        assert!(
            authenticated_session_account_id(&state, &session)
                .await
                .is_err()
        );
        session.actor = expected.principal_id.to_string();
        session.session_grant = None;
        assert!(
            authenticated_session_account_id(&state, &session)
                .await
                .is_err()
        );
    }

    #[test]
    fn agent_holder_binding_materializes_closed_authorization_context() {
        let mut grant = test_introspection_grant();
        grant.metadata = test_agent_metadata(&["ak.self.committed_event.read.scan.v1"]);
        grant.validate().unwrap();
        let SessionEndpointState::AgentRuntime {
            state: agent_session,
        } = session_binding_from_introspection(&grant).unwrap()
        else {
            panic!("Agent grant must produce an Agent endpoint");
        };
        assert_eq!(agent_session.metadata, grant.metadata);
        assert_eq!(agent_session.freshness_state, FreshnessState::Fresh);
        let mut incomplete = serde_json::to_value(&grant).unwrap();
        incomplete["scope_details"]
            .as_object_mut()
            .unwrap()
            .remove("resources");
        assert!(
            serde_json::from_value::<SessionGrantValidationMetadata>(incomplete).is_err(),
            "missing resources cannot become an unrestricted Agent session"
        );
    }
}
