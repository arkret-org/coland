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
//! returned metadata is the authority. This Station MUST NOT verify the grant
//! JWT's signature locally, replay the issuer DID history, or recompute the
//! issuance preimage / suite-tagged id / `jti` as a basis for admission — and
//! it does none of those.
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
use std::sync::LazyLock;
use std::time::{Duration as StdDuration, Instant};

use arkret_identifiers::{DeviceId, DidCoreId};
use arkret_models_collaboration::session_grants::SessionGrantValidationByJwt;
use arkret_models_identity::session_credential::SessionGrantHolderBinding;
use arkret_wire::FreshnessState;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration, Utc};
use coland_services::identity::{
    AgentSessionState as AgentSessionRecord, SessionEndpointState, SessionGrantAuthorizationState,
    SessionIdentityState as SessionRecord,
};
use parking_lot::Mutex;
use salvo::http::StatusCode;
use salvo::prelude::Request;
use sha2::{Digest, Sha256};

use crate::state::AppState;
use crate::wire::{
    SessionGrantAdminIntrospectionStatus, SessionGrantValidationInput,
    SessionGrantValidationMetadata, SessionGrantValidationOutcome,
};

/// Device-scope prefix carried in a `ak.session.grant`'s scope set
/// (`urn:arkret:client:device:<device_id>`). A grant that drives
/// `/_arkret/self/*` MUST carry one so the request is device-bound.
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

/// Process-local introspection cache. Same in-memory trade-off as the other
/// coland reducer projections (`handle_releases`, `account_lifecycle`): a
/// restart drops the cache and the next request re-introspects. Keyed by a
/// service-DID-bound hash of the presented grant so cross-audience grants never
/// collide.
static INTROSPECTION_CACHE: LazyLock<Mutex<HashMap<String, CachedIntrospection>>> =
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
fn introspection_cache_key(grant_jwt: &str, audience: &str, authority_context: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(audience.as_bytes());
    hasher.update(b":");
    hasher.update(authority_context.as_bytes());
    hasher.update(b":");
    hasher.update(grant_jwt.as_bytes());
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
        "url={}\nprivate_networks={}",
        state
            .config()
            .session_grant_introspection_url
            .as_deref()
            .unwrap_or_default(),
        crate::security::private_networks_allowed(state.config().development_mode),
    )
}

fn introspection_cache_key_for(state: &AppState, grant_jwt: &str) -> String {
    introspection_cache_key(
        grant_jwt,
        state.service_id(),
        &introspection_authority_context(state),
    )
}

fn cache_lookup(key: &str) -> Option<SessionGrantValidationMetadata> {
    cache_lookup_at(key, Instant::now())
}

fn cache_lookup_at(key: &str, now: Instant) -> Option<SessionGrantValidationMetadata> {
    let mut cache = INTROSPECTION_CACHE.lock();
    prune_introspection_cache_locked(&mut cache, now);
    match cache.get(key) {
        Some(entry) if now.duration_since(entry.inserted_at) < INTROSPECTION_CACHE_TTL => {
            Some(entry.grant.clone())
        }
        Some(_) => {
            cache.remove(key);
            None
        }
        None => None,
    }
}

fn cache_store(key: String, grant: SessionGrantValidationMetadata) {
    {
        let mut cache = INTROSPECTION_CACHE.lock();
        prune_introspection_cache_locked(&mut cache, Instant::now());
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
            key,
            CachedIntrospection {
                grant,
                inserted_at: Instant::now(),
            },
        );
    }
}

fn prune_introspection_cache_locked(
    cache: &mut HashMap<String, CachedIntrospection>,
    now: Instant,
) {
    cache.retain(|_, entry| now.duration_since(entry.inserted_at) < INTROSPECTION_CACHE_TTL);
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

/// Drop any cached introspection entry for `grant_jwt`. Called by logout so the
/// next introspection of that grant goes to coauth and observes `active=false`
/// (account-lifecycle.md §4.1 step 3 — the local-side invalidation).
pub(crate) fn invalidate_cached_grant(state: &AppState, grant_jwt: &str) {
    let key = introspection_cache_key_for(state, grant_jwt);
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
    grant_jwt: &str,
    force_fresh: bool,
) -> Result<SessionGrantValidationMetadata, AuthError> {
    let key = introspection_cache_key_for(state, grant_jwt);
    if !force_fresh && let Some(grant) = cache_lookup(&key) {
        // Cached grants can still expire between introspection and use.
        if grant.expires_at <= crate::wire::now() {
            return Err((
                StatusCode::UNAUTHORIZED,
                "auth_expired",
                "session grant has expired",
            ));
        }
        return Ok(grant);
    }

    let grant = introspect_session_grant_remote(state, grant_jwt).await?;
    cache_store(key, grant.clone());
    Ok(grant)
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
    grant_jwt: String,
    /// Whether the result was taken with the cache bypassed. A memo taken
    /// fresh also satisfies a later consumer that only needs the cached
    /// freshness; the reverse is not true and re-introspects.
    taken_fresh: bool,
    grant: SessionGrantValidationMetadata,
}

/// Record this request's single authoritative result. Called from the one place
/// that holds `&mut Request` before any handler runs (the RFC 9421 PoP hoop).
pub(crate) async fn take_request_authoritative_grant(
    state: &AppState,
    req: &mut Request,
    grant_jwt: &str,
    force_fresh: bool,
) -> Result<SessionGrantValidationMetadata, AuthError> {
    if let Some(grant) = memoized_grant(req, grant_jwt, force_fresh) {
        return Ok(grant);
    }
    let grant = introspect_session_grant_cached(state, grant_jwt, force_fresh).await?;
    req.extensions_mut().insert(RequestAuthoritativeGrant {
        grant_jwt: grant_jwt.to_owned(),
        taken_fresh: force_fresh,
        grant: grant.clone(),
    });
    Ok(grant)
}

/// Reuse this request's authoritative result when one was already taken at a
/// freshness at least as strict as the caller needs; otherwise introspect.
async fn request_authoritative_grant(
    state: &AppState,
    req: &Request,
    grant_jwt: &str,
    force_fresh: bool,
) -> Result<SessionGrantValidationMetadata, AuthError> {
    if let Some(grant) = memoized_grant(req, grant_jwt, force_fresh) {
        return Ok(grant);
    }
    introspect_session_grant_cached(state, grant_jwt, force_fresh).await
}

fn memoized_grant(
    req: &Request,
    grant_jwt: &str,
    force_fresh: bool,
) -> Option<SessionGrantValidationMetadata> {
    let memo = req.extensions().get::<RequestAuthoritativeGrant>()?;
    // The memo belongs to the exact token it was taken for. A request that
    // somehow presents a different credential gets its own authoritative read.
    if memo.grant_jwt != grant_jwt || (force_fresh && !memo.taken_fresh) {
        return None;
    }
    Some(memo.grant.clone())
}

/// Raw coauth introspection (no cache). Reads `cnf_jkt`, `session_public_key`,
/// scopes, subject, device_id and expiry off the introspection response.
async fn introspect_session_grant_remote(
    state: &AppState,
    grant_jwt: &str,
) -> Result<SessionGrantValidationMetadata, AuthError> {
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
    let request = SessionGrantValidationInput::ByJwt(SessionGrantValidationByJwt {
        grant_jwt: grant_jwt.to_owned(),
        audience_id: Some(configured_service_audience(state)?),
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
        .json::<SessionGrantValidationOutcome>()
        .await
        .map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "session grant introspection response was invalid",
            )
        })?;
    if !outcome.active || outcome.status != SessionGrantAdminIntrospectionStatus::Active {
        return Err(unauthenticated("session grant is not active"));
    }
    outcome.grant.ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
        "session grant introspection omitted grant metadata",
    ))
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
    let authority = grant.account_id();
    if authority.station_id != grant.audience_id {
        return Err(unauthenticated(
            "session grant authority context does not match its subject/audience",
        ));
    }
    if let SessionGrantHolderBinding::AgentRuntime {
        agent_id,
        agent_key_authorization_ref,
        verification_method,
    } = &grant.holder_binding
    {
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
                granted_scope: grant.scopes.clone(),
                scope_details: serde_json::json!({
                    "session_grant_id": grant.id,
                    "session_grant_revocation_ref": grant.revocation_ref,
                    "agent_key_authorization_ref": agent_key_authorization_ref,
                    "verification_method": verification_method,
                }),
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
    grant_jwt: &str,
    grant: &SessionGrantValidationMetadata,
) -> Result<SessionRecord, AuthError> {
    if grant.audience_id.as_str() != state.service_id() {
        return Err(unauthenticated(
            "session grant audience does not match this Station",
        ));
    }
    let endpoint = session_binding_from_introspection(grant)?;
    let token_hash =
        crate::routing::identity::auth::session_credential_hash(grant_jwt, state.service_id());
    Ok(SessionRecord {
        token_hash,
        account_pk: None,
        actor: grant.account_id.principal_id.to_string(),
        endpoint,
        audience: state.service_id().clone(),
        session_public_key: Some(grant.session_public_key.as_str().to_owned()),
        session_grant: Some(SessionGrantAuthorizationState {
            grant_id: grant.id.clone(),
            revocation_ref: grant.revocation_ref.clone(),
            account_id: grant.account_id.clone(),
            issuer_id: grant.issuer_id.clone(),
            scopes: grant.scopes.clone(),
            credential_class: grant.credential_class,
            holder_binding: grant.holder_binding.clone(),
            device_binding: grant.device_binding.clone(),
            cnf_jkt: grant.cnf_jkt.clone(),
        }),
        expires_at: grant.expires_at,
        created_at: crate::wire::now(),
        revoked_at: None,
    })
}

pub(crate) fn verify_grant_dpop_request(
    state: &AppState,
    req: &Request,
    grant_jwt: &str,
    cnf_jkt: Option<&str>,
) -> Result<(), AuthError> {
    verify_grant_dpop_request_at_base(req, grant_jwt, cnf_jkt, &state.config().public_base_url)
}

pub(crate) fn verify_grant_dpop_request_at_base(
    req: &Request,
    grant_jwt: &str,
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
            access_token: Some(grant_jwt),
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
    grant_jwt: &str,
    force_fresh: bool,
) -> Result<SessionRecord, AuthError> {
    // 1. grant active (cached ≤120s; sensitive ops force fresh). Reads cnf_jkt, session_public_key,
    //    scopes, subject, device_id, expiry.
    //
    //    This is the request's single authoritative result: when the RFC 9421
    //    PoP hoop already took one for this request at this freshness or
    //    stricter, that exact result is reused instead of introspecting again.
    let grant = request_authoritative_grant(state, req, grant_jwt, force_fresh).await?;

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
    verify_grant_dpop_request(state, req, grant_jwt, Some(&grant.cnf_jkt))?;

    Ok(session_from_verified_grant(
        state, grant_jwt, grant, endpoint,
    ))
}

/// Synthesize the request- or connection-scoped `SessionRecord` from an
/// already-verified grant. Not persisted as a local bearer.
///
/// `token_hash` carries a stable, grant-derived value so downstream code that
/// keys on it (e.g. self-path session-revoke of the calling session) resolves
/// to this grant.
pub(crate) fn session_from_verified_grant(
    state: &AppState,
    grant_jwt: &str,
    grant: SessionGrantValidationMetadata,
    endpoint: SessionEndpointState,
) -> SessionRecord {
    let grant_context = SessionGrantAuthorizationState {
        grant_id: grant.id.clone(),
        revocation_ref: grant.revocation_ref.clone(),
        account_id: grant.account_id.clone(),
        issuer_id: grant.issuer_id.clone(),
        scopes: grant.scopes.clone(),
        credential_class: grant.credential_class,
        holder_binding: grant.holder_binding.clone(),
        device_binding: grant.device_binding.clone(),
        cnf_jkt: grant.cnf_jkt.clone(),
    };
    SessionRecord {
        token_hash: crate::routing::identity::auth::session_credential_hash(
            grant_jwt,
            state.service_id(),
        ),
        account_pk: None,
        actor: grant.account_id.principal_id.to_string(),
        endpoint,
        audience: state.service_id().clone(),
        session_public_key: Some(grant.session_public_key.into_string()),
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
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use arkret_identifiers::SessionGrantId;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    async fn read_mock_http_request(stream: &mut tokio::net::TcpStream) {
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
                return;
            }
        }
    }

    async fn spawn_counting_introspection_mock(
        outcome: SessionGrantValidationOutcome,
    ) -> (String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind introspection mock");
        let address = listener.local_addr().expect("mock address");
        let count = Arc::new(AtomicUsize::new(0));
        let observed = count.clone();
        let body = Arc::new(serde_json::to_vec(&outcome).expect("serialize mock outcome"));
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                read_mock_http_request(&mut stream).await;
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
        (format!("http://{address}/introspect"), count, task)
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
        let grant = test_introspection_grant();
        let mut cached = Request::default();
        cached.extensions_mut().insert(RequestAuthoritativeGrant {
            grant_jwt: "token-a".to_owned(),
            taken_fresh: false,
            grant: grant.clone(),
        });
        assert!(memoized_grant(&cached, "token-a", false).is_some());
        assert!(
            memoized_grant(&cached, "token-a", true).is_none(),
            "a cached result must not be reused for a force-fresh consumer",
        );
        assert!(memoized_grant(&cached, "token-b", false).is_none());

        let mut fresh = Request::default();
        fresh.extensions_mut().insert(RequestAuthoritativeGrant {
            grant_jwt: "token-a".to_owned(),
            taken_fresh: true,
            grant,
        });
        assert!(memoized_grant(&fresh, "token-a", true).is_some());
        assert!(memoized_grant(&fresh, "token-a", false).is_some());
        assert!(memoized_grant(&fresh, "token-b", true).is_none());
        assert!(memoized_grant(&Request::default(), "token-a", false).is_none());
    }

    #[tokio::test]
    async fn request_memo_cache_and_force_fresh_count_real_http_round_trips() {
        let grant = test_introspection_grant();
        let outcome = SessionGrantValidationOutcome {
            active: true,
            status: SessionGrantAdminIntrospectionStatus::Active,
            proof_required: false,
            one_time_use_consumed: false,
            grant: Some(grant),
        };
        let (url, count, mock) = spawn_counting_introspection_mock(outcome).await;
        let mut config = crate::config::AppConfig::test_default();
        config.development_mode = true;
        config.seed_demo_data = false;
        config.session_grant_introspection_url = Some(url.clone());
        config.account_authority_url = Some(url.trim_end_matches("/introspect").to_owned());
        config.register_test_internal_authority_channel("counting-mock-secret");
        let state = AppState::new(config, coland_storage_postgres::Db { pool: None });
        let token = format!("counting-grant-{}", url.rsplit(':').next().unwrap());
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

    #[test]
    fn self_introspection_cache_expires_at_exact_120_second_boundary() {
        let key = "controlled-self-ttl";
        let inserted_at = Instant::now();
        INTROSPECTION_CACHE.lock().insert(
            key.to_owned(),
            CachedIntrospection {
                grant: test_introspection_grant(),
                inserted_at,
            },
        );
        assert!(
            cache_lookup_at(
                key,
                inserted_at + INTROSPECTION_CACHE_TTL - StdDuration::from_nanos(1)
            )
            .is_some()
        );
        assert!(cache_lookup_at(key, inserted_at + INTROSPECTION_CACHE_TTL).is_none());
        INTROSPECTION_CACHE.lock().remove(key);
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

    fn test_introspection_grant() -> SessionGrantValidationMetadata {
        SessionGrantValidationMetadata {
            id: SessionGrantId::new(
                "ak:session_grant:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
            )
            .unwrap(),
            issuer_id: DidCoreId::new("ak:did_core:web:coauth.local").unwrap(),
            account_id: arkret_wire::AccountId::new(
                DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                crate::test_event::station_id(),
            ),
            device_id: Some(
                DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000001").unwrap(),
            ),
            device_binding: Some(
                arkret_models_identity::session_credential::SessionGrantDeviceBinding {
                    device_id: DeviceId::new(
                        "ak:device:0196419b-0000-7000-8000-000000000001",
                    )
                    .unwrap(),
                    authorization_event_id: arkret_identifiers::EventId::from_digest(
                        arkret_canonical::DigestSuite::Sha256,
                        [0x42; 32],
                    ),
                    model_generation_ref: 1,
                },
            ),
            audience_id: arkret_wire::project_did_to_core_id(
                    &arkret_wire::Did::new("did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:coland.local:webvh:service").unwrap(),
                )
                .unwrap(),
            scopes: vec!["ak.self.committed_event.read.scan.v1".to_owned()],
            expires_at: crate::wire::now() + Duration::minutes(5),
            revoked_at: None,
            revocation_ref: "ak:session:grant-1".to_owned(),
            session_public_key:
                arkret_models_identity::session_credential::CanonicalSessionPublicJwk::new(
                    r#"{"crv":"Ed25519","kty":"OKP","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
                )
                .unwrap(),
            cnf_jkt: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            credential_class:
                arkret_models_identity::session_credential::SessionGrantCredentialClass::Standard,
            holder_binding: SessionGrantHolderBinding::HumanDevice {
                device_binding: "ak:device:0196419b-0000-7000-8000-000000000001".to_owned(),
            },
        }
    }

    #[test]
    fn device_session_binding_rejects_metadata_mismatch() {
        let mut grant = test_introspection_grant();
        grant.device_id =
            Some(DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000002").unwrap());

        let err = session_binding_from_introspection(&grant).unwrap_err();

        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
        assert_eq!(err.1, "unauthenticated");
        assert_eq!(
            err.2,
            "session grant device metadata does not match its holder binding"
        );
    }

    #[tokio::test]
    async fn session_retains_signed_account_and_never_fills_a_missing_station() {
        let mut config = crate::config::AppConfig::test_default();
        config.seed_demo_data = false;
        let state = AppState::new(config, coland_storage_postgres::Db { pool: None });
        let mut grant = test_introspection_grant();
        grant.account_id.station_id = DidCoreId::new("ak:did_core:web:origin.example").unwrap();
        assert!(session_binding_from_introspection(&grant).is_err());
        grant.audience_id = grant.account_id.station_id.clone();
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
        // Wire-valid agent grants carry no top-level human device metadata;
        // the typed holder binding is self-contained.
        grant.device_id = None;
        grant.device_binding = None;
        grant.account_id = arkret_wire::AccountId::new(
            DidCoreId::new("ak:did_core:web:agent.example").unwrap(),
            grant.audience_id.clone(),
        );
        grant.scopes = vec!["ak.self.committed_event.read.scan.v1".to_owned()];
        grant.holder_binding = SessionGrantHolderBinding::AgentRuntime {
            agent_id: DidCoreId::new("ak:did_core:web:agent.example").unwrap(),
            agent_key_authorization_ref: arkret_identifiers::EventId::new(
                "ak:event:AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            )
            .unwrap(),
            verification_method: arkret_wire::DidUrl::new(
                "did:web:agent.example#runtime-1".to_owned(),
            )
            .unwrap(),
        };

        let SessionEndpointState::AgentRuntime {
            state: agent_session,
        } = session_binding_from_introspection(&grant).unwrap()
        else {
            panic!("Agent grant must produce an Agent endpoint");
        };
        assert_eq!(
            agent_session.granted_scope,
            vec!["ak.self.committed_event.read.scan.v1"]
        );
        assert_eq!(agent_session.freshness_state, FreshnessState::Fresh);
        assert_eq!(
            agent_session.scope_details["session_grant_revocation_ref"],
            "ak:session:grant-1"
        );
    }
}
