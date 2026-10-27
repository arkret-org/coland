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
    SessionGrantValidationMetadata,
};

/// Device-scope prefix carried in a `ak.session.grant`'s scope set
/// (`urn:arkret:client:device:<device_id>`). A grant that drives
/// `/_arkret/self/*` MUST carry one so the request is device-bound.
/// TTL for the session-grant introspection cache (api-conventions.md §3.3 D2:
/// SHOULD ≤ 120s). The revocation-visibility upper bound equals this TTL;
/// sensitive operations bypass the cache entirely (`force_fresh`).
const INTROSPECTION_CACHE_TTL: StdDuration = StdDuration::from_secs(120);
const INTROSPECTION_CACHE_MAX_ENTRIES: usize = 4096;

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
    state
        .local_account_authority()
        .map(|authority| authority.cache_namespace().to_owned())
        .unwrap_or_else(|| "unconfigured-local-issuer".to_owned())
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

    let grant = introspect_session_grant_authority(state, grant_jwt).await?;
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
async fn introspect_session_grant_authority(
    state: &AppState,
    grant_jwt: &str,
) -> Result<SessionGrantValidationMetadata, AuthError> {
    let authority = state.local_account_authority().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
        "local Account Authority is unavailable",
    ))?;
    let request = SessionGrantValidationInput::ByJwt(SessionGrantValidationByJwt {
        grant_jwt: grant_jwt.to_owned(),
        audience_id: Some(configured_service_audience(state)?),
        proof: None,
    });
    let outcome = authority
        .validate_session_grant(request)
        .await
        .map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "local Account Authority returned no authoritative outcome",
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
                    "scope_details": grant.scope_details,
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
    grant_jwt: &str,
) -> Result<NativeReplyAuthenticatedSession, AuthError> {
    // The standard RFC 9421 request hoop must already have verified the request.
    // This takes (or reuses) the same strict request memo for DPoP and downstream
    // actor/ceiling checks, rather than independently parsing a JWT locally.
    take_request_authoritative_grant(state, req, grant_jwt, true).await?;
    let session = grant_dpop_session(state, req, grant_jwt, true).await?;
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

    use super::*;
    use crate::wire::SessionGrantValidationResponseBody;

    struct CountingAuthority {
        station_id: DidCoreId,
        namespace: String,
        outcome: SessionGrantValidationResponseBody,
        count: Arc<AtomicUsize>,
    }

    impl coland_contracts::account_authority::LocalAccountAuthority for CountingAuthority {
        fn stage_device_pairing(
            &self,
            _: arkret_models_collaboration::device_pairing::DevicePairingStageRequestBody,
            _: String,
        ) -> coland_contracts::account_authority::AccountAuthorityCall<
            '_,
            arkret_models_collaboration::device_pairing::DevicePairingStageResponseBody,
            coland_contracts::account_authority::AccountAuthorityPairingError,
        > {
            Box::pin(async {
                Err(coland_contracts::account_authority::AccountAuthorityPairingError::Unavailable)
            })
        }
        fn resolve_device_pairing(
            &self,
            _: arkret_models_collaboration::device_pairing::DevicePairingResolveRequestBody,
        ) -> coland_contracts::account_authority::AccountAuthorityCall<
            '_,
            arkret_models_collaboration::device_pairing::DevicePairingBootstrap,
            coland_contracts::account_authority::AccountAuthorityPairingError,
        > {
            Box::pin(async {
                Err(coland_contracts::account_authority::AccountAuthorityPairingError::Unavailable)
            })
        }
        fn device_pairing_status(
            &self,
            _: arkret_models_collaboration::device_pairing::DevicePairingStatusRequestBody,
        ) -> coland_contracts::account_authority::AccountAuthorityCall<
            '_,
            arkret_models_collaboration::device_pairing::DevicePairingStatusResponseBody,
            coland_contracts::account_authority::AccountAuthorityPairingError,
        > {
            Box::pin(async {
                Err(coland_contracts::account_authority::AccountAuthorityPairingError::Unavailable)
            })
        }

        fn station_id(&self) -> &DidCoreId {
            &self.station_id
        }
        fn cache_namespace(&self) -> &str {
            &self.namespace
        }
        fn validate_session_grant(
            &self,
            _: SessionGrantValidationInput,
        ) -> coland_contracts::account_authority::AccountAuthorityCall<
            '_,
            SessionGrantValidationResponseBody,
        > {
            Box::pin(async move {
                self.count.fetch_add(1, Ordering::SeqCst);
                Ok(self.outcome.clone())
            })
        }
        fn terminate_authentication_session(&self, _: arkret_models_collaboration::session_grants::AuthenticationSessionTerminationInput)
        -> coland_contracts::account_authority::AccountAuthorityCall<'_, arkret_models_collaboration::session_grants::AuthenticationSessionTerminationResponseBody>{
            Box::pin(async {
                Err(coland_contracts::account_authority::AccountAuthorityUnavailable)
            })
        }
        fn issue_controller_gate(&self, _: arkret_models_identity::agent_signer_evidence::ControllerAccountGateIssuanceInput)
        -> coland_contracts::account_authority::AccountAuthorityCall<'_, arkret_models_identity::agent_signer_evidence::ControllerAccountGateAttestationIssueResponseBody>{
            Box::pin(async {
                Err(coland_contracts::account_authority::AccountAuthorityUnavailable)
            })
        }
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

    #[tokio::test]
    async fn missing_issuer_capability_is_unavailable_without_invalidating_the_grant() {
        let mut config = crate::config::AppConfig::test_default();
        config.seed_demo_data = false;
        let state = AppState::new(config, coland_storage_postgres::Db { pool: None });
        let error =
            request_authoritative_grant(&state, &Request::default(), "unavailable-grant", true)
                .await
                .unwrap_err();
        assert_eq!(error.0, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(error.1, "temporarily_unavailable");
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
    async fn request_memo_cache_and_force_fresh_count_authority_calls() {
        let grant = test_introspection_grant();
        let outcome = SessionGrantValidationResponseBody {
            active: true,
            status: SessionGrantAdminIntrospectionStatus::Active,
            proof_required: false,
            one_time_use_consumed: false,
            grant: Some(grant),
        };
        let count = Arc::new(AtomicUsize::new(0));
        let mut config = crate::config::AppConfig::test_default();
        config.seed_demo_data = false;
        let state = AppState::new(config, coland_storage_postgres::Db { pool: None });
        let namespace = uuid::Uuid::now_v7().to_string();
        let authority = Arc::new(CountingAuthority {
            station_id: state.service_core_id(),
            namespace: namespace.clone(),
            outcome,
            count: count.clone(),
        });
        let state = state.with_local_account_authority(authority).unwrap();
        let token = format!("counting-grant-{namespace}");
        let key = introspection_cache_key_for(&state, &token);
        INTROSPECTION_CACHE.lock().remove(&key);

        let mut request = Request::default();
        take_request_authoritative_grant(&state, &mut request, &token, false)
            .await
            .expect("first consumer introspects");
        request_authoritative_grant(&state, &request, &token, false)
            .await
            .expect("second consumer reuses request memo");
        assert_eq!(
            count.load(Ordering::SeqCst),
            1,
            "two consumers use one authority call"
        );

        let mut warm_request = Request::default();
        take_request_authoritative_grant(&state, &mut warm_request, &token, false)
            .await
            .expect("warm cache serves low-sensitivity request");
        assert_eq!(
            count.load(Ordering::SeqCst),
            1,
            "warm cache adds no authority call"
        );

        take_request_authoritative_grant(&state, &mut warm_request, &token, true)
            .await
            .expect("force-fresh consumer bypasses cached memo");
        request_authoritative_grant(&state, &warm_request, &token, true)
            .await
            .expect("later force-fresh consumer reuses fresh memo");
        assert_eq!(
            count.load(Ordering::SeqCst),
            2,
            "force-fresh adds exactly one authority call"
        );

        INTROSPECTION_CACHE.lock().remove(&key);
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

    fn test_introspection_grant() -> SessionGrantValidationMetadata {
        SessionGrantValidationMetadata {
            scope_details: None,
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
            "session grant introspection authorization metadata is incomplete"
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
        // Wire-valid Agent grants omit human device metadata and retain the
        // immutable issuer scope alongside their typed holder binding.
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
        grant.scope_details = Some(
            serde_json::json!({
                "controller_principal_id": "ak:did_core:web:alice.example",
                "agent_key_authorization_ref": "ak:event:AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "realm_ids": [],
                "strand_ids": [],
                "resources": {"realm_ids": [], "strand_ids": []},
                "constraints": {
                    "allowed_tracks": ["discussion"], "allowed_data_labels": [], "allowed_endpoints": []
                },
                "capability_grant_refs": [],
                "policy_refs": []
            })
            .as_object()
            .unwrap()
            .clone(),
        );
        grant.validate().unwrap();

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
            agent_session.scope_details["scope_details"],
            serde_json::to_value(grant.scope_details.as_ref().unwrap()).unwrap()
        );
        assert_eq!(
            agent_session.scope_details["session_grant_revocation_ref"],
            "ak:session:grant-1"
        );
        grant.scope_details.as_mut().unwrap().remove("resources");
        assert!(
            session_binding_from_introspection(&grant).is_err(),
            "missing resource metadata cannot become an unrestricted Agent session"
        );
    }
}
