//! Simple in-memory rate limiter middleware.
//!
//! Spec: A.3 — buckets are keyed on `(remote_addr, endpoint_class)` rather
//! than the raw remote address so a single abusive endpoint cannot starve
//! a peer's quota across the rest of the API surface. We recognize four
//! endpoint classes:
//!
//! - `probe`  — the public capability probe (`/_arkret/describe`). Every client MUST fetch this
//!   *before* it can authenticate, so it gets its own generous bucket and never shares the
//!   authenticated `api` quota: a hot authenticated surface (e.g. a sync long-poll loop) must not
//!   be able to starve the one probe a client needs just to begin signing in.
//! - `auth`   — the credential/bearer-issuing surface (strict, low ceiling): the spec-canonical
//!   `/_arkret/gate/account/register`, `/_arkret/gate/account/session-grants`, and
//!   `/_arkret/gate/account/agent-key-pair`, plus the `/_coland/gate/auth/*` auth routes. Must be
//!   hardened against credential-stuffing.
//! - `api`    — every other `/_arkret/*` request (moderate ceiling).
//! - `other`  — anything outside `/_arkret/*` (default ceiling).
//!
//! Each class carries its own quota; the `describe` wire surface advertises the
//! SAME per-class ceilings via [`RateLimiterConfig::advertised_policy`], so a
//! conformant client that budgets against the advertised policy can never trip
//! a 429 it could not predict. Advertised quota and enforced quota MUST agree.
//!
//! Ceilings come from [`RateLimiterConfig::from_env`]: production keeps the
//! strict per-class defaults; `development_mode` lifts every ceiling far above
//! a human dev's click rate (on localhost every local client shares the single
//! loopback bucket, so prod ceilings would otherwise trip 429 during dx
//! hot-reload + repeated connect bootstraps and block sign-in). The limiter
//! stays installed in both modes. Operators can tune any class with the
//! `COLAND_RATE_LIMIT_{DEFAULT,AUTH,API,PROBE}_PER_MINUTE` and
//! `COLAND_RATE_LIMIT_WINDOW_SECONDS` env vars.
//!
//! Reverse-proxy deployments can opt into sanitized `X-Forwarded-For`
//! client extraction with `COLAND_RATE_LIMIT_TRUST_X_FORWARDED_FOR=1`.
//! Directly exposed deployments keep the default fail-closed behaviour and
//! bucket on the TCP peer address.

use std::sync::Arc;
use std::time::Duration;

use arkret_rate_limit::{FixedWindowConfig, MemoryFixedWindowRateLimiter};
use salvo::prelude::*;

/// Canonical paths whose [`EndpointClass`] is pinned. Shared by
/// [`EndpointClass::classify`] (enforcement) and
/// [`RateLimiterConfig::advertised_policy`] (the `describe` wire surface) so the
/// advertised policy can never drift from what is actually enforced.
const DESCRIBE_PROBE_PATH: &str = "/_arkret/describe";
const AUTH_REGISTER_PATH: &str = "/_arkret/gate/account/register";
const AUTH_SESSION_GRANTS_PATH: &str = "/_arkret/gate/account/session-grants";
const AUTH_AGENT_KEY_PAIR_PATH: &str = "/_arkret/gate/account/agent-key-pair";
const COLAND_AUTH_PREFIX: &str = "/_coland/gate/auth/";
const ARKRET_PREFIX: &str = "/_arkret/";

/// Rate limiter configuration.
#[derive(Clone, Debug)]
pub struct RateLimiterConfig {
    /// Maximum requests per window per key. Used as the fallback for any
    /// endpoint class that does not have a class-specific override.
    pub max_requests: u32,
    /// Window duration.
    pub window: Duration,
    /// Strict ceiling for the credential/bearer-issuing endpoints (see the
    /// `Auth` class in [`EndpointClass::classify`]); defaults to a low value
    /// to harden against credential-stuffing.
    pub auth_max_requests: u32,
    /// Moderate ceiling for the rest of `/_arkret/*`.
    pub api_max_requests: u32,
    /// Generous ceiling for the public capability probe (`/_arkret/describe`).
    /// It is the unauthenticated bootstrap surface and lives in its own bucket,
    /// so a high limit here cannot be spent by authenticated traffic.
    pub probe_max_requests: u32,
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        Self {
            // `other` (non-`/_arkret/*`) ceiling.
            max_requests: 600,
            window: Duration::from_secs(60),
            // Strict for the credential endpoints: 60/min ≈ 1/sec. Enough
            // headroom for an OAuth refresh cycle, but tight enough to stall a
            // guessing loop.
            auth_max_requests: 60,
            // Moderate for the rest of /_arkret/*. Lower than `other` so a
            // single endpoint cannot burn the entire IP-wide budget on its own.
            api_max_requests: 300,
            // The bootstrap probe gets a full budget in its own bucket; clients
            // must succeed at it before they can authenticate at all.
            probe_max_requests: 600,
        }
    }
}

/// Per-class ceiling overrides, already resolved by the configuration loader.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RateLimitOverrides {
    pub window_seconds: Option<u32>,
    pub default_per_minute: Option<u32>,
    pub auth_per_minute: Option<u32>,
    pub api_per_minute: Option<u32>,
    pub probe_per_minute: Option<u32>,
}

impl RateLimiterConfig {
    /// Build the runtime config from the deployment posture +
    /// `COLAND_RATE_LIMIT_*` overrides.
    ///
    /// Production keeps the strict per-class ceilings ([`Self::default`]).
    /// `development_mode` lifts every ceiling far above any human dev's click
    /// rate so localhost loopback (where every local client shares the single
    /// `127.0.0.1` bucket) does not trip 429 during hot-reload / repeated
    /// connect bootstraps and block sign-in. The limiter stays installed in
    /// both modes (defense in depth + an honest `hardening.rate_limit_enabled`);
    /// only the ceilings move.
    pub fn resolve(development_mode: bool, overrides: RateLimitOverrides) -> Self {
        let base = if development_mode {
            Self::development()
        } else {
            Self::default()
        };
        base.with_overrides(overrides)
    }

    fn development() -> Self {
        // Far above any human's interactive request rate, but still bounded so
        // a runaway loop in a dev build is eventually caught.
        const DEV_CEILING: u32 = 100_000;
        Self {
            max_requests: DEV_CEILING,
            window: Duration::from_secs(60),
            auth_max_requests: DEV_CEILING,
            api_max_requests: DEV_CEILING,
            probe_max_requests: DEV_CEILING,
        }
    }

    fn with_overrides(mut self, overrides: RateLimitOverrides) -> Self {
        if let Some(seconds) = overrides.window_seconds {
            self.window = Duration::from_secs(u64::from(seconds.max(1)));
        }
        if let Some(value) = overrides.default_per_minute {
            self.max_requests = value;
        }
        if let Some(value) = overrides.auth_per_minute {
            self.auth_max_requests = value;
        }
        if let Some(value) = overrides.api_per_minute {
            self.api_max_requests = value;
        }
        if let Some(value) = overrides.probe_per_minute {
            self.probe_max_requests = value;
        }
        self
    }

    /// Ceiling for a request class under these ceilings.
    fn ceiling_for(&self, class: EndpointClass) -> u32 {
        match class {
            EndpointClass::Probe => self.probe_max_requests,
            EndpointClass::Auth => self.auth_max_requests,
            EndpointClass::Api => self.api_max_requests,
            EndpointClass::Other => self.max_requests,
        }
    }

    /// The advertised `rate_limit_policy` for the `describe` wire surface,
    /// derived from the SAME ceilings the middleware enforces. Entries are
    /// ordered most-specific-first, mirroring [`EndpointClass::classify`]; the
    /// scope is `ip` because the buckets are keyed on the remote address.
    pub fn advertised_policy(
        &self,
    ) -> arkret_models_discovery::service_description::RateLimitPolicy {
        let window_seconds = u32::try_from(self.window.as_secs())
            .unwrap_or(u32::MAX)
            .max(1);
        let entry = |endpoint: String, max_requests: u32| {
            arkret_models_discovery::service_description::RateLimitEntry {
                endpoint: Some(endpoint),
                // NOTE: `arkret_models_discovery::service_description::RateLimitScope` (crate root)
                // is the authz constraints enum; the describe entry needs the
                // service-description scope, which lives under `models`.
                rate_limit_scope: Some(arkret_models_discovery::RateLimitScope::Single(
                    "ip".to_owned(),
                )),
                window_seconds: Some(window_seconds),
                max_requests: Some(max_requests.max(1)),
                ..arkret_models_discovery::service_description::RateLimitEntry::default()
            }
        };
        arkret_models_discovery::service_description::RateLimitPolicy {
            policy_version: Some("1".to_owned()),
            entries: vec![
                entry(DESCRIBE_PROBE_PATH.to_owned(), self.probe_max_requests),
                entry(AUTH_REGISTER_PATH.to_owned(), self.auth_max_requests),
                entry(AUTH_SESSION_GRANTS_PATH.to_owned(), self.auth_max_requests),
                entry(AUTH_AGENT_KEY_PAIR_PATH.to_owned(), self.auth_max_requests),
                entry(format!("{COLAND_AUTH_PREFIX}*"), self.auth_max_requests),
                entry(format!("{ARKRET_PREFIX}*"), self.api_max_requests),
                entry("*".to_owned(), self.max_requests),
            ],
            ..arkret_models_discovery::service_description::RateLimitPolicy::default()
        }
    }
}

/// Endpoint class — derived from the request path. Each class participates
/// in a separate `(remote_addr, class)` bucket so a hot endpoint cannot
/// starve a peer's quota across the rest of the API surface.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum EndpointClass {
    Probe,
    Auth,
    Api,
    Other,
}

impl EndpointClass {
    fn classify(path: &str) -> Self {
        // The public capability probe gets its own bucket: it is the
        // unauthenticated bootstrap surface every client must reach before it
        // can sign in, so it must never share the authenticated `Api` quota.
        // Checked first because it is itself under `/_arkret/`.
        if path == DESCRIBE_PROBE_PATH {
            Self::Probe
        }
        // Credential/bearer-issuing endpoints get the strict `Auth` bucket so the
        // anti-credential-stuffing quota actually covers them. These do NOT live
        // under a single `/_arkret/gate/auth/` prefix: the spec-canonical
        // account registration, session-grant exchange, and agent-key-pair authorization sit under
        // `/_arkret/gate/account/*`, and the private auth surface lives under
        // `/_coland/gate/auth/*`. Match the real routes, not a dead prefix.
        else if path == AUTH_REGISTER_PATH
            || path == AUTH_SESSION_GRANTS_PATH
            || path == AUTH_AGENT_KEY_PAIR_PATH
            || path.starts_with(COLAND_AUTH_PREFIX)
        {
            Self::Auth
        } else if path.starts_with(ARKRET_PREFIX) {
            Self::Api
        } else {
            Self::Other
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Probe => "probe",
            Self::Auth => "auth",
            Self::Api => "api",
            Self::Other => "other",
        }
    }
}

/// Rate limiter state.
#[derive(Clone)]
pub struct RateLimiter {
    config: RateLimiterConfig,
    state: Arc<MemoryFixedWindowRateLimiter<String>>,
}

const RATE_LIMIT_MAX_ENTRIES: usize = 100_000;

impl RateLimiter {
    pub fn new(config: RateLimiterConfig) -> Self {
        Self {
            state: Arc::new(MemoryFixedWindowRateLimiter::new(FixedWindowConfig::new(
                u64::from(config.max_requests),
                config.window,
                RATE_LIMIT_MAX_ENTRIES,
            ))),
            config,
        }
    }

    /// Check if a request is allowed for the given key.
    /// Returns true if allowed, false if rate limited.
    pub fn check(&self, key: &str) -> bool {
        self.check_with_ceiling(key, self.config.max_requests)
            .is_ok()
    }

    fn check_with_ceiling(&self, key: &str, ceiling: u32) -> Result<(), Duration> {
        self.check_with_ceiling_window(key, ceiling, self.config.window)
    }

    /// Fixed-window check against an explicit ceiling **and** window. The
    /// rate-limiter middleware passes the live (hot-swappable) window/ceiling
    /// from `RuntimeSettings` here so quota changes take effect immediately;
    /// the shared counter map is unaffected by the source of the window.
    fn check_with_ceiling_window(
        &self,
        key: &str,
        ceiling: u32,
        window: Duration,
    ) -> Result<(), Duration> {
        self.state
            .check_with_config(
                key.to_owned(),
                FixedWindowConfig::new(u64::from(ceiling), window, RATE_LIMIT_MAX_ENTRIES),
            )
            .map_err(|rejection| rejection.retry_after)
    }
}

/// Rate limiter middleware for Salvo.
#[derive(Clone)]
pub struct RateLimiterMiddleware {
    limiter: RateLimiter,
    config_provider: Option<Arc<dyn Fn() -> RateLimiterConfig + Send + Sync>>,
}

impl RateLimiterMiddleware {
    pub fn new(limiter: RateLimiter) -> Self {
        Self {
            limiter,
            config_provider: None,
        }
    }

    pub fn with_config_provider(
        limiter: RateLimiter,
        config_provider: Arc<dyn Fn() -> RateLimiterConfig + Send + Sync>,
    ) -> Self {
        Self {
            limiter,
            config_provider: Some(config_provider),
        }
    }
}

fn forwarded_for_trusted() -> bool {
    TRUST_FORWARDED_FOR.get().copied().unwrap_or(false)
}

static TRUST_FORWARDED_FOR: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

/// Install whether `X-Forwarded-For` may be trusted for client attribution.
///
/// Read once by the configuration loader. The first call wins.
pub fn install_forwarded_for_trust(trusted: bool) {
    let _ = TRUST_FORWARDED_FOR.set(trusted);
}

/// The client address to attribute a request to, or `None` when
/// `X-Forwarded-For` is not trusted.
///
/// This is the only implementation. It takes the **rightmost parseable IP** in
/// the chain — the entry this deployment's own proxy appended. Leftmost
/// entries are supplied by the caller and are therefore forgeable, which
/// matters wherever the result is used as a rate-limit key or recorded as
/// request provenance.
pub(crate) fn trusted_forwarded_client(req: &Request) -> Option<String> {
    if !forwarded_for_trusted() {
        return None;
    }
    let header = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())?;
    rightmost_forwarded_ip(header).map(|address| address.to_string())
}

fn rightmost_forwarded_ip(header: &str) -> Option<std::net::IpAddr> {
    header
        .split(',')
        .map(str::trim)
        .rev()
        .find_map(|part| part.parse::<std::net::IpAddr>().ok())
}

fn rate_limit_peer_key(req: &Request) -> String {
    trusted_forwarded_client(req).unwrap_or_else(|| req.remote_addr().to_string())
}

#[async_trait]
impl Handler for RateLimiterMiddleware {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        // Spec: A.3 — buckets are keyed on `(remote_addr, endpoint_class)`
        // so a hot endpoint (e.g. /auth) cannot starve the rest of the
        // surface for the same peer, and a low ceiling on /auth/* makes
        // credential-stuffing prohibitively slow.
        let class = EndpointClass::classify(req.uri().path());
        let key = format!("{}:{}", rate_limit_peer_key(req), class.label());
        // Live ceilings/window from the runtime overlay (hot-swappable via the
        // admin settings endpoint). `affix_state::inject(state)` runs before
        // this hoop, so `AppState` is always in the depot; the fallback to the
        // limiter's boot config only matters in unit tests that exercise the
        // middleware without injected state.
        let effective = self
            .config_provider
            .as_ref()
            .map(|provider| provider())
            .unwrap_or_else(|| self.limiter.config.clone());
        let ceiling = effective.ceiling_for(class);

        if let Err(retry_after) =
            self.limiter
                .check_with_ceiling_window(&key, ceiling, effective.window)
        {
            let retry_after_ms = retry_after.as_millis().try_into().unwrap_or(u64::MAX);
            let retry_after_seconds = retry_after_ms.div_ceil(1000).max(1);
            let request_id = arkret_identifiers::new_prefixed_uuid7("ak:request:");
            res.status_code(StatusCode::TOO_MANY_REQUESTS);
            res.headers_mut()
                .insert(salvo::http::header::RETRY_AFTER, retry_after_seconds.into());
            crate::error::render_problem_envelope(
                res,
                StatusCode::TOO_MANY_REQUESTS,
                arkret_wire::problem_details::Problem::from_code(
                    "rate_limited",
                    "Too many requests. Please try again later.",
                )
                .with_instance(request_id)
                .with_retry_after_ms(Some(retry_after_ms)),
            );
            return;
        }

        ctrl.call_next(req, depot, res).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_after_reports_active_window_remaining() {
        let limiter = RateLimiter::new(RateLimiterConfig {
            max_requests: 1,
            window: Duration::from_secs(60),
            auth_max_requests: 1,
            api_max_requests: 1,
            probe_max_requests: 1,
        });

        assert!(limiter.check("client"));
        assert!(!limiter.check("client"));

        let retry_after = limiter
            .check_with_ceiling("client", 1)
            .expect_err("client remains limited");
        assert!(retry_after > Duration::from_secs(0));
        assert!(retry_after <= Duration::from_secs(60));
    }

    #[test]
    fn describe_probe_has_its_own_class() {
        // The login bootstrap calls `/_arkret/describe` before it can
        // authenticate; it must not share the authenticated `Api` bucket.
        assert_eq!(
            EndpointClass::classify(DESCRIBE_PROBE_PATH),
            EndpointClass::Probe
        );
        assert_eq!(
            EndpointClass::classify("/_arkret/self/account/subscribe"),
            EndpointClass::Api
        );
        assert_eq!(
            EndpointClass::classify(AUTH_REGISTER_PATH),
            EndpointClass::Auth
        );
        assert_eq!(EndpointClass::classify("/health"), EndpointClass::Other);
    }

    #[test]
    fn advertised_policy_matches_enforced_ceilings() {
        // The core invariant: a client that budgets against the advertised
        // `describe` policy can never trip a 429 it could not predict. Every
        // advertised entry's ceiling MUST equal what the middleware enforces
        // for a request matching that endpoint's class.
        let config = RateLimiterConfig::default();
        let policy = config.advertised_policy();
        assert!(!policy.entries.is_empty());

        for entry in &policy.entries {
            let endpoint = entry.endpoint.as_deref().expect("entry has endpoint");
            let advertised = entry.max_requests.expect("entry has max_requests");
            // Resolve a representative concrete path for the glob/catch-all
            // entries so we can run them through the real classifier.
            let concrete = match endpoint {
                "*" => "/some/non-arkret/path",
                "/_arkret/*" => "/_arkret/self/account/subscribe",
                "/_coland/gate/auth/*" => "/_coland/gate/auth/dev-login",
                literal => literal,
            };
            let enforced = config.ceiling_for(EndpointClass::classify(concrete));
            assert_eq!(
                advertised, enforced,
                "advertised ceiling for `{endpoint}` drifted from enforcement",
            );
        }
    }

    #[test]
    fn development_mode_relaxes_every_class() {
        let dev = RateLimiterConfig::resolve(true, RateLimitOverrides::default());
        let prod = RateLimiterConfig::default();
        assert!(dev.probe_max_requests > prod.probe_max_requests);
        assert!(dev.api_max_requests > prod.api_max_requests);
        assert!(dev.auth_max_requests > prod.auth_max_requests);
        assert!(dev.max_requests >= prod.max_requests);
    }

    #[test]
    fn forwarded_chain_uses_rightmost_valid_ip() {
        assert_eq!(
            rightmost_forwarded_ip("198.51.100.1, invalid, 203.0.113.7"),
            Some("203.0.113.7".parse().unwrap())
        );
        assert_eq!(rightmost_forwarded_ip("invalid, also-invalid"), None);
    }
}
