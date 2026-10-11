use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
#[cfg(test)]
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;
use std::time::Duration;

use arkret_egress_reqwest::{EgressGuard, LockedEgressUrl};
use reqwest::Url;

use crate::config::AppConfig;

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_HTTPS_PORT: u16 = 443;

/// Every input that can change an egress or federation verdict, parsed once.
///
/// These used to be eight separate `std::env::var` reads spread across this
/// file, each with its own parser. `COLAND_SOVEREIGN_ENCLAVE` in particular had
/// a second parser in `AppConfig` that accepted `on` and was case-insensitive
/// while this file's did not, so `COLAND_SOVEREIGN_ENCLAVE=on` enforced the
/// enclave posture at startup while leaving this gate — the one that actually
/// denies outbound federation — switched off.
///
/// The values are installed once at startup by [`install_egress_policy`] and
/// are immutable afterwards, which is what lets the ~74 call sites of the
/// functions below stay parameterless.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EgressPolicy {
    pub allow_private_networks: Option<bool>,
    pub allowed_hosts: Vec<String>,
    pub denylist: Vec<String>,
    pub federation_denylist: Vec<String>,
    pub federation_trust_domain_allowlist: Vec<String>,
    pub sovereign_enclave_enabled: bool,
    pub sovereign_enclave_allowed_outbound_hosts: Vec<String>,
}

static EGRESS_POLICY: OnceLock<EgressPolicy> = OnceLock::new();

/// Install the process egress policy. The first call wins; later calls are
/// ignored so a test harness cannot silently reconfigure a live gate.
pub fn install_egress_policy(policy: EgressPolicy) {
    let _ = EGRESS_POLICY.set(policy);
}

/// The installed policy, or an empty one.
///
/// An empty policy is the fail-closed reading everywhere it matters: no
/// sovereign enclave, no allowlists, no denylists, and
/// `allow_private_networks` deferring to `development_mode`.
fn egress_policy() -> &'static EgressPolicy {
    static EMPTY: OnceLock<EgressPolicy> = OnceLock::new();
    EGRESS_POLICY
        .get()
        .unwrap_or_else(|| EMPTY.get_or_init(EgressPolicy::default))
}

/// The hosts outbound HTTP may reach when the sovereign enclave profile is on.
///
/// The single parse of `COLAND_SOVEREIGN_ENCLAVE_ALLOWED_OUTBOUND_HOSTS`.
/// `AppConfig` surfaces this rather than parsing the variable a second time:
/// the config field used to be an independent copy that only reached a startup
/// log, so what an operator read back was not, by construction, what the
/// egress gate enforced.
pub fn sovereign_enclave_allowed_outbound_hosts() -> Vec<String> {
    egress_policy()
        .sovereign_enclave_allowed_outbound_hosts
        .clone()
}

/// Whether the sovereign enclave profile is enabled for this process.
pub fn sovereign_enclave_enabled() -> bool {
    egress_policy().sovereign_enclave_enabled
}

/// Result of validating the immutable startup posture for a sovereign enclave.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnclaveAssertionResult {
    pub enabled: bool,
    pub federation_outbound_disabled: bool,
    pub resolver_method_allowlist_present: bool,
    pub violations: Vec<String>,
}

impl EnclaveAssertionResult {
    pub fn is_compliant(&self) -> bool {
        !self.enabled || self.violations.is_empty()
    }
}

/// Validate the typed startup configuration before enabling the sovereign
/// enclave security posture. This guard does not create Realm, membership,
/// invitation, account, routing, or frontier state.
pub fn assert_enclave_invariants(config: &AppConfig) -> EnclaveAssertionResult {
    let enabled = config.sovereign_enclave_enabled;
    let mut violations = Vec::new();
    let federation_outbound_disabled = !config.federation_outbound_enabled;
    let resolver_method_allowlist_present = !config.did_resolver_allow_methods.is_empty();
    if enabled {
        if config.federation_outbound_enabled {
            violations.push(
                "sovereign_enclave_enabled=true requires federation_outbound_enabled=false"
                    .to_owned(),
            );
        }
        if !resolver_method_allowlist_present {
            violations.push(
                "sovereign_enclave_enabled=true requires a non-empty did_resolver_allow_methods"
                    .to_owned(),
            );
        }
    }
    EnclaveAssertionResult {
        enabled,
        federation_outbound_disabled,
        resolver_method_allowlist_present,
        violations,
    }
}

/// `sync/sovereign-deployment.md` §8 (normative) — before a federation request
/// to any external service, the target `service_id`'s verified `trust_domain`
/// MUST be in
/// the local `federation_allowlist`; otherwise the outbound MUST fail closed.
///
/// Returns the denial reason, or `None` when the request may proceed.
///
/// Fail closed in both directions of the unset case: with the sovereign
/// profile on and no allowlist configured, *every* outbound federation request
/// is denied. That is the profile's stated posture ("outbound federation is
/// disabled"), and it is the only reading that does not turn a forgotten
/// setting into an open boundary. The spec scopes this MUST to sovereign
/// deployments, so a non-sovereign deployment is unaffected and keeps using
/// the peer denylist.
///
/// This is an allowlist and deliberately not expressible through
/// [`federation_target_denied`]: a denylist cannot fail closed, and §8 says
/// explicitly that the sender MUST NOT rely on the receiver to refuse.
pub fn federation_outbound_trust_domain_denial(
    peer_id: &str,
    peer_trust_domain: Option<&str>,
) -> Option<String> {
    let policy = egress_policy();
    federation_outbound_trust_domain_denial_with_policy(
        policy.sovereign_enclave_enabled,
        &policy.federation_trust_domain_allowlist,
        peer_id,
        peer_trust_domain,
    )
}

fn federation_outbound_trust_domain_denial_with_policy(
    sovereign_enabled: bool,
    allowlist: &[String],
    peer_id: &str,
    peer_trust_domain: Option<&str>,
) -> Option<String> {
    if !sovereign_enabled {
        return None;
    }
    let Some(trust_domain) = peer_trust_domain.filter(|value| !value.trim().is_empty()) else {
        return Some(format!(
            "federation_trust_domain_missing: {peer_id} has no verified trust_domain binding"
        ));
    };
    let allowed = allowlist
        .iter()
        .any(|entry| entry_matches(entry, trust_domain));
    tracing::info!(
        target = "sovereign_boundary_audit",
        target_class = "federation outbound",
        peer_id,
        trust_domain,
        posture = if allowed { "allowed" } else { "denied" },
        "sovereign federation outbound trust_domain check"
    );
    if allowed {
        None
    } else {
        Some(format!(
            "federation_trust_domain_not_allowed: {peer_id} is bound to trust_domain \
             {trust_domain}, which is not in the local federation_allowlist"
        ))
    }
}

/// Whether outbound egress to private/loopback networks is permitted.
///
/// `COLAND_EGRESS_ALLOW_PRIVATE_NETWORKS`, when set, is authoritative and MUST
/// be used to decouple this decision from the deployment posture in any
/// environment where the two must differ. When the variable is unset the
/// default follows `development_mode` (dev needs to reach localhost services).
///
/// Deployment note: a production deployment MUST run with
/// `development_mode = false`; otherwise the private-network egress guard opens
/// as a side effect of the dev flag. The cloud metadata endpoint
/// (`169.254.169.254`) remains hard-blocked regardless (see
/// [`validate_url_for_egress`]), which caps the blast radius of a misconfigured
/// `development_mode`, but the explicit env var should be preferred to pin the
/// posture independently.
pub fn private_networks_allowed(development_mode: bool) -> bool {
    egress_policy()
        .allow_private_networks
        .unwrap_or(development_mode)
}

/// Stable digest of every input that can change an egress verdict.
///
/// A `policy_suppressed` federation outbox row records the version that denied
/// it; the dispatcher only revalidates rows whose recorded version differs from
/// the live one. Without this, a restart would either re-run the whole
/// suppressed backlog every tick or — worse — silently bypass a policy that
/// still denies the target.
pub fn egress_policy_version(development_mode: bool) -> String {
    let mut canonical = String::new();
    canonical.push_str("allow_private=");
    canonical.push_str(if private_networks_allowed(development_mode) {
        "1"
    } else {
        "0"
    });
    let policy = egress_policy();
    for (name, entries) in [
        ("COLAND_EGRESS_ALLOWED_HOSTS", policy.allowed_hosts.clone()),
        ("COLAND_EGRESS_DENYLIST", policy.denylist.clone()),
    ] {
        canonical.push('\n');
        canonical.push_str(name);
        canonical.push('=');
        let mut entries = entries;
        entries.sort();
        entries.dedup();
        canonical.push_str(&entries.join(","));
    }
    let mut federation = federation_denylist_entries();
    federation.sort();
    federation.dedup();
    canonical.push_str("\nfederation_denylist=");
    canonical.push_str(&federation.join(","));
    canonical.push_str("\nsovereign_enclave=");
    canonical.push_str(if sovereign_enclave_enabled() {
        "1"
    } else {
        "0"
    });
    let mut enclave_hosts = sovereign_enclave_allowed_outbound_hosts();
    enclave_hosts.sort();
    enclave_hosts.dedup();
    canonical.push_str("\nsovereign_enclave_allowed_hosts=");
    canonical.push_str(&enclave_hosts.join(","));
    // §8's outbound allowlist changes an egress verdict, so a `policy_suppressed`
    // federation row must revalidate when it changes.
    let mut federation_allowlist = policy.federation_trust_domain_allowlist.clone();
    federation_allowlist.sort();
    federation_allowlist.dedup();
    canonical.push_str("\nfederation_trust_domain_allowlist=");
    canonical.push_str(&federation_allowlist.join(","));
    arkret_canonical::sha256_digest(canonical.as_bytes())
}

pub fn validate_http_url_for_egress(
    raw_url: &str,
    purpose: &str,
    development_mode: bool,
) -> Result<Url, String> {
    let url = Url::parse(raw_url).map_err(|error| format!("{purpose}: invalid URL: {error}"))?;
    if let Err(error) =
        validate_url_for_egress(&url, purpose, private_networks_allowed(development_mode))
    {
        record_egress_denial(&url, purpose, &error);
        return Err(error);
    }
    Ok(url)
}

pub fn validate_http_url_for_egress_with_pinned_client(
    raw_url: &str,
    purpose: &str,
    development_mode: bool,
    request_timeout: Duration,
) -> Result<(Url, reqwest::Client), String> {
    validate_http_url_for_egress_with_pinned_client_allow_private(
        raw_url,
        purpose,
        private_networks_allowed(development_mode),
        request_timeout,
    )
}

pub fn validate_http_url_for_egress_with_pinned_client_allow_private(
    raw_url: &str,
    purpose: &str,
    allow_private_networks: bool,
    request_timeout: Duration,
) -> Result<(Url, reqwest::Client), String> {
    let url = Url::parse(raw_url).map_err(|error| format!("{purpose}: invalid URL: {error}"))?;
    let target = match resolve_and_validate_url_for_egress(&url, purpose, allow_private_networks) {
        Ok(target) => target,
        Err(error) => {
            record_egress_denial(&url, purpose, &error);
            return Err(error);
        }
    };
    let builder = egress_http_client_builder()?
        .connect_timeout(DEFAULT_CONNECT_TIMEOUT.min(request_timeout))
        .timeout(request_timeout)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy();
    let client = target
        .apply_to_client_builder(builder)
        .build()
        .map_err(|error| format!("failed to build pinned egress HTTP client: {error}"))?;
    Ok((url, client))
}

fn egress_http_client_builder() -> Result<reqwest::ClientBuilder, String> {
    let builder = reqwest::Client::builder();
    let Some(path) = std::env::var_os("SSL_CERT_FILE") else {
        return Ok(builder);
    };
    let path = std::path::PathBuf::from(path);
    let pem = std::fs::read(&path)
        .map_err(|error| format!("failed to read SSL_CERT_FILE {}: {error}", path.display()))?;
    let certificates = reqwest::Certificate::from_pem_bundle(&pem).map_err(|error| {
        format!(
            "SSL_CERT_FILE {} contains no valid PEM certificate: {error}",
            path.display()
        )
    })?;
    // `SSL_CERT_FILE` is an explicit operator trust store.  Use rustls/webpki
    // for that exact store instead of passing its roots through the platform
    // verifier: Windows CryptoAPI rejects valid run-scoped rcgen authorities
    // before webpki can evaluate them.  Hostname verification remains enabled.
    Ok(builder.tls_backend_rustls().tls_certs_only(certificates))
}

pub fn validate_url_for_egress(
    url: &Url,
    purpose: &str,
    allow_private_networks: bool,
) -> Result<(), String> {
    validate_url_for_egress_with_resolver(url, purpose, allow_private_networks, |host, port| {
        let resolved = (host, port)
            .to_socket_addrs()
            .map_err(|error| format!("{purpose}: DNS resolution for {host} failed: {error}"))?;
        Ok(resolved.map(|addr| addr.ip()).collect())
    })
}

pub fn validate_url_for_egress_with_resolved_ips(
    url: &Url,
    purpose: &str,
    allow_private_networks: bool,
    resolved_ips: &[IpAddr],
) -> Result<(), String> {
    validate_url_for_egress_with_resolver(url, purpose, allow_private_networks, |_host, _port| {
        Ok(resolved_ips.to_vec())
    })
}

/// Judge the host through coland's deployment layers, which the shared guard
/// knows nothing about: the sovereign-enclave outbound allowlist and the
/// operator host deny/allow lists.
///
/// Runs *after* the shared guard's scheme/host judgment so the reported denial
/// reason keeps its existing precedence.
fn validate_coland_host_layers(url: &Url, purpose: &str) -> Result<String, String> {
    let host = url
        .host_str()
        .filter(|host| !host.trim().is_empty())
        .ok_or_else(|| format!("{purpose}: URL host is required"))?;
    validate_sovereign_enclave_host_policy(host, purpose)?;
    validate_host_policy(host, purpose)?;
    Ok(host.to_owned())
}

fn resolve_and_validate_url_for_egress(
    url: &Url,
    purpose: &str,
    allow_private_networks: bool,
) -> Result<LockedEgressUrl, String> {
    let guard = egress_guard(allow_private_networks);
    guard
        .validate_url(url, purpose)
        .map_err(|error| error.to_string())?;
    validate_coland_host_layers(url, purpose)?;
    guard
        .lock_url(url, purpose)
        .map_err(|error| error.to_string())
}

fn validate_url_for_egress_with_resolver<F>(
    url: &Url,
    purpose: &str,
    allow_private_networks: bool,
    mut resolve_host: F,
) -> Result<(), String>
where
    F: FnMut(&str, u16) -> Result<Vec<IpAddr>, String>,
{
    let guard = egress_guard(allow_private_networks);
    guard
        .validate_url(url, purpose)
        .map_err(|error| error.to_string())?;
    let host = validate_coland_host_layers(url, purpose)?;
    let port = url.port_or_known_default().unwrap_or(DEFAULT_HTTPS_PORT);
    let addresses = match arkret_egress_reqwest::literal_host_ip(url) {
        Some(ip) => vec![SocketAddr::new(ip, port)],
        None => resolve_host(&host, port)?
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect::<Vec<_>>(),
    };
    guard
        .validate_addresses(&host, &addresses, purpose)
        .map_err(|error| error.to_string())
}

fn record_egress_denial(url: &Url, purpose: &str, error: &str) {
    let reason = egress_denial_reason(error);
    let host = url.host_str().unwrap_or_default();
    let scheme = url.scheme();
    crate::metrics::record_egress_denied(reason, purpose);
    tracing::warn!(
        target = "egress_policy",
        reason,
        target_class = purpose,
        host,
        scheme,
        %error,
        "outbound HTTP request denied by egress policy"
    );
}

fn validate_sovereign_enclave_host_policy(host: &str, purpose: &str) -> Result<(), String> {
    validate_sovereign_enclave_host_policy_with_entries(
        host,
        purpose,
        sovereign_enclave_enabled(),
        &sovereign_enclave_allowed_outbound_hosts(),
    )
}

fn validate_sovereign_enclave_host_policy_with_entries(
    host: &str,
    purpose: &str,
    sovereign_enabled: bool,
    allowed_hosts: &[String],
) -> Result<(), String> {
    if !sovereign_enabled {
        return Ok(());
    }
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let allowed = allowed_hosts
        .iter()
        .any(|entry| host_policy_entry_matches(entry, &host));
    audit_sovereign_enclave_egress(purpose, &host, allowed);
    if allowed {
        Ok(())
    } else {
        Err(format!(
            "{purpose}: sovereign_enclave_outbound_not_allowed egress target {host}"
        ))
    }
}

fn audit_sovereign_enclave_egress(purpose: &str, host: &str, allowed: bool) {
    let posture = if allowed { "allowed" } else { "denied" };
    tracing::info!(
        target = "sovereign_boundary_audit",
        target_class = purpose,
        host,
        posture,
        "sovereign enclave outbound call audit"
    );
}

pub fn federation_origin_denied(origin_did: &str) -> bool {
    federation_target_denied(None, Some(origin_did), None)
}

pub fn federation_peer_denied(peer_url: &str, peer_id: &str) -> bool {
    federation_target_denied(Some(peer_url), Some(peer_id), None)
}

pub fn federation_target_denied(
    peer_url: Option<&str>,
    peer_id: Option<&str>,
    peer_trust_domain: Option<&str>,
) -> bool {
    let entries = federation_denylist_entries();
    federation_target_denied_with_entries(&entries, peer_url, peer_id, peer_trust_domain)
}

fn federation_target_denied_with_entries(
    entries: &[String],
    peer_url: Option<&str>,
    peer_id: Option<&str>,
    peer_trust_domain: Option<&str>,
) -> bool {
    if entries.is_empty() {
        return false;
    }
    let url_host = peer_url.and_then(url_host);
    let did_domain = peer_id.and_then(did_web_domain);
    entries.iter().any(|entry| {
        let entry = entry.as_str();
        peer_id.is_some_and(|did| entry_matches(entry, did))
            || peer_trust_domain.is_some_and(|trust| entry_matches(entry, trust))
            || url_host
                .as_deref()
                .is_some_and(|host| domain_entry_matches(entry, host))
            || did_domain
                .as_deref()
                .is_some_and(|host| domain_entry_matches(entry, host))
    })
}

/// coland's outbound posture. A controlled-network deployment additionally
/// admits private and CGNAT destinations; metadata / link-local destinations
/// stay impossible in both postures.
fn egress_guard(allow_private_networks: bool) -> EgressGuard {
    if allow_private_networks {
        EgressGuard::new(arkret_egress_policy::OutboundPolicy::controlled_network(
            true,
        ))
    } else {
        EgressGuard::public_https()
    }
}

fn egress_denial_reason(error: &str) -> &'static str {
    if error.contains("localhost") {
        "localhost"
    } else if error.contains("private_network") || error.contains("private address") {
        "private_network"
    } else if error.contains("loopback") {
        "loopback"
    } else if error.contains("cloud_metadata") {
        "cloud_metadata"
    } else if error.contains("link_local") {
        "link_local"
    } else if error.contains("multicast") {
        "multicast"
    } else if error.contains("unspecified") {
        "unspecified"
    } else if error.contains("host_not_allowed") {
        "host_not_allowed"
    } else if error.contains("host_denied") {
        "host_denied"
    } else if error.contains("sovereign_enclave_outbound_not_allowed") {
        "sovereign_enclave_outbound_not_allowed"
    } else if error.contains("blocked") {
        "blocked_address"
    } else if error.contains("scheme") {
        "invalid_scheme"
    } else if error.contains("DNS resolution") {
        "dns_resolution_failed"
    } else if error.contains("host is required") {
        "missing_host"
    } else {
        "policy_denied"
    }
}

fn federation_denylist_entries() -> Vec<String> {
    egress_policy().federation_denylist.clone()
}

fn validate_host_policy(host: &str, purpose: &str) -> Result<(), String> {
    let policy = egress_policy();
    validate_host_policy_with_entries(host, purpose, &policy.denylist, &policy.allowed_hosts)
}

fn validate_host_policy_with_entries(
    host: &str,
    purpose: &str,
    denied_hosts: &[String],
    allowed_hosts: &[String],
) -> Result<(), String> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if denied_hosts
        .iter()
        .any(|entry| host_policy_entry_matches(entry, &host))
    {
        return Err(format!("{purpose}: host_denied egress target {host}"));
    }
    if !allowed_hosts.is_empty()
        && !allowed_hosts
            .iter()
            .any(|entry| host_policy_entry_matches(entry, &host))
    {
        return Err(format!("{purpose}: host_not_allowed egress target {host}"));
    }
    Ok(())
}

/// Split a comma / semicolon / newline separated host policy list.
///
/// Public so the configuration loader — the only parser — can produce the
/// entries this module consumes.
pub fn split_host_policy_entries(raw: Option<&str>) -> Vec<String> {
    raw.into_iter()
        .flat_map(|raw| {
            raw.split([',', ';', '\n'])
                .map(|entry| entry.trim().trim_end_matches('.').to_ascii_lowercase())
                .filter(|entry| !entry.is_empty())
                .collect::<Vec<_>>()
        })
        .collect()
}

/// Same split, without the trailing-dot trim, for federation denylist entries.
pub fn split_federation_denylist_entries(raws: &[Option<&str>]) -> Vec<String> {
    raws.iter()
        .filter_map(|raw| *raw)
        .flat_map(|raw| {
            raw.split([',', ';', '\n'])
                .map(|entry| entry.trim().to_ascii_lowercase())
                .filter(|entry| !entry.is_empty())
                .collect::<Vec<_>>()
        })
        .collect()
}

fn host_policy_entry_matches(entry: &str, host: &str) -> bool {
    if entry == "*" {
        return true;
    }
    if let Some(suffix) = entry.strip_prefix("*.") {
        return host == suffix || host.ends_with(&format!(".{suffix}"));
    }
    if let Some(suffix) = entry.strip_prefix('.') {
        return host == suffix || host.ends_with(&format!(".{suffix}"));
    }
    host == entry
}

fn entry_matches(entry: &str, value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    entry == value
        || entry
            .strip_prefix("did:")
            .is_some_and(|rest| value == format!("did:{rest}"))
        || entry
            .strip_prefix("trust_domain:")
            .is_some_and(|rest| value == rest)
}

fn domain_entry_matches(entry: &str, host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let domain = entry
        .strip_prefix("domain:")
        .or_else(|| entry.strip_prefix("host:"))
        .unwrap_or(entry)
        .trim_end_matches('.')
        .to_ascii_lowercase();
    host == domain || host.ends_with(&format!(".{domain}"))
}

fn url_host(raw_url: &str) -> Option<String> {
    Url::parse(raw_url)
        .ok()
        .and_then(|url| url.host_str().map(|host| host.to_owned()))
}

fn did_web_domain(did: &str) -> Option<String> {
    let domain = if let Some(rest) = did.strip_prefix("did:web:") {
        rest.split(':').next()?
    } else {
        let rest = did.strip_prefix("did:webvh:")?;
        let mut parts = rest.split(':');
        let scid = parts.next()?;
        let host = parts.next()?;
        if scid.is_empty() {
            return None;
        }
        host
    };
    let domain = domain
        .split("%3A")
        .next()
        .unwrap_or(domain)
        .split("%3a")
        .next()
        .unwrap_or(domain)
        .trim_end_matches('.')
        .to_ascii_lowercase();
    (!domain.trim().is_empty()).then_some(domain)
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use parking_lot::Mutex;

    use super::*;
    use crate::config::ObjectStorageConfig;

    fn base_config() -> AppConfig {
        AppConfig {
            object_storage: ObjectStorageConfig::local(
                std::env::temp_dir().join("coland-enclave-tests"),
            ),
            development_mode: true,
            did_resolver_allow_methods: vec!["web".to_owned()],
            ..AppConfig::test_default()
        }
    }

    #[test]
    fn sovereign_enclave_disabled_has_no_startup_violations() {
        let result = assert_enclave_invariants(&base_config());
        assert!(result.is_compliant());
        assert!(result.violations.is_empty());
    }

    #[test]
    fn sovereign_enclave_requires_outbound_federation_off() {
        let mut config = base_config();
        config.sovereign_enclave_enabled = true;
        config.federation_outbound_enabled = true;
        let result = assert_enclave_invariants(&config);
        assert!(!result.is_compliant());
        assert!(
            result
                .violations
                .iter()
                .any(|violation| violation.contains("federation_outbound_enabled"))
        );
    }

    #[test]
    fn sovereign_enclave_requires_did_method_allowlist() {
        let mut config = base_config();
        config.sovereign_enclave_enabled = true;
        config.did_resolver_allow_methods.clear();
        let result = assert_enclave_invariants(&config);
        assert!(!result.is_compliant());
        assert!(
            result
                .violations
                .iter()
                .any(|violation| violation.contains("did_resolver_allow_methods"))
        );
    }

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn egress_guard_rejects_loopback_and_private_literals() {
        let _guard = env_lock().lock();
        for raw in [
            "http://127.0.0.1:8080/x",
            "http://10.0.0.1/x",
            "http://172.16.0.1/x",
            "http://192.168.1.1/x",
            "http://169.254.169.254/latest/meta-data",
            "http://[::1]/x",
            "http://[fd00::1]/x",
            "http://[64:ff9b::a00:1]/x",
            "http://[2002:0a00:0001::1]/x",
            "http://[2001:0000::f5ff:fffe]/x",
        ] {
            let url = Url::parse(raw).unwrap();
            assert!(
                validate_url_for_egress(&url, "test", false).is_err(),
                "{raw} should be blocked"
            );
        }
    }

    #[test]
    fn egress_guard_allows_private_when_explicitly_configured() {
        let _guard = env_lock().lock();
        let url = Url::parse("http://127.0.0.1:8080/x").unwrap();
        assert!(validate_url_for_egress(&url, "test", true).is_ok());
    }

    #[test]
    fn egress_guard_rejects_metadata_even_when_private_allowed() {
        let _guard = env_lock().lock();
        for raw in [
            "http://169.254.169.254/latest/meta-data",
            "http://169.254.1.1/x",
            "http://[64:ff9b::a9fe:a9fe]/x",
        ] {
            let url = Url::parse(raw).unwrap();
            assert!(
                validate_url_for_egress(&url, "test", true).is_err(),
                "{raw} should stay blocked"
            );
        }
        let controlled_private = Url::parse("http://[fd00::1]/x").unwrap();
        assert!(validate_url_for_egress(&controlled_private, "test", true).is_ok());
    }

    #[test]
    fn egress_guard_rejects_dns_answers_that_resolve_private() {
        let _guard = env_lock().lock();
        let url = Url::parse("https://relay.example/federation").unwrap();
        let error = validate_url_for_egress_with_resolver(&url, "test", false, |_host, _port| {
            Ok(vec![IpAddr::V4(Ipv4Addr::new(10, 42, 0, 12))])
        })
        .unwrap_err();
        assert!(error.contains("private address"));
    }

    #[test]
    fn egress_guard_allows_public_dns_answers() {
        let _guard = env_lock().lock();
        let url = Url::parse("https://relay.example/federation").unwrap();
        assert!(
            validate_url_for_egress_with_resolver(&url, "test", false, |_host, _port| {
                Ok(vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))])
            })
            .is_ok()
        );
    }

    #[test]
    fn egress_guard_rejects_any_private_answer_to_limit_rebinding() {
        let _guard = env_lock().lock();
        let url = Url::parse("https://relay.example/federation").unwrap();
        let error = validate_url_for_egress_with_resolver(&url, "test", false, |_host, _port| {
            Ok(vec![
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
            ])
        })
        .unwrap_err();
        assert!(error.contains("loopback"));
    }

    #[test]
    fn egress_guard_enforces_host_deny_and_allow_lists() {
        let denied = vec!["blocked.example".to_owned()];
        let allowed = vec!["*.allowed.example".to_owned()];
        assert!(
            validate_host_policy_with_entries("blocked.example", "test", &denied, &allowed)
                .unwrap_err()
                .contains("host_denied")
        );
        assert!(
            validate_host_policy_with_entries("other.example", "test", &denied, &allowed)
                .unwrap_err()
                .contains("host_not_allowed")
        );
        assert!(
            validate_host_policy_with_entries("relay.allowed.example", "test", &denied, &allowed,)
                .is_ok()
        );
    }

    #[test]
    fn sovereign_egress_host_allowlist_is_enforced_by_the_url_gate() {
        let allowed_hosts = vec!["relay.allowed.example".to_owned()];
        assert!(
            validate_sovereign_enclave_host_policy_with_entries(
                "relay.allowed.example",
                "test",
                true,
                &allowed_hosts,
            )
            .is_ok()
        );
        assert!(
            validate_sovereign_enclave_host_policy_with_entries(
                "relay.other.example",
                "test",
                true,
                &allowed_hosts,
            )
            .unwrap_err()
            .contains("sovereign_enclave_outbound_not_allowed")
        );
    }

    #[test]
    fn sovereign_federation_trust_domain_is_verified_and_fail_closed() {
        let allowlist = vec!["ak:trust_domain:partner.example".to_owned()];
        let service_id = "did:web:relay.partner.example";

        assert!(
            federation_outbound_trust_domain_denial_with_policy(
                true,
                &allowlist,
                service_id,
                None,
            )
            .is_some()
        );
        assert!(
            federation_outbound_trust_domain_denial_with_policy(
                true,
                &allowlist,
                service_id,
                Some("ak:trust_domain:untrusted.example")
            )
            .is_some()
        );
        assert!(
            federation_outbound_trust_domain_denial_with_policy(
                true,
                &allowlist,
                service_id,
                Some("ak:trust_domain:partner.example")
            )
            .is_none()
        );
    }

    #[test]
    fn federation_denylist_matches_did_domain_and_url_domain() {
        let entries = vec![
            "ak:did_core:web:blocked.example".to_owned(),
            "domain:evil.example".to_owned(),
            "ak:trust_domain:bad.example".to_owned(),
        ];
        assert!(federation_target_denied_with_entries(
            &entries,
            None,
            Some("ak:did_core:web:blocked.example"),
            None,
        ));
        assert!(federation_target_denied_with_entries(
            &entries,
            Some("https://relay.evil.example"),
            Some("ak:did_core:web:other.example"),
            None,
        ));
        assert!(federation_target_denied_with_entries(
            &entries,
            None,
            Some("ak:did_core:web:other.example"),
            Some("ak:trust_domain:bad.example"),
        ));
        assert!(!federation_target_denied_with_entries(
            &entries,
            Some("https://good.example"),
            Some("ak:did_core:web:good.example"),
            None,
        ));
    }

    #[test]
    fn federation_denylist_matches_did_webvh_host_not_scid() {
        let entries = vec![
            "domain:local.host".to_owned(),
            "ak:trust_domain:local.host".to_owned(),
        ];
        assert!(federation_target_denied_with_entries(
            &entries,
            None,
            Some(
                "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:local.host:webvh:service"
            ),
            None,
        ));
        assert!(!federation_target_denied_with_entries(
            &entries,
            None,
            Some(
                "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:other.host:webvh:service"
            ),
            None,
        ));
    }

    #[test]
    fn trust_domain_policy_is_closed_when_empty_and_scoped_to_sovereign_mode() {
        let empty = Vec::new();
        let service_id = "did:web:partner.example";
        let trust_domain = Some("ak:trust_domain:partner.example");
        assert!(
            federation_outbound_trust_domain_denial_with_policy(
                true,
                &empty,
                service_id,
                trust_domain,
            )
            .is_some()
        );
        assert!(
            federation_outbound_trust_domain_denial_with_policy(
                false,
                &empty,
                service_id,
                trust_domain,
            )
            .is_none()
        );
    }
}
