pub const SERVICE_IDENTITY_KEYSTORE_APP: &str = "coland.service-identity";
pub const CONFIGURED_SIGNING_KEY_REF: &str = "secret:COLAND_NOTARY_SIGNING_KEY";

use std::collections::BTreeMap;
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arkret_identifiers::{DidCoreId, TrustDomainId};
use zeroize::{Zeroize, Zeroizing};

/// v1 interoperability bound for HTTP message content of a non-streaming JSON operation, from
/// `zh/conformance/scalability-constraints.md` §2.1.3. A deployment MUST NOT declare a lower
/// global value (§2.1.6): a legal 8 MiB canonical body has to stay portable across services, and
/// a federation origin cannot split batches safely if peers cap the wire below the constant.
pub const DEFAULT_MAX_REQUEST_SIZE_BYTES: usize = 16 * 1024 * 1024;
pub const DEFAULT_TO_DEVICE_QUEUE_CAPACITY: usize = 10_000;
/// Concurrent Applet edge transactions this Station admits before it
/// sheds load. applet-integration.md 7.3 requires the excess to come back
/// as per-event `queue_full` rejections with `retry_after_ms`, not as a
/// timeout or an unbounded backlog.
pub const DEFAULT_APPLET_TRANSACTION_INFLIGHT_CAPACITY: usize = 64;
pub const PQ_HYBRID_TLS_DEPLOYMENT_PROBE_ENV: &str = "COLAND_PQ_TLS_DEPLOYMENT_PROBE";

/// STUN URL shipped as the [`IceServersConfig::default`] value. A production
/// deployment still advertising this Google public STUN server leaks client
/// candidate-gathering to a third party; surfaced as a hardening warning.
pub const PLACEHOLDER_STUN_URL: &str = "stun:stun.l.google.com:19302";

/// TURN URL shipped as the [`IceServersConfig::default`] value. It points at a
/// non-existent host, so a production deployment still advertising it has no
/// working relay; surfaced as a hardening warning.
pub const PLACEHOLDER_TURN_HOST: &str = "turn.coland.local";

/// Command-line-only startup choices supplied by the executable layer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StartupOverrides {
    pub bind: Option<String>,
    pub first_provisioning: bool,
}

/// Durable key-custody backend used by every Coland KeyStore namespace.
#[derive(Clone, Default)]
pub enum KeyStoreConfig {
    /// No durable key custody. This is valid only for fully in-memory tests and
    /// local development; a persistent database must never use it.
    #[default]
    Disabled,
    /// Native operating-system credential storage for the current user.
    Platform,
    /// Authenticated encrypted file with a separately custodied master key.
    EncryptedFile {
        path: PathBuf,
        master_key: Arc<Zeroizing<[u8; 32]>>,
    },
}

impl fmt::Debug for KeyStoreConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disabled => formatter.write_str("Disabled"),
            Self::Platform => formatter.write_str("Platform"),
            Self::EncryptedFile { path, .. } => formatter
                .debug_struct("EncryptedFile")
                .field("path", path)
                .field("master_key", &"<redacted>")
                .finish(),
        }
    }
}

impl KeyStoreConfig {
    /// Parse and validate key-store settings from already-resolved values.
    pub fn from_values(values: &BTreeMap<String, String>) -> anyhow::Result<Self> {
        Self::resolve(
            env_non_empty(values, "COLAND_KEYSTORE_BACKEND")
                .map(|value| value.to_ascii_lowercase())
                .as_deref(),
            env_non_empty(values, "COLAND_KEYSTORE_PATH").map(PathBuf::from),
            env_non_empty(values, "COLAND_KEYSTORE_MASTER_KEY_FILE").as_deref(),
            env_non_empty(values, "COLAND_KEYSTORE_MASTER_KEY").map(Zeroizing::new),
        )
    }

    /// Validate an already-read backend selection.
    fn resolve(
        backend: Option<&str>,
        path: Option<PathBuf>,
        master_key_file: Option<&str>,
        raw_master_key: Option<Zeroizing<String>>,
    ) -> anyhow::Result<Self> {
        let backend = backend.map(str::to_owned);
        let master_key_file = master_key_file.map(str::to_owned);

        match backend.as_deref() {
            None => {
                if path.is_some() || raw_master_key.is_some() {
                    anyhow::bail!(
                        "COLAND_KEYSTORE_BACKEND is required when encrypted-file KeyStore settings are configured"
                    );
                }
                Ok(Self::Disabled)
            }
            Some("platform") => {
                if path.is_some() || raw_master_key.is_some() {
                    anyhow::bail!(
                        "COLAND_KEYSTORE_PATH and COLAND_KEYSTORE_MASTER_KEY(_FILE) are only valid with COLAND_KEYSTORE_BACKEND=encrypted_file"
                    );
                }
                Ok(Self::Platform)
            }
            Some("encrypted_file") => {
                let path = path.ok_or_else(|| {
                    anyhow::anyhow!(
                        "COLAND_KEYSTORE_PATH is required with COLAND_KEYSTORE_BACKEND=encrypted_file"
                    )
                })?;
                if master_key_file
                    .as_ref()
                    .is_some_and(|key_path| paths_refer_to_same_file(Path::new(key_path), &path))
                {
                    anyhow::bail!(
                        "COLAND_KEYSTORE_MASTER_KEY_FILE must be separate from COLAND_KEYSTORE_PATH"
                    );
                }
                let raw_master_key = raw_master_key.ok_or_else(|| {
                    anyhow::anyhow!(
                        "COLAND_KEYSTORE_MASTER_KEY or COLAND_KEYSTORE_MASTER_KEY_FILE is required with COLAND_KEYSTORE_BACKEND=encrypted_file"
                    )
                })?;
                use base64::Engine as _;
                let mut decoded = Zeroizing::new(
                    base64::engine::general_purpose::STANDARD
                        .decode(raw_master_key.as_bytes())
                        .or_else(|_| {
                            base64::engine::general_purpose::URL_SAFE_NO_PAD
                                .decode(raw_master_key.as_bytes())
                        })
                        .map_err(|error| {
                            anyhow::anyhow!(
                                "COLAND_KEYSTORE_MASTER_KEY must be base64 (standard or url-safe-no-pad): {error}"
                            )
                        })?,
                );
                if decoded.len() != 32 {
                    anyhow::bail!(
                        "COLAND_KEYSTORE_MASTER_KEY must decode to exactly 32 bytes (got {})",
                        decoded.len()
                    );
                }
                let mut master_key = [0u8; 32];
                master_key.copy_from_slice(&decoded);
                decoded.zeroize();
                Ok(Self::EncryptedFile {
                    path,
                    master_key: Arc::new(Zeroizing::new(master_key)),
                })
            }
            Some(other) => anyhow::bail!(
                "COLAND_KEYSTORE_BACKEND must be platform or encrypted_file; got {other}"
            ),
        }
    }

    #[inline]
    pub fn is_durable(&self) -> bool {
        !matches!(self, Self::Disabled)
    }

    pub fn backend_name(&self) -> Option<&'static str> {
        match self {
            Self::Disabled => None,
            Self::Platform => Some("platform"),
            Self::EncryptedFile { .. } => Some("encrypted_file"),
        }
    }

    /// Open one application namespace in the configured durable backend.
    pub fn open(
        &self,
        application_id: &str,
    ) -> anyhow::Result<Option<Box<dyn arkret_keystore::KeyStore>>> {
        match self {
            Self::Disabled => Ok(None),
            Self::Platform => arkret_keystore::durable_platform_keystore(application_id)
                .map(Some)
                .map_err(|error| anyhow::anyhow!("opening platform KeyStore failed: {error}")),
            Self::EncryptedFile { path, master_key } => {
                let mut key = **master_key.as_ref();
                let store = arkret_keystore::EncryptedFileKeyStore::new(path, application_id, key);
                key.zeroize();
                store
                    .map(|store| Some(Box::new(store) as Box<dyn arkret_keystore::KeyStore>))
                    .map_err(|error| {
                        anyhow::anyhow!("opening encrypted-file KeyStore failed: {error}")
                    })
            }
        }
    }
}

fn paths_refer_to_same_file(left: &Path, right: &Path) -> bool {
    left == right
        || std::fs::canonicalize(left)
            .ok()
            .zip(std::fs::canonicalize(right).ok())
            .is_some_and(|(left, right)| left == right)
}

fn validate_persistence_key_store(
    database_url: Option<&str>,
    key_store: &KeyStoreConfig,
) -> anyhow::Result<()> {
    if database_url.is_some() && !key_store.is_durable() {
        anyhow::bail!(
            "DATABASE_URL requires a durable KeyStore; set COLAND_KEYSTORE_BACKEND=platform or encrypted_file"
        );
    }
    Ok(())
}

/// The four registered facts and credential of one
/// deployment-internal authenticated channel (`sync/service-http-binding.md`
/// §2.2.3).
///
/// Service identities are resolved where the channel is used rather than
/// copied here: a split Account Authority signs as this Station, so both ends
/// use this Station's service `did_core_id`. Trust domains are not collapsed:
/// the Account Authority/source domain is explicit here and the
/// Station/destination domain comes from `AppConfig::trust_domain`. The fixed
/// product-private adapter paths remain compile-time facts, while this struct
/// carries the shared per-edge secret. Operators cannot widen the credential
/// into a bearer-protected canonical path group.
#[derive(Clone)]
pub struct InternalAuthorityChannelConfig {
    /// Shared per-edge credential, byte-identical to the Account Authority's
    /// `stations[].internal_authority_shared_secret` for this Station. The
    /// same secret authenticates both directions of this one edge; it is not a
    /// general deployment bearer and grants nothing outside the fixed private
    /// adapters.
    credential: String,
    /// Account Authority/source trust domain from explicit deployment config.
    account_authority_trust_domain: TrustDomainId,
    /// Exact controller-gate operation endpoint derived from the canonical
    /// Account Authority base at startup.
    controller_gate_url: String,
}

impl InternalAuthorityChannelConfig {
    /// The shared credential. Kept behind an accessor so it is never printed:
    /// [`std::fmt::Debug`] is implemented by hand to redact it.
    #[must_use]
    pub fn credential(&self) -> &str {
        &self.credential
    }

    /// Exact controller-gate operation endpoint bound to the Authority origin.
    #[must_use]
    pub fn controller_gate_url(&self) -> &str {
        &self.controller_gate_url
    }

    /// Account Authority trust domain bound by deployment configuration.
    #[must_use]
    pub fn account_authority_trust_domain(&self) -> &TrustDomainId {
        &self.account_authority_trust_domain
    }
}

impl std::fmt::Debug for InternalAuthorityChannelConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InternalAuthorityChannelConfig")
            .field("credential", &"<redacted>")
            .field(
                "account_authority_trust_domain",
                &self.account_authority_trust_domain,
            )
            .field("controller_gate_url", &self.controller_gate_url)
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub bind: SocketAddr,
    pub metrics_bind: SocketAddr,
    pub public_base_url: String,
    /// Explicit one-shot authorization for a new class-B deployment to mint
    /// its first service identity. The resulting DID is persisted and never
    /// copied back into configuration.
    pub first_provisioning: bool,
    /// Optional TLS certificate PEM path. When both this and
    /// [`tls_key_path`] are configured, coland starts an HTTPS listener using
    /// Salvo's rustls integration instead of plain TCP.
    pub tls_cert_path: Option<PathBuf>,
    /// Optional TLS private-key PEM path paired with [`tls_cert_path`].
    pub tls_key_path: Option<PathBuf>,
    pub database_url: Option<String>,
    pub object_storage: ObjectStorageConfig,
    /// ICE/STUN/TURN servers and credential lifetimes advertised by the
    /// RTC ice-config endpoint. Externalized via `COLAND_ICE_*` /
    /// `COLAND_TURN_*` env vars; defaults preserve the historical
    /// hardcoded values.
    pub ice: IceServersConfig,
    /// LiveKit API Key/Secret for `bindings/livekit.md` §2 backend tokens.
    /// When set, the `livekit` media focus issues a standard LiveKit JWT
    /// (`HS256` over `header.payload`, signed with the API Secret) instead
    /// of failing closed. `COLAND_LIVEKIT_API_KEY` /
    /// `COLAND_LIVEKIT_API_SECRET` (secret also accepts `_FILE`). v1
    /// supports a single API Key/Secret pair; multi-deployment LiveKit
    /// (one pair per LiveKit cluster, keyed by focus `issuer_kid`) is a
    /// follow-up.
    pub livekit: LiveKitConfig,
    /// Media token issuance configuration for this deployment.
    ///
    /// It is deliberately configuration and not Realm state: the signed
    /// `ak.realm.media_service` cell describes which foci exist and where their
    /// token endpoints are, while the signing key and TTL belong to the service
    /// those endpoints name (`media-service-binding.md` §2).
    pub media: MediaIssuerConfig,
    /// Explicit comma-separated browser origin allowlist. Wildcards are invalid
    /// because this service also exposes authenticated protocol operations.
    pub cors_allow_origin: Option<String>,
    /// Public Account Authority base URL advertised to browser clients in
    /// `/_arkret/describe.auth_metadata.account_authority`. Registration,
    /// password recovery, passkey, OIDC, and email verification live there;
    /// coland consumes the resulting session grants and may expose DID provider
    /// primitives for trusted server-to-server calls.
    pub account_authority_url: Option<String>,
    /// Explicit delegation of the complete IVS lifecycle to this Station's
    /// Account Authority. Disabled deployments do not advertise or mount it.
    pub third_party_invite_provider_enabled: bool,
    /// Explicit destination trust domain for signed Station -> Account
    /// Authority requests. It is independent of the older shared-secret
    /// channel: RFC 9421 transport requires this value even when that channel
    /// is absent.
    pub account_authority_trust_domain: Option<TrustDomainId>,
    /// Public assertion key delegated in this Station's signed DID inception.
    /// Changing this pin requires an authorized DID history update.
    pub account_authority_public_key_multibase: Option<String>,
    /// OAuth/OIDC `client_id` this coland deployment is registered as at the
    /// Authentication Method Provider, advertised to browser clients in
    /// `/_arkret/describe.auth_metadata.methods[].oidc.client_id`. The web
    /// client uses it verbatim as the `client_id` in its OIDC authorize
    /// request; coauth keys clients by ULID, so this MUST be the registered
    /// client ULID (e.g. the dev `config.dev.yaml` client). When unset the
    /// OIDC method advertises no `client_id` and the client has nothing valid
    /// to fall back to.
    pub oidc_client_id: Option<String>,
    pub development_mode: bool,
    /// Typed fault-injection points for durable-workflow crash-consistency
    /// tests. Parsed once here from `COLAND_FAILPOINTS` and always empty
    /// unless `development_mode` is on. See [`crate::failpoints`].
    pub failpoints: crate::failpoints::FailpointRegistry,
    pub session_grant_introspection_url: Option<String>,
    /// Exact Account Authority process S2S hard-logout endpoint. This is intentionally
    /// independent from session-grant introspection: the two operations may
    /// be routed or versioned separately and must never be derived from one
    /// another by string substitution.
    pub auth_session_logout_url: Option<String>,
    pub internal_authority_shared_secret: Option<String>,
    /// The registered deployment-internal authenticated channel between this
    /// Station and its Account Authority (`sync/service-http-binding.md`
    /// §2.2.3), or `None` when no such channel is registered.
    ///
    /// Registering the channel adopts §2.2.3's deployment premise that every
    /// proxy which decrypts or forwards its plaintext is a trusted member of
    /// the same TCB. The application does not model or inspect the proxy chain.
    pub internal_authority_channel: Option<InternalAuthorityChannelConfig>,
    /// Target-local participation ceiling, independent of controller selection.
    pub agent_participation_ceiling:
        arkret_models_collaboration::governance::agent_participation::ParticipationBits,
    pub did_resolver_allow_methods: Vec<String>,
    /// Enable coland's built-in `did:webvh` provider. This is intended for
    /// ordinary self-hosted deployments and tests: coauth can discover it via
    /// `/_arkret/root/identity/describe`, register a user DID through coland, then
    /// resolve the resulting document through coland's local identity store.
    pub embedded_webvh_provider_enabled: bool,
    /// Shared bearer token required to write embedded `did:webvh` records.
    /// Read endpoints remain public because DID resolution needs them, but
    /// registration must be restricted to the trusted registration service
    /// (normally coauth).
    pub embedded_webvh_registration_bearer: Option<String>,
    /// Optional external `did:webvh` provider URL. This can point at any
    /// compatible provider. It records admin intent and is surfaced in
    /// `/identity/describe` even when the boot probe fails.
    pub external_webvh_provider_url: Option<String>,
    /// Registration credential for using the configured external WebVH
    /// service as this deployment's Service Identity Provider. When present,
    /// service identity is class-A/provider-backed and first provisioning does
    /// not require `COLAND_FIRST_PROVISIONING`.
    pub external_webvh_registration_bearer: Option<String>,
    /// Runtime liveness for the external provider. `true` only when the
    /// external provider's `/describe` probe succeeds at boot.
    pub external_webvh_provider_active: bool,
    /// Provider id coauth should preselect. When unset, coland chooses
    /// `coland.embedded` if the embedded provider is enabled, otherwise the
    /// first configured external provider.
    pub default_webvh_provider_id: Option<String>,
    /// Base64-encoded 32-byte ed25519 seed for the NotaryWorker
    /// signing identity (env `COLAND_NOTARY_SIGNING_KEY`). When `Some(_)`
    /// the worker uses a deterministic ed25519-dalek signing key derived
    /// from this seed; when `None` the worker boots with an in-process
    /// random ephemeral key and a sticky-warn log line on every signing
    /// pass, matching the [`NotarySigningKeyOrigin::Ephemeral`] branch.
    ///
    /// Loading is identical to coauth's session-grant signing-key pattern
    /// — the env var holds the raw seed, base64-standard-padded; bad shape
    /// fails fast at startup with a clear error.
    pub notary_signing_key_seed: Option<[u8; 32]>,
    /// Durable key custody shared by service identity, notary, and admin
    /// KeyStore namespaces. Signing and WebVH
    /// control secrets are addressed exclusively by the opaque KeyRefs in
    /// the verified `LocalDidCoreIdentity`; AppState neither derives a key id
    /// from the service DID nor independently mints a runtime signer.
    ///
    /// When disabled, an explicit `COLAND_NOTARY_SIGNING_KEY` may supply the
    /// signing secret, but WebVH control-key custody still requires a durable
    /// KeyStore. Service signing-key rotation fails closed until the WebVH
    /// history, DID document, stored identity, KeyStore, and recovery bundle
    /// can be updated as one recoverable transition.
    pub key_store: KeyStoreConfig,
    /// Federation fanout topology. The on-the-wire shape is `ak.peer.events.command.submit.v1`
    /// under `/_arkret/peer/events`; the topology only changes which peer set
    /// receives accepted Event fanout.
    ///
    /// - [`FederationFanoutTopology::Mesh`] — broadcast each accepted Event to every known peer.
    /// - [`FederationFanoutTopology::Hub`] — push only to a single configured upstream hub; rely
    ///   on the hub for outbound dissemination.
    pub federation_fanout_topology: FederationFanoutTopology,
    /// Federation peer endpoints the outbound layer considers as broadcast
    /// targets (mesh) or hub upstream (hub). The resolved form is
    /// `url|service_id|trust_domain`, where `service_id` is a `DidCoreId`.
    /// Endpoint-only entries are resolved
    /// through `/_arkret/describe`; the discovered service DID and trust
    /// domain are kept in runtime state rather than copied into deployment
    /// config. Sovereign outbound fails closed until that binding is present.
    /// Empty disables federation outbound.
    pub federation_peers: Vec<String>,
    /// Explicit onboarding trust roots for independently operated public Push
    /// Gateways.  Each entry binds one canonical HTTPS origin to the exact
    /// Gateway service DID and its current receipt assertion method/key.
    ///
    /// Env: `COLAND_TRUSTED_PUSH_GATEWAYS`, a closed JSON array.  This is not
    /// derived from `federation_peers`: that registry admits only Station peers
    /// and does not establish Push Gateway receipt trust.
    pub trusted_push_gateways: crate::push_gateway_registry::TrustedPushGatewayRegistry,
    /// G3.S0 — when true (default), `main.rs` spawns the
    /// `FederationDispatcher` background worker that drains the
    /// `federation_outbox` table and POSTs each pending row to its peer
    /// with `Idempotency-Key` + `Content-Digest` headers. Set
    /// `COLAND_FEDERATION_OUTBOUND=0` to disable for integration tests
    /// that don't want background HTTP traffic (the in-process `enqueue`
    /// path still writes outbox rows so cotest can observe the boundary).
    pub federation_outbound_enabled: bool,
    /// Maximum time the source Station waits for every affected Station to
    /// acknowledge an exact deactivation record before the mutable
    /// propagation projection becomes `incomplete`.
    /// Env: `COLAND_DEACTIVATION_PROPAGATION_WINDOW_MS` (default 86_400_000).
    pub deactivation_propagation_window_ms: u64,
    /// Cadence of the durable SecurityRotation worker sweep in seconds.
    /// Env: `COLAND_SECURITY_ROTATION_WORKER_INTERVAL_SECONDS` (default `5`,
    /// `1..=3600`).
    pub security_rotation_worker_interval_seconds: u64,
    /// Default page size for `GET /_coland/admin/cells` and the rest of
    /// the admin paginated read surfaces when the caller omits `limit`.
    /// Env: `COLAND_ADMIN_PAGE_LIMIT` (default `100`).
    pub admin_default_page_limit: usize,
    /// Hard cap on `limit` query for the admin paginated read surfaces;
    /// requests asking for a larger page are clamped down. Defends
    /// against a misbehaving client exhausting in-memory projection state.
    /// Env: `COLAND_ADMIN_MAX_PAGE_LIMIT` (default `1000`).
    pub admin_max_page_limit: usize,
    /// Stable principal IDs allowed to call `GET /_coland/admin/{resource}` and the
    /// other production-gated admin read surfaces when `development_mode` is
    /// false. Empty (default) keeps the previous "dev-mode only" posture for
    /// these endpoints. Env: `COLAND_ADMIN_PRINCIPAL_IDS` (comma-separated).
    pub admin_principal_ids: Vec<DidCoreId>,
    /// Maximum unacknowledged to-device messages retained per
    /// `(recipient_account_id, device_id)`. Older messages beyond this
    /// capacity are dropped, and the device lost watermark is advanced so the
    /// next to-device response can carry `lost=true`.
    /// Env: `COLAND_TO_DEVICE_QUEUE_CAPACITY` (default 10_000).
    pub to_device_queue_capacity: usize,
    /// Concurrent `ak.edge.applet.command.transaction.v1` deliveries this
    /// Station processes before shedding load with `queue_full`.
    /// Env: `COLAND_APPLET_TRANSACTION_INFLIGHT_CAPACITY` (default 64).
    pub applet_transaction_inflight_capacity: usize,
    /// Rolling-24h per-principal cap on full-ciphertext key-backup downloads
    /// (`key-management.md` §7.8), already clamped to the range
    /// `coland_services::runtime_guards` allows.
    /// Env: `COLAND_KEY_BACKUP_DAILY_DOWNLOAD_LIMIT`.
    pub key_backup_daily_download_limit: u32,
    /// Directory holding the service-identity bundle, when the deployment
    /// provisions identity from files rather than from the database.
    /// Env: `COLAND_SERVICE_IDENTITY_BUNDLE_DIR`.
    pub service_identity_bundle_dir: Option<String>,
    /// Path to the verified-profile artifact. Absence is the feature flag:
    /// no artifact keeps the dev-mode `verified_profiles = []` invariant.
    /// Env: `COLAND_VERIFIED_PROFILES_ARTIFACT`.
    pub verified_profiles_artifact: Option<String>,
    /// Trust domain the external webvh provider's `/describe` must present.
    /// Falls back to this deployment's own trust domain when unset.
    /// Env: `COLAND_EXTERNAL_WEBVH_PROVIDER_TRUST_DOMAIN`.
    pub external_webvh_provider_trust_domain: Option<String>,
    /// Per-class rate-limit ceilings, parsed once so the enforced quota and
    /// the ceilings `describe` advertises cannot disagree.
    /// Env: `COLAND_RATE_LIMIT_*`.
    pub rate_limiter: crate::ratelimit::RateLimiterConfig,
    /// Env: `COLAND_MAX_REQUEST_SIZE`, clamped up to the v1 interoperability
    /// floor.
    pub max_request_size_bytes: usize,
    /// Result of the deployment's PQ-hybrid TLS handshake probe.
    /// Env: `COLAND_PQ_TLS_DEPLOYMENT_PROBE`.
    pub pq_hybrid_tls_probe: Option<String>,
    /// Bounded drain: how long a graceful shutdown waits for in-flight
    /// requests. `None` keeps the "wait indefinitely" behaviour.
    /// Env: `COLAND_SHUTDOWN_GRACE_SECS`.
    pub shutdown_grace_seconds: Option<u64>,
    /// Maximum physical WebSocket lifetime before bounded drain (1..=600s).
    /// Env: `COLAND_WEBSOCKET_MAX_LIFETIME_SECS`.
    pub websocket_max_lifetime_seconds: u64,
    /// Resolved `RUST_LOG` directive.
    ///
    /// Resolved here rather than by `EnvFilter::from_default_env()` so a
    /// `RUST_LOG` supplied through `--config` is honoured: the file never
    /// reaches the process environment, so the subscriber cannot find it there.
    pub log_filter: Option<String>,
    /// Env: `COLAND_LOG_FILE`. Logs are teed to this path when set.
    pub log_file: Option<PathBuf>,
    /// OpenTelemetry export settings.
    pub otel: OtelConfig,
    /// Connection-pool sizing for the Postgres backend. Held as plain values
    /// rather than `coland_storage_postgres::PoolTuning` because `coland-http`
    /// must not depend on a storage backend; `coland-server` assembles them.
    /// Env: `COLAND_DB_POOL_MAX_SIZE`.
    pub db_pool_max_size: Option<usize>,
    /// Env: `COLAND_DB_POOL_ACQUIRE_TIMEOUT_SECS`.
    pub db_pool_acquire_timeout_seconds: Option<u64>,
    /// Base URL of the push gateway (floria) this deployment notifies over
    /// the registered internal channel when an account is deactivated
    /// (`account-lifecycle.md` §7.1, Push-route completion criterion). The fanout
    /// endpoint is derived by appending
    /// `floria_contracts::ACCOUNT_DEACTIVATE_FANOUT_PATH`.
    ///
    /// `None` (default) declares that this deployment has **no** independent
    /// push gateway holding registration/delivery state — the single-box /
    /// dev posture. In that posture the local push-route purge is the
    /// complete Push-route fanout action and `deactivation_partial` is never
    /// raised for the gateway leg. Deployments that run floria MUST set this,
    /// or the spec's gateway-side stop-delivery guarantee silently does not
    /// exist. Env: `COLAND_DEACTIVATION_PUSH_GATEWAY_URL`.
    pub deactivation_push_gateway_url: Option<String>,
    /// Bearer token for floria's `http.internal_auth` profile on the
    /// deactivation fanout endpoint. When the gateway URL is set but this is
    /// missing, the fanout is still attempted (and honestly fails with 401,
    /// keeping `deactivation_partial=true`) rather than being silently
    /// skipped. Env: `COLAND_DEACTIVATION_PUSH_GATEWAY_BEARER`.
    pub deactivation_push_gateway_bearer: Option<String>,
    /// Resumable (tus) blob upload — staging directory for in-progress
    /// upload parts before they are completed into the blob store. See
    /// spec crypto-media/media-and-blob.md §2.1.
    /// Env: `COLAND_RESUMABLE_UPLOAD_DIR` (default `./coland-resumable-uploads`).
    pub resumable_upload_dir: PathBuf,
    /// Resumable (tus) blob upload — maximum lifetime of an incomplete
    /// upload part, in seconds. Expired parts are garbage-collected and
    /// never produce a referencable `blob_ref`. Advertised in
    /// `describe.limits.resumable_upload_incomplete_ttl_seconds`.
    /// Env: `COLAND_RESUMABLE_UPLOAD_TTL_SECS` (default 86_400 = 24h).
    pub resumable_upload_incomplete_ttl_seconds: u64,
    /// Deployment trust domain id, used to bind peer authorization and
    /// recovery transcripts to this Station so the same proof bytes
    /// cannot be replayed cross-domain. Loaded from
    /// `COLAND_TRUST_DOMAIN` (must match `ak:trust_domain:<scope>`,
    /// scope = lowercase alphanumerics/dot/dash/underscore/colon ≤128 chars).
    /// This is explicit deployment identity configuration: a stable service
    /// core id cannot be reversed into a host or trust domain.
    pub trust_domain: TrustDomainId,
    /// Deployment/admin upper bound for invite/contact receive policies.
    /// Constraints can only reduce holder reachability. Loaded from
    /// `COLAND_RECEIVE_POLICY_*` env vars and advertised on ServiceDescribe.
    pub receive_policy_constraints: Option<arkret_wire::receive_policy::ReceivePolicyConstraints>,
    /// When true, `AppState::new` seeds a deterministic demo Realm
    /// (`ak:realm:<44-char event token>`), demo account (`did:web:alice.example`),
    /// and matching space_meta record on boot. Off by default so
    /// production deployments don't ship a globally-shared demo Realm
    /// that collides across federated peers. Test harnesses opt in via
    /// `test_config()` to keep their fixture IDs stable.
    /// Env: `COLAND_SEED_DEMO_DATA` (default false).
    pub seed_demo_data: bool,
    /// Enables the sovereign-enclave startup and egress security posture.
    /// Startup validates it through [`crate::security::assert_enclave_invariants`]:
    /// outbound federation OFF, DID resolver method allow-list
    /// non-empty, every outbound HTTP call gated through the shared
    /// [`crate::security`] egress validation layer.
    /// Env: `COLAND_SOVEREIGN_ENCLAVE` (default false).
    pub sovereign_enclave_enabled: bool,
    /// Host allow-list for outbound HTTP when the enclave security posture
    /// is enabled. Hosts are matched case-insensitively.
    /// Comma-separated env var
    /// `COLAND_SOVEREIGN_ENCLAVE_ALLOWED_OUTBOUND_HOSTS`.
    ///
    /// This is a read-back of the list
    /// [`crate::security::validate_url_for_egress`] enforces, not a parallel
    /// copy of it — see
    /// [`crate::security::sovereign_enclave_allowed_outbound_hosts`].
    pub sovereign_enclave_allowed_outbound_hosts: Vec<String>,
    /// P5 (5.4) — structured-logging output format. Defaults to
    /// [`LogFormat::Json`] in production (`COLAND_DEVELOPMENT_MODE=false`)
    /// and [`LogFormat::Plain`] in development. Override at any time via
    /// `COLAND_LOG_FORMAT=json|plain`. JSON output is the format on-call
    /// runbooks assume (the `runbook.md` log-search recipes use
    /// `jq`-friendly field names).
    pub log_format: LogFormat,
}

/// OpenTelemetry span export settings.
///
/// Parsed and validated with the rest of the configuration. The exporter is
/// built after `AppConfig` exists, so it has no reason to reach for the
/// process environment itself.
#[derive(Clone, Debug, PartialEq)]
pub struct OtelConfig {
    /// Env: `COLAND_OTEL_EXPORTER` — `otlp` / `1` / `true` enables export.
    pub exporter_enabled: bool,
    /// Env: `COLAND_OTEL_ENDPOINT`.
    pub endpoint: String,
    /// Env: `COLAND_OTEL_TIMEOUT_SECS`, at least 1.
    pub timeout_seconds: u64,
    /// Env: `COLAND_OTEL_SAMPLE_RATIO`, validated to `0.0..=1.0` at load.
    pub sample_ratio: f64,
    /// Env: `COLAND_OTEL_SERVICE_NAME`; the caller's default when unset.
    pub service_name: Option<String>,
}

impl Default for OtelConfig {
    fn default() -> Self {
        Self {
            exporter_enabled: false,
            endpoint: "http://127.0.0.1:4317".to_owned(),
            timeout_seconds: 3,
            sample_ratio: 1.0,
            service_name: None,
        }
    }
}

/// Tracing-subscriber output format. See [`AppConfig::log_format`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogFormat {
    /// Human-readable ANSI-decorated logs. Default in development mode.
    Plain,
    /// One JSON object per event. Default in production so
    /// log-aggregation pipelines (Loki, OpenSearch, Cloud Logging)
    /// see structured fields without bespoke parsers.
    Json,
}

impl LogFormat {
    fn from_values(values: &BTreeMap<String, String>, development_mode: bool) -> Self {
        match lookup(values, "COLAND_LOG_FORMAT").ok().as_deref() {
            Some("json") | Some("JSON") => LogFormat::Json,
            Some("plain") | Some("PLAIN") | Some("text") | Some("TEXT") => LogFormat::Plain,
            _ => {
                if development_mode {
                    LogFormat::Plain
                } else {
                    LogFormat::Json
                }
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObjectStorageConfig {
    Local {
        root: PathBuf,
        prefix: String,
    },
    S3Compatible {
        bucket: String,
        region: String,
        endpoint: Option<String>,
        access_key_id: Option<String>,
        secret_access_key: Option<String>,
        session_token: Option<String>,
        prefix: String,
        force_path_style: bool,
        allow_http: bool,
        skip_signature: bool,
    },
}

impl ObjectStorageConfig {
    pub fn local(root: impl Into<PathBuf>) -> Self {
        Self::Local {
            root: root.into(),
            prefix: String::new(),
        }
    }

    pub fn backend_name(&self) -> &'static str {
        match self {
            Self::Local { .. } => "local",
            Self::S3Compatible { .. } => "s3",
        }
    }

    pub fn log_target(&self) -> String {
        match self {
            Self::Local { root, prefix } => {
                if prefix.is_empty() {
                    root.display().to_string()
                } else {
                    format!("{}:{}", root.display(), prefix)
                }
            }
            Self::S3Compatible {
                bucket,
                endpoint,
                prefix,
                ..
            } => {
                let endpoint = endpoint.as_deref().unwrap_or("aws-region-endpoint");
                if prefix.is_empty() {
                    format!("{endpoint}/{bucket}")
                } else {
                    format!("{endpoint}/{bucket}/{prefix}")
                }
            }
        }
    }
}

/// ICE/STUN/TURN configuration advertised by
/// `POST /_arkret/self/rtc/ice-config`. Externalized from hardcoded
/// defaults so operators can point clients at their own STUN/TURN
/// infrastructure and tune credential lifetimes per deployment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IceServersConfig {
    /// STUN server URLs advertised to clients (e.g. `stun:host:3478`).
    pub stun_urls: Vec<String>,
    /// TURN server URLs advertised to clients (e.g.
    /// `turn:host:3478?transport=udp`).
    pub turn_urls: Vec<String>,
    /// Lifetime in seconds of an issued ICE configuration / TURN
    /// credential before clients must request a refresh.
    pub ttl_seconds: u32,
    /// Lead time in seconds before `ttl_seconds` at which clients should
    /// proactively refresh the ICE configuration.
    pub refresh_lead_seconds: u32,
    /// Rotation window in seconds for the TURN shared secret. Reserved for
    /// time-windowed TURN credential derivation.
    pub turn_secret_rotation_window_seconds: u64,
    /// Optional REST-style (draft-uberti) TURN shared secret. The advertised
    /// TURN credential is `base64(HMAC-SHA256(turn_shared_secret, username))`
    /// over the `<expiry-unix>:<pseudonym>` username, so an external coturn
    /// configured with the same secret validates it. When unset, a
    /// deployment-stable fallback derived from the notary signing seed is used.
    pub turn_shared_secret: Option<String>,
}

impl Default for IceServersConfig {
    fn default() -> Self {
        Self {
            stun_urls: vec!["stun:stun.l.google.com:19302".to_owned()],
            turn_urls: vec!["turn:turn.coland.local:3478?transport=udp".to_owned()],
            ttl_seconds: 300,
            refresh_lead_seconds: 75,
            turn_secret_rotation_window_seconds: 86_400,
            turn_shared_secret: None,
        }
    }
}

/// LiveKit API credentials used to mint `bindings/livekit.md` §2 backend
/// tokens (standard LiveKit JWT, `HS256` signed with the API Secret).
///
/// v1 carries a single `(api_key, api_secret)` pair. Deployments that run
/// multiple LiveKit clusters MUST map each focus `issuer_kid` to its own
/// API Key/Secret; that multi-pair mapping is intentionally deferred and a
/// single configured pair is matched against the focus `issuer_kid` at
/// sign time.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LiveKitConfig {
    /// LiveKit API Key. In the LiveKit binding the media focus
    /// `issuer_kid` is the LiveKit API Key; the token issuer fails closed
    /// when the focus-declared `issuer_kid` does not equal this value.
    pub api_key: Option<String>,
    /// LiveKit API Secret. HMAC-SHA256 signing key for the JWT. Never
    /// surfaced in any public cell, `/health`, or describe payload.
    pub api_secret: Option<String>,
}

/// Media token issuer configuration.
///
/// `media-service-binding.md` §3 anchors an issued token by requiring the bare
/// controller of `participant_binding.issuer_kid` to equal a current-epoch
/// `ak.realm.media_service.service_id`. The key itself is this deployment's,
/// so it is configured here: putting it in the Realm cell would make an issuer
/// key rotation require a capability-holding Realm Event and would publish
/// issuer internals to every member.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MediaIssuerConfig {
    /// DID URL (with verification-method fragment) this service signs media
    /// participant bindings with. Its bare controller MUST be a current-epoch
    /// `service_id`, which the token issuer re-checks before signing.
    pub issuer_kid: String,
    /// Issued token lifetime. `media-service-binding.md` §3 caps it at 600s and
    /// recommends 300s; the issuer clamps to the hard ceiling regardless.
    pub token_ttl_seconds: u64,
}

impl MediaIssuerConfig {
    #[cfg(any(test, feature = "test-support"))]
    fn test_default() -> Self {
        Self {
            issuer_kid: String::new(),
            token_ttl_seconds: arkret_wire::MEDIA_TOKEN_TTL_SHOULD_SECS,
        }
    }
}

/// Load the media issuer configuration. `issuer_kid` defaults to
/// `<service DID>#media-1` at request time when unset, so a single-key
/// deployment needs no extra environment variable.
fn load_media_issuer_config(values: &BTreeMap<String, String>) -> MediaIssuerConfig {
    MediaIssuerConfig {
        issuer_kid: env_non_empty(values, "COLAND_MEDIA_ISSUER_KID").unwrap_or_default(),
        token_ttl_seconds: env_non_empty(values, "COLAND_MEDIA_TOKEN_TTL_SECONDS")
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|ttl| *ttl > 0)
            .unwrap_or(arkret_wire::MEDIA_TOKEN_TTL_SHOULD_SECS),
    }
}

/// Load LiveKit API credentials. The secret accepts the `_FILE` indirection
/// so operators can mount it via Kubernetes / Docker / systemd secrets.
fn load_livekit_config(values: &BTreeMap<String, String>) -> LiveKitConfig {
    let api_key = env_non_empty(values, "COLAND_LIVEKIT_API_KEY");
    let api_secret = env_non_empty(values, "COLAND_LIVEKIT_API_SECRET");
    LiveKitConfig {
        api_key,
        api_secret,
    }
}

/// Federation fanout topology. Selected at config-load
/// time via `COLAND_FEDERATION_FANOUT_TOPOLOGY` env var (`mesh` | `hub`).
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, salvo::oapi::ToSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum FederationFanoutTopology {
    /// Default — broadcast every accepted Event to every peer in
    /// [`AppConfig::federation_peers`].
    Mesh,
    /// Push to a single upstream hub. The first entry in
    /// [`AppConfig::federation_peers`] is the hub.
    Hub,
}

impl FederationFanoutTopology {
    pub fn from_env_value(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "hub" => Self::Hub,
            _ => Self::Mesh,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Mesh => "mesh",
            Self::Hub => "hub",
        }
    }
}

/// Provenance tag for the NotaryWorker's signing key. Surfaced
/// on each signing pass so logs flag the dev-only ephemeral path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotarySigningKeyOrigin {
    /// Loaded from `COLAND_NOTARY_SIGNING_KEY` (production-grade
    /// persistent identity).
    Configured,
    /// In-process random seed — fine for tests, **never** for production:
    /// every restart changes the Station signer DID and breaks authority
    /// commit verification.
    Ephemeral,
}

impl AppConfig {
    /// Single source of truth for test configs. Defaults take the
    /// production posture (`development_mode = false`, per-family
    /// validation on, demo seeding off);
    /// individual tests opt into relaxed settings explicitly via
    /// struct-update syntax:
    ///
    /// ```ignore
    /// let config = AppConfig {
    ///     development_mode: true,
    ///     ..AppConfig::test_default()
    /// };
    /// ```
    #[cfg(any(test, feature = "test-support"))]
    pub fn test_default() -> Self {
        Self {
            bind: "127.0.0.1:0".parse().unwrap(),
            metrics_bind: "127.0.0.1:0".parse().unwrap(),
            public_base_url: "http://server".to_owned(),
            first_provisioning: false,
            tls_cert_path: None,
            tls_key_path: None,
            database_url: None,
            object_storage: ObjectStorageConfig::local(
                std::env::temp_dir().join("coland-test-blobs"),
            ),
            ice: IceServersConfig::default(),
            livekit: LiveKitConfig::default(),
            media: MediaIssuerConfig::test_default(),
            cors_allow_origin: None,
            account_authority_url: None,
            third_party_invite_provider_enabled: false,
            account_authority_trust_domain: None,
            account_authority_public_key_multibase: None,
            oidc_client_id: None,
            development_mode: false,
            failpoints: crate::failpoints::FailpointRegistry::disabled(),
            session_grant_introspection_url: None,
            auth_session_logout_url: None,
            internal_authority_shared_secret: None,
            internal_authority_channel: None,
            agent_participation_ceiling:
                arkret_models_collaboration::governance::agent_participation::ParticipationBits::ALL,
            // Test fixtures intentionally allow bare `did:web` — the spec
            // conformance vectors use it. The production default
            // (`default_did_resolver_allow_methods`) is webvh-only.
            did_resolver_allow_methods: vec!["web".to_owned(), "key".to_owned(), "uuid".to_owned()],
            embedded_webvh_provider_enabled: false,
            embedded_webvh_registration_bearer: None,
            external_webvh_provider_url: None,
            external_webvh_registration_bearer: None,
            external_webvh_provider_active: false,
            default_webvh_provider_id: None,
            notary_signing_key_seed: None,
            key_store: KeyStoreConfig::Disabled,
            federation_fanout_topology: FederationFanoutTopology::Mesh,
            federation_peers: Vec::new(),
            trusted_push_gateways:
                crate::push_gateway_registry::TrustedPushGatewayRegistry::default(),
            // Off so test binaries never spawn background federation HTTP
            // traffic; the in-process enqueue path still writes outbox rows.
            federation_outbound_enabled: false,
            deactivation_propagation_window_ms: 86_400_000,
            security_rotation_worker_interval_seconds: 5,
            admin_default_page_limit: 100,
            admin_max_page_limit: 1000,
            admin_principal_ids: Vec::new(),
            to_device_queue_capacity: 10_000,
            applet_transaction_inflight_capacity: DEFAULT_APPLET_TRANSACTION_INFLIGHT_CAPACITY,
            key_backup_daily_download_limit:
                coland_services::runtime_guards::clamp_key_backup_daily_download_limit(None),
            service_identity_bundle_dir: None,
            verified_profiles_artifact: None,
            external_webvh_provider_trust_domain: None,
            rate_limiter: crate::ratelimit::RateLimiterConfig::default(),
            max_request_size_bytes: DEFAULT_MAX_REQUEST_SIZE_BYTES,
            pq_hybrid_tls_probe: None,
            shutdown_grace_seconds: None,
            websocket_max_lifetime_seconds: 600,
            log_filter: None,
            log_file: None,
            otel: OtelConfig::default(),
            db_pool_max_size: None,
            db_pool_acquire_timeout_seconds: None,
            deactivation_push_gateway_url: None,
            deactivation_push_gateway_bearer: None,
            resumable_upload_dir: PathBuf::from("./coland-resumable-uploads"),
            resumable_upload_incomplete_ttl_seconds: 86_400,
            seed_demo_data: false,
            trust_domain: TrustDomainId::new("ak:trust_domain:coland.local")
                .expect("static trust domain"),
            receive_policy_constraints: None,
            sovereign_enclave_enabled: false,
            sovereign_enclave_allowed_outbound_hosts: Vec::new(),
            log_format: LogFormat::Plain,
        }
    }

    /// Register an internal authority channel in integration fixtures without
    /// exposing unchecked production constructors for the channel types.
    #[cfg(any(test, feature = "test-support"))]
    pub fn register_test_internal_authority_channel(&mut self, credential: impl Into<String>) {
        assert!(
            self.account_authority_url.is_some(),
            "test internal channel requires an Account Authority URL"
        );
        let credential = credential.into();
        self.account_authority_trust_domain = Some(self.trust_domain.clone());
        self.internal_authority_shared_secret = Some(credential.clone());
        self.internal_authority_channel = Some(InternalAuthorityChannelConfig {
            credential,
            account_authority_trust_domain: self.trust_domain.clone(),
            controller_gate_url: internal_authority_operation_url(
                self.account_authority_url
                    .as_deref()
                    .expect("checked above"),
                INTERNAL_CONTROLLER_GATE_PATH,
            )
            .expect("test Account Authority URL must be valid"),
        });
    }
}

impl AppConfig {
    /// Parse and validate deployment configuration from explicit values.
    ///
    /// Reading process arguments, environment variables and files belongs to
    /// the executable layer. This library function has no process-global input.
    pub fn from_values(
        values: &BTreeMap<String, String>,
        startup: StartupOverrides,
    ) -> anyhow::Result<Self> {
        let bind = startup
            .bind
            .or_else(|| lookup(values, "COLAND_BIND").ok())
            .unwrap_or_else(|| "127.0.0.1:8698".to_owned())
            .parse()?;
        let metrics_bind = lookup(values, "COLAND_METRICS_BIND")
            .unwrap_or_else(|_| "127.0.0.1:9090".to_owned())
            .parse()?;
        let public_base_url =
            lookup(values, "COLAND_PUBLIC_BASE_URL").unwrap_or_else(|_| format!("http://{bind}"));
        let first_provisioning = startup.first_provisioning
            || env_bool(values, "COLAND_FIRST_PROVISIONING")?.unwrap_or(false);
        let tls_cert_path = env_non_empty(values, "COLAND_TLS_CERT_PATH").map(PathBuf::from);
        let tls_key_path = env_non_empty(values, "COLAND_TLS_KEY_PATH").map(PathBuf::from);
        if tls_cert_path.is_some() != tls_key_path.is_some() {
            anyhow::bail!("COLAND_TLS_CERT_PATH and COLAND_TLS_KEY_PATH must be set together");
        }
        let database_url = lookup(values, "DATABASE_URL")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let object_storage = load_object_storage_config(values)?;
        let ice = load_ice_servers_config(values);
        let livekit = load_livekit_config(values);
        let media = load_media_issuer_config(values);
        let account_authority_url = env_non_empty(values, "COLAND_ACCOUNT_AUTHORITY_URL")
            .map(|value| {
                arkret_models_identity::service_identity::CanonicalServiceUrl::canonicalize(value)
                    .map(|url| url.as_str().to_owned())
                    .map_err(|error| {
                        anyhow::anyhow!("COLAND_ACCOUNT_AUTHORITY_URL is invalid: {error}")
                    })
            })
            .transpose()?;
        let account_authority_public_key_multibase =
            env_non_empty(values, "COLAND_ACCOUNT_AUTHORITY_PUBLIC_KEY_MULTIBASE");
        let third_party_invite_provider_enabled =
            env_bool(values, "COLAND_THIRD_PARTY_INVITE_PROVIDER_ENABLED")?.unwrap_or(false);
        if third_party_invite_provider_enabled && account_authority_url.is_none() {
            anyhow::bail!(
                "COLAND_THIRD_PARTY_INVITE_PROVIDER_ENABLED requires COLAND_ACCOUNT_AUTHORITY_URL"
            );
        }
        if let Some(key) = &account_authority_public_key_multibase {
            arkret_canonical::multibase::decode_ed25519_multibase(key).map_err(|error| {
                anyhow::anyhow!("COLAND_ACCOUNT_AUTHORITY_PUBLIC_KEY_MULTIBASE is invalid: {error}")
            })?;
        }
        // A separate Account Authority process still signs as this Station.
        // Its public key is delegated by the Station's signed DID history;
        // the optional key pin controls that delegation, not another identity.
        if account_authority_url.is_none() && account_authority_public_key_multibase.is_some() {
            anyhow::bail!(
                "COLAND_ACCOUNT_AUTHORITY_PUBLIC_KEY_MULTIBASE requires COLAND_ACCOUNT_AUTHORITY_URL"
            );
        }
        let oidc_client_id = env_non_empty(values, "COLAND_OAUTH_CLIENT_ID");
        // Formal signature and DID validation never depend on this flag.
        // Local network development must opt
        // in explicitly via `COLAND_DEVELOPMENT_MODE=true`.
        let development_mode = env_bool(values, "COLAND_DEVELOPMENT_MODE")?.unwrap_or(false);
        // Production first provisioning is authorized later, after the
        // durable identity stores are open, by `first_provisioning`.
        // Development mode may provision automatically. Config never carries
        // or pins the resulting DID (identity-did.md §3.7 I-2/I-3).
        // API conventions section 10 requires explicit origins for endpoints
        // carrying Authorization, device proof or session semantics. Development
        // mode has the same boundary; operators opt in to browser origins.
        let cors_allow_origin = lookup(values, "COLAND_CORS_ALLOW_ORIGIN")
            .ok()
            .map(|v| v.trim().to_owned())
            .filter(|v| !v.is_empty());
        if cors_allow_origin
            .as_deref()
            .is_some_and(|raw| raw.split(',').any(|origin| origin.trim() == "*"))
        {
            anyhow::bail!(
                "COLAND_CORS_ALLOW_ORIGIN requires explicit origins; wildcard is invalid"
            );
        }
        let session_grant_introspection_url =
            env_non_empty(values, "COLAND_SESSION_GRANT_INTROSPECTION_URL");
        let auth_session_logout_url = env_non_empty(values, "COLAND_AUTH_SESSION_LOGOUT_URL");
        if let Some(value) = auth_session_logout_url.as_deref() {
            validate_auth_session_logout_url(value)?;
        }
        let internal_authority_shared_secret =
            env_non_empty(values, "COLAND_INTERNAL_AUTHORITY_SHARED_SECRET");
        let account_authority_trust_domain =
            env_non_empty(values, "COLAND_ACCOUNT_AUTHORITY_TRUST_DOMAIN")
                .map(|value| {
                    TrustDomainId::new(value).map_err(|error| {
                anyhow::anyhow!(
                    "COLAND_ACCOUNT_AUTHORITY_TRUST_DOMAIN must be ak:trust_domain:<scope>: {error}"
                )
            })
                })
                .transpose()?;
        // `service-http-binding.md` §2.2.3 — register the deployment-internal
        // authenticated channel to this Station's Account Authority.
        //
        // All three inputs are required and none is guessed: the Account
        // Authority endpoint names the peer this channel is registered with,
        // its trust domain binds the source side independently from this
        // Station's destination trust domain, and the shared credential
        // authenticates it. Any one missing leaves the
        // channel unregistered, and the operations that travel on it then fail
        // closed rather than falling back to an anonymous or relaxed path.
        // There is deliberately no fallback to `describe`, a hostname-derived
        // trust domain, a first configured peer, or an unauthenticated call.
        //
        // The credential is the same per-edge secret the Account Authority
        // holds as `stations[].internal_authority_shared_secret`; both
        // directions of this one edge use it, exactly as coauth does. See
        // `AppConfig::internal_authority_channel` for what registering the
        // channel asserts about the link.
        let internal_authority_channel = match (
            account_authority_url.as_deref(),
            internal_authority_shared_secret.as_deref(),
            account_authority_trust_domain.as_ref(),
        ) {
            (Some(authority_url), Some(credential), Some(account_authority_trust_domain)) => {
                if let Some(introspection_url) = session_grant_introspection_url.as_deref() {
                    validate_internal_authority_endpoint_binding(
                        authority_url,
                        introspection_url,
                        "COLAND_SESSION_GRANT_INTROSPECTION_URL",
                        INTERNAL_SESSION_GRANT_INTROSPECTION_PATH,
                    )?;
                }
                if let Some(logout_url) = auth_session_logout_url.as_deref() {
                    validate_internal_authority_endpoint_binding(
                        authority_url,
                        logout_url,
                        "COLAND_AUTH_SESSION_LOGOUT_URL",
                        INTERNAL_AUTH_SESSION_LOGOUT_PATH,
                    )?;
                }
                Some(InternalAuthorityChannelConfig {
                    credential: credential.to_owned(),
                    account_authority_trust_domain: account_authority_trust_domain.clone(),
                    controller_gate_url: internal_authority_operation_url(
                        authority_url,
                        INTERNAL_CONTROLLER_GATE_PATH,
                    )?,
                })
            }
            _ => None,
        };
        let did_resolver_allow_methods = env_csv(values, "COLAND_DID_RESOLVER_ALLOW_METHODS")
            .unwrap_or_else(default_did_resolver_allow_methods);
        let embedded_webvh_provider_enabled =
            env_bool(values, "COLAND_EMBEDDED_WEBVH_PROVIDER_ENABLED")?.unwrap_or(true);
        let embedded_webvh_registration_bearer =
            env_non_empty(values, "COLAND_EMBEDDED_WEBVH_REGISTRATION_BEARER");
        let external_webvh_provider_url =
            env_non_empty(values, "COLAND_EXTERNAL_WEBVH_PROVIDER_URL");
        let external_webvh_registration_bearer =
            env_non_empty(values, "COLAND_EXTERNAL_WEBVH_REGISTRATION_BEARER");
        if external_webvh_registration_bearer.is_some() && external_webvh_provider_url.is_none() {
            anyhow::bail!(
                "COLAND_EXTERNAL_WEBVH_PROVIDER_URL is required when \
                 COLAND_EXTERNAL_WEBVH_REGISTRATION_BEARER is configured"
            );
        }
        let default_webvh_provider_id = env_non_empty(values, "COLAND_DEFAULT_WEBVH_PROVIDER_ID");
        let notary_signing_key_seed = load_notary_signing_key_seed(values)?;
        let key_store = KeyStoreConfig::from_values(values)?;
        validate_persistence_key_store(database_url.as_deref(), &key_store)?;
        // T2 — without a persistent notary seed (env or KeyStore) the worker
        // mints a fresh ephemeral ed25519 identity on every restart, which
        // breaks the authority signature chain. Match the `agent_audit_binding`
        // fail-fast posture; the notary key is at least as critical.
        if !development_mode && notary_signing_key_seed.is_none() && !key_store.is_durable() {
            anyhow::bail!(
                "COLAND_NOTARY_SIGNING_KEY (or a durable COLAND_KEYSTORE_BACKEND) is required when COLAND_DEVELOPMENT_MODE is false; an ephemeral notary key breaks the authority signature chain across restarts"
            );
        }
        let federation_fanout_topology = lookup(values, "COLAND_FEDERATION_FANOUT_TOPOLOGY")
            .ok()
            .map(|value| FederationFanoutTopology::from_env_value(&value))
            .unwrap_or(FederationFanoutTopology::Mesh);
        let federation_peers = lookup(values, "COLAND_FEDERATION_PEERS")
            .ok()
            .map(|value| {
                value
                    .split(',')
                    .map(|v| v.trim().to_owned())
                    .filter(|v| !v.is_empty())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let trusted_push_gateways = env_non_empty(values, "COLAND_TRUSTED_PUSH_GATEWAYS")
            .map(|value| {
                crate::push_gateway_registry::TrustedPushGatewayRegistry::from_json(&value).map_err(
                    |error| anyhow::anyhow!("COLAND_TRUSTED_PUSH_GATEWAYS is invalid: {error}"),
                )
            })
            .transpose()?
            .unwrap_or_default();
        // G3.S0 — outbound dispatcher toggle. Defaults to enabled so the
        // background worker drains the outbox; tests that don't want
        // unsolicited HTTP traffic set `COLAND_FEDERATION_OUTBOUND=0`.
        let federation_outbound_enabled =
            env_bool(values, "COLAND_FEDERATION_OUTBOUND")?.unwrap_or(true);
        let deactivation_propagation_window_ms = match lookup(
            values,
            "COLAND_DEACTIVATION_PROPAGATION_WINDOW_MS",
        ) {
            Ok(value) => value.trim().parse::<u64>().map_err(|error| {
                anyhow::anyhow!(
                    "COLAND_DEACTIVATION_PROPAGATION_WINDOW_MS must be a positive integer: {error}"
                )
            })?,
            Err(_) => 86_400_000,
        };
        if deactivation_propagation_window_ms == 0
            || deactivation_propagation_window_ms > i64::MAX as u64
        {
            anyhow::bail!(
                "COLAND_DEACTIVATION_PROPAGATION_WINDOW_MS must be in 1..={} milliseconds",
                i64::MAX
            );
        }
        let security_rotation_worker_interval_seconds =
            match env_non_empty(values, "COLAND_SECURITY_ROTATION_WORKER_INTERVAL_SECONDS") {
                None => 5,
                Some(raw) => raw
                    .trim()
                    .parse::<u64>()
                    .ok()
                    .filter(|seconds| (1..=3_600).contains(seconds))
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "COLAND_SECURITY_ROTATION_WORKER_INTERVAL_SECONDS must be in 1..=3600"
                        )
                    })?,
            };
        let admin_default_page_limit = lookup(values, "COLAND_ADMIN_PAGE_LIMIT")
            .ok()
            .and_then(|value| value.trim().parse::<usize>().ok())
            .filter(|n| *n > 0)
            .unwrap_or(100);
        let admin_max_page_limit = lookup(values, "COLAND_ADMIN_MAX_PAGE_LIMIT")
            .ok()
            .and_then(|value| value.trim().parse::<usize>().ok())
            .filter(|n| *n > 0)
            .unwrap_or(1000)
            .max(admin_default_page_limit);
        let admin_principal_ids = lookup(values, "COLAND_ADMIN_PRINCIPAL_IDS")
            .ok()
            .map(|value| {
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(|value| {
                        DidCoreId::new(value.to_owned()).map_err(|error| {
                            anyhow::anyhow!("COLAND_ADMIN_PRINCIPAL_IDS is invalid: {error}")
                        })
                    })
                    .collect::<anyhow::Result<Vec<_>>>()
            })
            .transpose()?
            .unwrap_or_default();
        let to_device_queue_capacity = lookup(values, "COLAND_TO_DEVICE_QUEUE_CAPACITY")
            .ok()
            .and_then(|value| value.trim().parse::<usize>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(DEFAULT_TO_DEVICE_QUEUE_CAPACITY);
        let applet_transaction_inflight_capacity =
            lookup(values, "COLAND_APPLET_TRANSACTION_INFLIGHT_CAPACITY")
                .ok()
                .and_then(|value| value.trim().parse::<usize>().ok())
                .filter(|value| *value > 0)
                .unwrap_or(DEFAULT_APPLET_TRANSACTION_INFLIGHT_CAPACITY);
        // Parsed here, clamped by the guard that owns the range. Previously
        // `runtime_guards` read this from the environment itself, which put an
        // env read inside `coland-services`.
        let key_backup_daily_download_limit =
            coland_services::runtime_guards::clamp_key_backup_daily_download_limit(
                env_non_empty(values, "COLAND_KEY_BACKUP_DAILY_DOWNLOAD_LIMIT")
                    .and_then(|value| value.parse::<u32>().ok()),
            );
        let service_identity_bundle_dir =
            env_non_empty(values, "COLAND_SERVICE_IDENTITY_BUNDLE_DIR");
        let verified_profiles_artifact = env_non_empty(values, "COLAND_VERIFIED_PROFILES_ARTIFACT");
        let external_webvh_provider_trust_domain =
            env_non_empty(values, "COLAND_EXTERNAL_WEBVH_PROVIDER_TRUST_DOMAIN");
        let rate_limiter = crate::ratelimit::RateLimiterConfig::resolve(
            development_mode,
            crate::ratelimit::RateLimitOverrides {
                window_seconds: rate_limit_override(values, "COLAND_RATE_LIMIT_WINDOW_SECONDS"),
                default_per_minute: rate_limit_override(
                    values,
                    "COLAND_RATE_LIMIT_DEFAULT_PER_MINUTE",
                ),
                auth_per_minute: rate_limit_override(values, "COLAND_RATE_LIMIT_AUTH_PER_MINUTE"),
                api_per_minute: rate_limit_override(values, "COLAND_RATE_LIMIT_API_PER_MINUTE"),
                probe_per_minute: rate_limit_override(values, "COLAND_RATE_LIMIT_PROBE_PER_MINUTE"),
            },
        );
        let max_request_size_bytes = Self::max_request_size_bytes(values);
        let pq_hybrid_tls_probe = env_non_empty(values, PQ_HYBRID_TLS_DEPLOYMENT_PROBE_ENV);
        let shutdown_grace_seconds = env_non_empty(values, "COLAND_SHUTDOWN_GRACE_SECS")
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|secs| *secs > 0);
        let log_filter = env_non_empty(values, "RUST_LOG");
        let websocket_max_lifetime_seconds =
            env_non_empty(values, "COLAND_WEBSOCKET_MAX_LIFETIME_SECS")
                .map(|value| value.parse::<u64>())
                .transpose()
                .map_err(|_| {
                    anyhow::anyhow!("COLAND_WEBSOCKET_MAX_LIFETIME_SECS must be an integer")
                })?
                .unwrap_or(600)
                .clamp(1, 600);
        let log_file = env_non_empty(values, "COLAND_LOG_FILE").map(PathBuf::from);
        let otel = load_otel_config(values)?;
        let db_pool_max_size = env_non_empty(values, "COLAND_DB_POOL_MAX_SIZE")
            .and_then(|value| value.parse::<usize>().ok());
        let db_pool_acquire_timeout_seconds =
            env_non_empty(values, "COLAND_DB_POOL_ACQUIRE_TIMEOUT_SECS")
                .and_then(|value| value.parse::<u64>().ok());
        let deactivation_push_gateway_url =
            env_non_empty(values, "COLAND_DEACTIVATION_PUSH_GATEWAY_URL");
        let deactivation_push_gateway_bearer =
            env_non_empty(values, "COLAND_DEACTIVATION_PUSH_GATEWAY_BEARER");
        if deactivation_push_gateway_url.is_none() && deactivation_push_gateway_bearer.is_some() {
            anyhow::bail!(
                "COLAND_DEACTIVATION_PUSH_GATEWAY_BEARER is set without COLAND_DEACTIVATION_PUSH_GATEWAY_URL"
            );
        }
        let resumable_upload_dir = env_non_empty(values, "COLAND_RESUMABLE_UPLOAD_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("./coland-resumable-uploads"));
        let resumable_upload_incomplete_ttl_seconds =
            lookup(values, "COLAND_RESUMABLE_UPLOAD_TTL_SECS")
                .ok()
                .and_then(|value| value.trim().parse::<u64>().ok())
                .unwrap_or(86_400)
                .max(60);
        let seed_demo_data = env_bool(values, "COLAND_SEED_DEMO_DATA")?.unwrap_or(false);
        // G3.S9 — sovereign enclave toggle + outbound host allow-list.
        //
        // This is now the only parse of every egress input. `security.rs` used
        // to read the same eight variables itself with a stricter, case-
        // sensitive matcher, so `COLAND_SOVEREIGN_ENCLAVE=on` turned the
        // enclave on here and left the outbound gate off there. The parsed
        // policy is installed into the gate by `install_egress_policy` at
        // startup; both sides now read one value.
        let sovereign_enclave_enabled =
            env_bool(values, "COLAND_SOVEREIGN_ENCLAVE")?.unwrap_or(false);
        let egress_policy = crate::security::EgressPolicy {
            allow_private_networks: env_bool(values, "COLAND_EGRESS_ALLOW_PRIVATE_NETWORKS")?,
            allowed_hosts: crate::security::split_host_policy_entries(
                env_non_empty(values, "COLAND_EGRESS_ALLOWED_HOSTS").as_deref(),
            ),
            denylist: crate::security::split_host_policy_entries(
                env_non_empty(values, "COLAND_EGRESS_DENYLIST").as_deref(),
            ),
            federation_denylist: crate::security::split_federation_denylist_entries(&[
                env_non_empty(values, "COLAND_FEDERATION_DENYLIST").as_deref(),
                env_non_empty(values, "COLAND_FEDERATION_PEER_DENYLIST").as_deref(),
            ]),
            federation_trust_domain_allowlist: crate::security::split_host_policy_entries(
                env_non_empty(values, "COLAND_FEDERATION_TRUST_DOMAIN_ALLOWLIST").as_deref(),
            ),
            sovereign_enclave_enabled,
            sovereign_enclave_allowed_outbound_hosts: crate::security::split_host_policy_entries(
                env_non_empty(values, "COLAND_SOVEREIGN_ENCLAVE_ALLOWED_OUTBOUND_HOSTS").as_deref(),
            ),
        };
        let sovereign_enclave_allowed_outbound_hosts = egress_policy
            .sovereign_enclave_allowed_outbound_hosts
            .clone();
        crate::security::install_egress_policy(egress_policy);
        crate::ratelimit::install_forwarded_for_trust(
            env_bool(values, "COLAND_RATE_LIMIT_TRUST_X_FORWARDED_FOR")?.unwrap_or(false),
        );
        let trust_domain = env_non_empty(values, "COLAND_TRUST_DOMAIN").ok_or_else(|| {
            anyhow::anyhow!(
                "COLAND_TRUST_DOMAIN is required; it cannot be derived from the service core id"
            )
        })?;
        let trust_domain = TrustDomainId::new(trust_domain).map_err(|error| {
            anyhow::anyhow!("COLAND_TRUST_DOMAIN must be ak:trust_domain:<scope>: {error}")
        })?;
        let receive_policy_constraints = load_receive_policy_constraints(values)?;
        let failpoints = crate::failpoints::FailpointRegistry::parse(
            env_non_empty(values, crate::failpoints::FAILPOINTS_ENV).as_deref(),
            development_mode,
        )?;
        let log_format = LogFormat::from_values(values, development_mode);

        Ok(Self {
            bind,
            metrics_bind,
            public_base_url,
            first_provisioning,
            tls_cert_path,
            tls_key_path,
            database_url,
            object_storage,
            ice,
            livekit,
            media,
            cors_allow_origin,
            account_authority_url,
            third_party_invite_provider_enabled,
            account_authority_trust_domain,
            account_authority_public_key_multibase,
            oidc_client_id,
            development_mode,
            failpoints,
            session_grant_introspection_url,
            auth_session_logout_url,
            internal_authority_shared_secret,
            internal_authority_channel,
            agent_participation_ceiling: env_non_empty(values, "COLAND_AGENT_PARTICIPATION_CEILING").map(|value| serde_json::from_str(&value)).transpose()?.unwrap_or(arkret_models_collaboration::governance::agent_participation::ParticipationBits::ALL),
            did_resolver_allow_methods,
            embedded_webvh_provider_enabled,
            embedded_webvh_registration_bearer,
            external_webvh_provider_url,
            external_webvh_registration_bearer,
            // `main.rs` flips this to true after a successful boot probe.
            external_webvh_provider_active: false,
            default_webvh_provider_id,
            notary_signing_key_seed,
            key_store,
            federation_fanout_topology,
            federation_peers,
            trusted_push_gateways,
            federation_outbound_enabled,
            deactivation_propagation_window_ms,
            security_rotation_worker_interval_seconds,
            admin_default_page_limit,
            admin_max_page_limit,
            admin_principal_ids,
            to_device_queue_capacity,
            applet_transaction_inflight_capacity,
            key_backup_daily_download_limit,
            service_identity_bundle_dir,
            verified_profiles_artifact,
            external_webvh_provider_trust_domain,
            rate_limiter,
            max_request_size_bytes,
            pq_hybrid_tls_probe,
            shutdown_grace_seconds,
            websocket_max_lifetime_seconds,
            log_filter,
            log_file,
            otel,
            db_pool_max_size,
            db_pool_acquire_timeout_seconds,
            deactivation_push_gateway_url,
            deactivation_push_gateway_bearer,
            resumable_upload_dir,
            resumable_upload_incomplete_ttl_seconds,
            seed_demo_data,
            trust_domain,
            receive_policy_constraints,
            sovereign_enclave_enabled,
            sovereign_enclave_allowed_outbound_hosts,
            log_format,
        })
    }

    /// Maximum bytes Salvo will read from a request body before returning
    /// `413 Payload Too Large`. Env: `COLAND_MAX_REQUEST_SIZE`, in bytes.
    ///
    /// The env override may only raise the bound. `scalability-constraints.md` §2.1.6 makes
    /// 16 MiB a fixed interoperability constant that a deployment or proxy MUST NOT declare
    /// lower, so a smaller value is clamped back up instead of silently making this service
    /// reject requests every other v1 service accepts.
    fn max_request_size_bytes(values: &BTreeMap<String, String>) -> usize {
        lookup(values, "COLAND_MAX_REQUEST_SIZE")
            .ok()
            .and_then(|value| value.trim().parse::<usize>().ok())
            .filter(|value| *value > 0)
            .map(|value| value.max(DEFAULT_MAX_REQUEST_SIZE_BYTES))
            .unwrap_or(DEFAULT_MAX_REQUEST_SIZE_BYTES)
    }

    /// Returns true when `actor` is configured as an admin principal in
    /// production mode via `COLAND_ADMIN_PRINCIPAL_IDS`.
    pub fn is_admin_principal(&self, actor: &str) -> bool {
        self.admin_principal_ids
            .iter()
            .any(|configured| configured.as_str() == actor)
    }

    /// Derive the effective admin-API authentication posture from the
    /// current config. Returned values are stable strings safe to surface
    /// in `/health` and the coland-local `/_coland/describe`:
    ///
    ///   - `"development"` — an explicit harness build with `COLAND_DEVELOPMENT_MODE=true`; a local
    ///     harness session may call admin endpoints.
    ///   - `"principal_id_allowlist"` — production mode, `COLAND_ADMIN_PRINCIPAL_IDS` is non-empty;
    ///     admin endpoints accept calls whose session actor appears in the allowlist.
    ///   - `"closed"` — production mode with neither admin allowlist nor introspection configured;
    ///     admin endpoints are effectively locked.
    pub fn admin_auth_mode(&self) -> &'static str {
        if self.development_harness_enabled() {
            "development"
        } else if !self.admin_principal_ids.is_empty() {
            "principal_id_allowlist"
        } else {
            "closed"
        }
    }

    /// The formal verifier always validates cryptographic proofs and rejects
    /// registered public test material, including inside a harness build.
    #[inline]
    pub fn proof_verifier_mode(&self) -> &'static str {
        "production"
    }

    /// Synthetic local credentials exist only in an isolated harness build.
    /// Development network and diagnostic settings do not enable them.
    #[inline]
    pub fn development_harness_enabled(&self) -> bool {
        cfg!(any(test, feature = "conformance-harness")) && self.development_mode
    }

    #[inline]
    pub fn tls_enabled(&self) -> bool {
        self.tls_cert_path.is_some() && self.tls_key_path.is_some()
    }

    pub fn pq_hybrid_tls_probe_verified_from_value(value: Option<&str>) -> bool {
        let Some(value) = value else {
            return false;
        };
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "verified" | "x25519mlkem768" | "tls13+x25519mlkem768"
        )
    }

    pub fn pq_hybrid_tls_probe_verified(&self) -> bool {
        Self::pq_hybrid_tls_probe_verified_from_value(self.pq_hybrid_tls_probe.as_deref())
    }

    pub fn pq_hybrid_tls_probe_configured(&self) -> bool {
        self.pq_hybrid_tls_probe.is_some()
    }

    pub fn pq_hybrid_tls_ready(&self) -> bool {
        self.development_mode || self.pq_hybrid_tls_probe_verified()
    }

    /// T8.3 — derive a non-sensitive production hardening snapshot from
    /// the live config. Values are environment-detected (no operator
    /// hand-holding required); `warnings[]` enumerates the failing
    /// checklist items so codmin can render them inline.
    ///
    /// The returned struct deliberately keeps only booleans / coarse
    /// enums — no secret material, URLs, paths, or token tails — so it
    /// is safe to publish on the unauthenticated `/health` endpoint.
    pub fn hardening_status(&self) -> crate::wire::HardeningStatus {
        let development_mode = self.development_mode;
        let tls_enabled = self.tls_enabled();
        let pq_hybrid_tls_required_group =
            coland_services::protocol_artifacts::pq_hybrid_tls_required_group();
        let pq_hybrid_tls_probe_artifact =
            coland_services::protocol_artifacts::PQ_HYBRID_TLS_DEPLOYMENT_PROBE_ARTIFACT_REF;
        let pq_hybrid_tls_probe_verified = self.pq_hybrid_tls_probe_verified();
        // CSP is enforced upstream by the reverse proxy (Caddyfile /
        // nginx); we can't probe the live header from inside the app,
        // but a configured `cors_allow_origin` is a strong signal that
        // the operator has wired up the proxy layer for browser clients.
        let csp_header_configured = self.cors_allow_origin.is_some();
        // CORS is "strict" when it is either unset (no cross-origin
        // browser access) or set to a concrete origin list rather than
        // the `*` wildcard.
        let cors_strict = match self.cors_allow_origin.as_deref() {
            None => true,
            Some(value) => !value.trim().split(',').any(|origin| origin.trim() == "*"),
        };
        // A configured durable KeyStore or an explicit signing seed is the
        // minimum acceptable production posture.
        let secret_manager_in_use =
            self.notary_signing_key_seed.is_some() || self.key_store.is_durable();
        // Log redaction is structurally enforced by the tracing layer
        // (no PII fields are logged at INFO); we report true unless dev
        // mode flips us into the chatty path.
        let log_redaction_enabled = !development_mode;
        let admin_auth_mode = self.admin_auth_mode().to_owned();
        // The rate limiter middleware is unconditionally installed by
        // `router()` in every mode (only the per-class ceilings vary with the
        // deployment posture; see `crate::ratelimit::RateLimiterConfig::from_env`).
        let rate_limit_enabled = true;
        // Provider credential rotation: coland's only signing identity
        // is the notary key; rotation is manual today. The KeyStore
        // path is the closest thing to "scheduled" we ship.
        let provider_credential_rotation = if self.key_store.is_durable() {
            "scheduled".to_owned()
        } else if self.notary_signing_key_seed.is_some() {
            "manual".to_owned()
        } else {
            "none".to_owned()
        };

        let checks = [
            ("development_mode_disabled", !development_mode),
            ("tls_enabled", tls_enabled),
            ("pq_hybrid_tls_probe_verified", pq_hybrid_tls_probe_verified),
            ("csp_header_configured", csp_header_configured),
            ("cors_strict", cors_strict),
            ("secret_manager_in_use", secret_manager_in_use),
            ("log_redaction_enabled", log_redaction_enabled),
            (
                "admin_auth_mode_production",
                admin_auth_mode != "development",
            ),
            ("rate_limit_enabled", rate_limit_enabled),
            (
                "provider_credential_rotation",
                provider_credential_rotation != "none",
            ),
            (
                "demo_data_disabled",
                !self.seed_demo_data || development_mode,
            ),
        ];
        let checklist_max = checks.len() as u32;
        let mut checklist_score: u32 = 0;
        let mut warnings: Vec<String> = Vec::new();
        for (label, ok) in checks {
            if ok {
                checklist_score += 1;
            } else {
                warnings.push((*label).to_owned());
            }
        }

        // T4 — advisory (non-scored) ICE/TURN posture. A production
        // deployment still advertising the built-in placeholders has no
        // working relay (placeholder TURN host does not resolve) or leaks
        // candidate gathering to a third party (Google public STUN). These
        // do not lower the checklist score — they are operational hints —
        // but they surface on `/health` so operators notice unset RTC infra.
        if !development_mode {
            if self.ice.stun_urls.iter().any(|u| u == PLACEHOLDER_STUN_URL) {
                warnings.push("ice_stun_placeholder".to_owned());
            }
            if self
                .ice
                .turn_urls
                .iter()
                .any(|u| u.contains(PLACEHOLDER_TURN_HOST))
            {
                warnings.push("ice_turn_placeholder".to_owned());
            }
        }

        crate::wire::HardeningStatus {
            development_mode,
            tls_enabled,
            pq_hybrid_tls_required_group: pq_hybrid_tls_required_group.to_owned(),
            pq_hybrid_tls_probe_artifact: pq_hybrid_tls_probe_artifact.to_owned(),
            pq_hybrid_tls_probe_verified,
            csp_header_configured,
            cors_strict,
            secret_manager_in_use,
            log_redaction_enabled,
            admin_auth_mode,
            rate_limit_enabled,
            provider_credential_rotation,
            checklist_score,
            checklist_max,
            warnings,
        }
    }
}

const INTERNAL_SESSION_GRANT_INTROSPECTION_PATH: &str =
    "/_coauth/internal/session-grants/introspect";
const INTERNAL_AUTH_SESSION_LOGOUT_PATH: &str = "/_coauth/internal/auth-sessions/logout";
const INTERNAL_CONTROLLER_GATE_PATH: &str = "/_coauth/internal/controller-gate-attestations";

fn parse_internal_authority_operation_url(
    value: &str,
    env_name: &str,
    expected_path: &str,
) -> anyhow::Result<url::Url> {
    let parsed = url::Url::parse(value)
        .map_err(|error| anyhow::anyhow!("{env_name} is invalid: {error}"))?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path() != expected_path
    {
        anyhow::bail!(
            "{env_name} must be an http(s) URL with a host, without credentials, query, or fragment, and with exact path {expected_path}"
        );
    }
    Ok(parsed)
}

fn validate_auth_session_logout_url(value: &str) -> anyhow::Result<()> {
    parse_internal_authority_operation_url(
        value,
        "COLAND_AUTH_SESSION_LOGOUT_URL",
        INTERNAL_AUTH_SESSION_LOGOUT_PATH,
    )
    .map(|_| ())
}

fn validate_internal_authority_endpoint_binding(
    authority_url: &str,
    operation_url: &str,
    env_name: &str,
    expected_path: &str,
) -> anyhow::Result<()> {
    let authority = url::Url::parse(authority_url).map_err(|error| {
        anyhow::anyhow!("canonical COLAND_ACCOUNT_AUTHORITY_URL is invalid: {error}")
    })?;
    let operation = parse_internal_authority_operation_url(operation_url, env_name, expected_path)?;
    anyhow::ensure!(
        operation.origin() == authority.origin(),
        "{env_name} must have the same scheme, host, and effective port as COLAND_ACCOUNT_AUTHORITY_URL"
    );
    Ok(())
}

fn internal_authority_operation_url(
    authority_url: &str,
    expected_path: &str,
) -> anyhow::Result<String> {
    let authority = url::Url::parse(authority_url).map_err(|error| {
        anyhow::anyhow!("canonical COLAND_ACCOUNT_AUTHORITY_URL is invalid: {error}")
    })?;
    let target = authority.join(expected_path).map_err(|error| {
        anyhow::anyhow!("Account Authority operation URL cannot be derived: {error}")
    })?;
    parse_internal_authority_operation_url(
        target.as_str(),
        "derived Account Authority operation URL",
        expected_path,
    )?;
    Ok(target.to_string())
}

fn load_object_storage_config(
    values: &BTreeMap<String, String>,
) -> anyhow::Result<ObjectStorageConfig> {
    let backend = env_non_empty(values, "COLAND_OBJECT_STORAGE_BACKEND")
        .unwrap_or_else(|| "local".to_owned())
        .to_ascii_lowercase();
    let prefix = normalized_storage_prefix(env_non_empty(values, "COLAND_OBJECT_STORAGE_PREFIX"));
    match backend.as_str() {
        "local" | "fs" | "filesystem" => {
            let root = env_non_empty(values, "COLAND_OBJECT_STORAGE_LOCAL_ROOT")
                .map(PathBuf::from)
                .unwrap_or_else(|| std::env::temp_dir().join("coland-objects"));
            Ok(ObjectStorageConfig::Local { root, prefix })
        }
        "s3" | "s3-compatible" | "s3_compatible" => {
            let bucket = required_env(values, "COLAND_OBJECT_STORAGE_S3_BUCKET")?;
            let region = env_non_empty(values, "COLAND_OBJECT_STORAGE_S3_REGION")
                .unwrap_or_else(|| "us-east-1".to_owned());
            let access_key_id = env_non_empty(values, "COLAND_OBJECT_STORAGE_S3_ACCESS_KEY_ID");
            let secret_access_key =
                env_non_empty(values, "COLAND_OBJECT_STORAGE_S3_SECRET_ACCESS_KEY");
            if access_key_id.is_some() != secret_access_key.is_some() {
                anyhow::bail!(
                    "COLAND_OBJECT_STORAGE_S3_ACCESS_KEY_ID and COLAND_OBJECT_STORAGE_S3_SECRET_ACCESS_KEY must be set together"
                );
            }
            Ok(ObjectStorageConfig::S3Compatible {
                bucket,
                region,
                endpoint: env_non_empty(values, "COLAND_OBJECT_STORAGE_S3_ENDPOINT"),
                access_key_id,
                secret_access_key,
                session_token: env_non_empty(values, "COLAND_OBJECT_STORAGE_S3_SESSION_TOKEN"),
                prefix,
                force_path_style: env_bool(values, "COLAND_OBJECT_STORAGE_S3_FORCE_PATH_STYLE")?
                    .unwrap_or(true),
                allow_http: env_bool(values, "COLAND_OBJECT_STORAGE_S3_ALLOW_HTTP")?
                    .unwrap_or(false),
                skip_signature: env_bool(values, "COLAND_OBJECT_STORAGE_S3_SKIP_SIGNATURE")?
                    .unwrap_or(false),
            })
        }
        other => anyhow::bail!(
            "COLAND_OBJECT_STORAGE_BACKEND must be local or s3-compatible, got {other}"
        ),
    }
}

/// Load ICE/STUN/TURN configuration from `COLAND_ICE_*` / `COLAND_TURN_*`
/// env vars. Each field falls back to the corresponding
/// [`IceServersConfig::default`] value when its env var is absent or empty,
/// preserving the historical hardcoded behavior.
fn load_ice_servers_config(values: &BTreeMap<String, String>) -> IceServersConfig {
    IceServersConfig::resolve(
        env_non_empty(values, "COLAND_ICE_STUN_URLS").as_deref(),
        env_non_empty(values, "COLAND_TURN_URLS").as_deref(),
        env_non_empty(values, "COLAND_ICE_TTL_SECONDS").as_deref(),
        env_non_empty(values, "COLAND_ICE_REFRESH_LEAD_SECONDS").as_deref(),
        env_non_empty(values, "COLAND_TURN_SECRET_ROTATION_WINDOW_SECS").as_deref(),
        env_non_empty(values, "COLAND_TURN_SHARED_SECRET"),
    )
}

impl IceServersConfig {
    /// Apply the configured values over [`Self::default`].
    ///
    /// Takes the values themselves rather than reading them, so the fallback
    /// rules are testable without any ambient state.
    fn resolve(
        stun_urls: Option<&str>,
        turn_urls: Option<&str>,
        ttl_seconds: Option<&str>,
        refresh_lead_seconds: Option<&str>,
        turn_secret_rotation_window_seconds: Option<&str>,
        turn_shared_secret: Option<String>,
    ) -> Self {
        let defaults = Self::default();
        let url_list = |raw: Option<&str>, fallback: Vec<String>| -> Vec<String> {
            match raw {
                Some(raw) => {
                    let parsed = raw
                        .split(',')
                        .map(|part| part.trim().to_owned())
                        .filter(|part| !part.is_empty())
                        .collect::<Vec<_>>();
                    if parsed.is_empty() { fallback } else { parsed }
                }
                None => fallback,
            }
        };
        Self {
            stun_urls: url_list(stun_urls, defaults.stun_urls),
            turn_urls: url_list(turn_urls, defaults.turn_urls),
            ttl_seconds: ttl_seconds
                .and_then(|value| value.parse::<u32>().ok())
                .filter(|value| *value > 0)
                .unwrap_or(defaults.ttl_seconds),
            refresh_lead_seconds: refresh_lead_seconds
                .and_then(|value| value.parse::<u32>().ok())
                .unwrap_or(defaults.refresh_lead_seconds),
            turn_secret_rotation_window_seconds: turn_secret_rotation_window_seconds
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(defaults.turn_secret_rotation_window_seconds),
            turn_shared_secret,
        }
    }
}

fn normalized_storage_prefix(prefix: Option<String>) -> String {
    prefix
        .map(|value| {
            value
                .trim()
                .trim_matches('/')
                .split('/')
                .filter(|part| !part.is_empty())
                .collect::<Vec<_>>()
                .join("/")
        })
        .unwrap_or_default()
}

/// Load the NotaryWorker signing seed from
/// `COLAND_NOTARY_SIGNING_KEY` (base64-standard encoded 32 bytes).
/// Returns `Ok(None)` when the env var is absent or empty (the
/// NotaryWorker then mints an ephemeral key with a sticky-warn).
/// Returns `Err(_)` when the env var is set but malformed — fail-fast at
/// startup rather than silently downgrading to ephemeral.
fn load_notary_signing_key_seed(
    values: &BTreeMap<String, String>,
) -> anyhow::Result<Option<[u8; 32]>> {
    let raw = match lookup(values, "COLAND_NOTARY_SIGNING_KEY") {
        Ok(value) => value.trim().to_owned(),
        Err(_) => return Ok(None),
    };
    if raw.is_empty() {
        return Ok(None);
    }
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(raw.as_bytes())
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(raw.as_bytes()))
        .map_err(|e| {
            anyhow::anyhow!(
                "COLAND_NOTARY_SIGNING_KEY must be base64 (standard or url-safe-no-pad): {e}"
            )
        })?;
    if bytes.len() != 32 {
        anyhow::bail!(
            "COLAND_NOTARY_SIGNING_KEY must decode to exactly 32 bytes (got {})",
            bytes.len()
        );
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    Ok(Some(seed))
}

/// Deployment carrier for the per-holder new-source quota
/// (`identity/consent-model.md` section 6.1.1.1).
///
/// An omitted variable is NOT "quota off": the omitted member simply falls back
/// to the specification default inside
/// `NewSourceQuotaConstraints::effective`, because the quota itself is a MUST.
/// Declaring the values here is what makes them reachable from `describe`,
/// which is the only place a holder UI can learn its own ceiling.
fn load_new_source_quota(
    values: &BTreeMap<String, String>,
) -> anyhow::Result<Option<arkret_wire::receive_policy::NewSourceQuotaConstraints>> {
    let quota = arkret_wire::receive_policy::NewSourceQuotaConstraints {
        window_seconds: env_u64(values, "COLAND_RECEIVE_POLICY_NEW_SOURCE_WINDOW_SECONDS")?,
        default_new_sources_per_window: env_u64(
            values,
            "COLAND_RECEIVE_POLICY_NEW_SOURCE_DEFAULT_PER_WINDOW",
        )?,
        max_new_sources_per_window: env_u64(
            values,
            "COLAND_RECEIVE_POLICY_NEW_SOURCE_MAX_PER_WINDOW",
        )?,
        retention_seconds: env_u64(values, "COLAND_RECEIVE_POLICY_NEW_SOURCE_RETENTION_SECONDS")?,
        default_new_sources_per_retention: env_u64(
            values,
            "COLAND_RECEIVE_POLICY_NEW_SOURCE_DEFAULT_PER_RETENTION",
        )?,
        max_new_sources_per_retention: env_u64(
            values,
            "COLAND_RECEIVE_POLICY_NEW_SOURCE_MAX_PER_RETENTION",
        )?,
    };
    if quota == arkret_wire::receive_policy::NewSourceQuotaConstraints::default() {
        return Ok(None);
    }
    // Reject a deployment that violates the cross-field invariants at boot
    // rather than silently advertising a quota the admission path would refuse.
    quota.effective(None).map_err(|error| {
        anyhow::anyhow!("COLAND_RECEIVE_POLICY_NEW_SOURCE_* is invalid: {error}")
    })?;
    Ok(Some(quota))
}

fn env_u64(values: &BTreeMap<String, String>, name: &str) -> anyhow::Result<Option<u64>> {
    let Some(raw) = env_non_empty(values, name) else {
        return Ok(None);
    };
    raw.trim()
        .parse::<u64>()
        .map(Some)
        .map_err(|error| anyhow::anyhow!("{name} must be a non-negative integer: {error}"))
}

fn load_receive_policy_constraints(
    values: &BTreeMap<String, String>,
) -> anyhow::Result<Option<arkret_wire::receive_policy::ReceivePolicyConstraints>> {
    let applies_to = env_csv_cap(values, "COLAND_RECEIVE_POLICY_APPLIES_TO")
        .map(|values| {
            values
                .into_iter()
                .map(|value| match value.as_str() {
                    "invite_delivery" => {
                        Ok(arkret_wire::receive_policy::ReceivePolicySurface::InviteDelivery)
                    }
                    "contact_request" => {
                        Ok(arkret_wire::receive_policy::ReceivePolicySurface::ContactRequest)
                    }
                    other => anyhow::bail!(
                        "COLAND_RECEIVE_POLICY_APPLIES_TO contains unsupported surface {other}"
                    ),
                })
                .collect::<anyhow::Result<Vec<_>>>()
        })
        .transpose()?;
    let deployment_allowed_introduction_kinds =
        env_csv_cap(values, "COLAND_RECEIVE_POLICY_PERMITTED_INTRODUCTION_KINDS");
    let deployment_denied_introduction_kinds =
        env_csv_cap(values, "COLAND_RECEIVE_POLICY_FORBIDDEN_INTRODUCTION_KINDS")
            .unwrap_or_default();
    let handle_claim_max_behavior =
        env_receive_action(values, "COLAND_RECEIVE_POLICY_HANDLE_CLAIM_MAX_BEHAVIOR")?;
    let explicit_address_max_behavior = env_receive_action(
        values,
        "COLAND_RECEIVE_POLICY_EXPLICIT_ADDRESS_MAX_BEHAVIOR",
    )?;
    let unknown_invites_max_behavior =
        env_unknown_action(values, "COLAND_RECEIVE_POLICY_UNKNOWN_INVITES_MAX_BEHAVIOR")?;
    let disclosure_max = {
        let high_trust_max =
            env_disclosure_level(values, "COLAND_RECEIVE_POLICY_DISCLOSURE_HIGH_TRUST_MAX")?;
        let discovery_trust_max = env_disclosure_level(
            values,
            "COLAND_RECEIVE_POLICY_DISCLOSURE_DISCOVERY_TRUST_MAX",
        )?;
        let low_trust_max =
            env_disclosure_level(values, "COLAND_RECEIVE_POLICY_DISCLOSURE_LOW_TRUST_MAX")?;
        if high_trust_max.is_some() || discovery_trust_max.is_some() || low_trust_max.is_some() {
            Some(arkret_wire::receive_policy::ReceiveDisclosureMax {
                high_trust_max,
                discovery_trust_max,
                low_trust_max,
            })
        } else {
            None
        }
    };
    let allowed_handle_domains =
        env_csv_cap(values, "COLAND_RECEIVE_POLICY_ALLOWED_HANDLE_DOMAINS").map(|domains| {
            domains
                .into_iter()
                .map(|domain| domain.to_ascii_lowercase())
                .collect()
        });
    let trusted_handle_issuer_ids =
        env_did_csv_cap(values, "COLAND_RECEIVE_POLICY_TRUSTED_HANDLE_ISSUERS")?;
    let trusted_directory_ids =
        env_did_csv_cap(values, "COLAND_RECEIVE_POLICY_TRUSTED_DIRECTORY_SERVICES")?;
    let trusted_source_ids =
        env_did_csv_cap(values, "COLAND_RECEIVE_POLICY_TRUSTED_PRINCIPAL_SERVICES")?;
    let denied_source_ids =
        env_did_csv_cap(values, "COLAND_RECEIVE_POLICY_BLOCKED_PRINCIPAL_SERVICES")?;
    let accepted_subject_did_methods =
        env_csv_cap(values, "COLAND_RECEIVE_POLICY_ACCEPTED_SUBJECT_DID_METHODS");
    let new_source_quota = load_new_source_quota(values)?;

    let has_any_constraint = applies_to.is_some()
        || new_source_quota.is_some()
        || deployment_allowed_introduction_kinds.is_some()
        || !deployment_denied_introduction_kinds.is_empty()
        || handle_claim_max_behavior.is_some()
        || explicit_address_max_behavior.is_some()
        || unknown_invites_max_behavior.is_some()
        || disclosure_max.is_some()
        || allowed_handle_domains.is_some()
        || trusted_handle_issuer_ids.is_some()
        || trusted_directory_ids.is_some()
        || trusted_source_ids.is_some()
        || denied_source_ids.is_some()
        || accepted_subject_did_methods.is_some();
    if !has_any_constraint {
        return Ok(None);
    }

    Ok(Some(
        arkret_wire::receive_policy::ReceivePolicyConstraints {
            policy_version: Some("env".to_owned()),
            applies_to,
            deployment_allowed_introduction_kinds,
            deployment_denied_introduction_kinds,
            handle_claim_max_behavior,
            explicit_address_max_behavior,
            unknown_invites_max_behavior,
            new_source_quota,
            disclosure_max,
            allowed_handle_domains,
            trusted_handle_issuer_ids,
            trusted_directory_ids,
            trusted_source_ids,
            denied_source_ids,
            accepted_subject_did_methods,
        },
    ))
}

fn env_disclosure_level(
    values: &BTreeMap<String, String>,
    name: &str,
) -> anyhow::Result<Option<arkret_wire::receive_policy::ReceiveDisclosureLevel>> {
    let Some(value) = env_non_empty(values, name) else {
        return Ok(None);
    };
    match value.as_str() {
        "opaque" => Ok(Some(
            arkret_wire::receive_policy::ReceiveDisclosureLevel::Opaque,
        )),
        "outcome" => Ok(Some(
            arkret_wire::receive_policy::ReceiveDisclosureLevel::Outcome,
        )),
        other => anyhow::bail!("{name} must be opaque or outcome; got {other}"),
    }
}

fn env_receive_action(
    values: &BTreeMap<String, String>,
    name: &str,
) -> anyhow::Result<Option<arkret_wire::receive_policy::InviteReceiveAction>> {
    let Some(value) = env_non_empty(values, name) else {
        return Ok(None);
    };
    match value.as_str() {
        "drop" => Ok(Some(arkret_wire::receive_policy::InviteReceiveAction::Drop)),
        "quarantine" => Ok(Some(
            arkret_wire::receive_policy::InviteReceiveAction::Quarantine,
        )),
        "notify" => Ok(Some(
            arkret_wire::receive_policy::InviteReceiveAction::Notify,
        )),
        other => anyhow::bail!("{name} must be drop, quarantine, or notify; got {other}"),
    }
}

fn env_unknown_action(
    values: &BTreeMap<String, String>,
    name: &str,
) -> anyhow::Result<Option<arkret_wire::receive_policy::UnknownInviteAction>> {
    let Some(value) = env_non_empty(values, name) else {
        return Ok(None);
    };
    match value.as_str() {
        "drop" => Ok(Some(arkret_wire::receive_policy::UnknownInviteAction::Drop)),
        "quarantine" => Ok(Some(
            arkret_wire::receive_policy::UnknownInviteAction::Quarantine,
        )),
        other => anyhow::bail!("{name} must be drop or quarantine; got {other}"),
    }
}

fn rate_limit_override(values: &BTreeMap<String, String>, name: &str) -> Option<u32> {
    env_non_empty(values, name).and_then(|value| value.parse::<u32>().ok())
}

fn load_otel_config(values: &BTreeMap<String, String>) -> anyhow::Result<OtelConfig> {
    let defaults = OtelConfig::default();
    let sample_ratio = env_non_empty(values, "COLAND_OTEL_SAMPLE_RATIO")
        .map(|value| value.parse::<f64>())
        .transpose()
        .map_err(|error| anyhow::anyhow!("COLAND_OTEL_SAMPLE_RATIO must be a number: {error}"))?
        .unwrap_or(defaults.sample_ratio);
    anyhow::ensure!(
        (0.0..=1.0).contains(&sample_ratio),
        "COLAND_OTEL_SAMPLE_RATIO must be between 0.0 and 1.0"
    );
    Ok(OtelConfig {
        exporter_enabled: env_non_empty(values, "COLAND_OTEL_EXPORTER").is_some_and(|value| {
            matches!(value.to_ascii_lowercase().as_str(), "otlp" | "1" | "true")
        }),
        endpoint: env_non_empty(values, "COLAND_OTEL_ENDPOINT").unwrap_or(defaults.endpoint),
        timeout_seconds: env_non_empty(values, "COLAND_OTEL_TIMEOUT_SECS")
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(defaults.timeout_seconds)
            .max(1),
        sample_ratio,
        service_name: env_non_empty(values, "COLAND_OTEL_SERVICE_NAME"),
    })
}

fn env_csv_cap(values: &BTreeMap<String, String>, name: &str) -> Option<Vec<String>> {
    let raw = lookup(values, name).ok()?;
    Some(
        raw.split(',')
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .collect(),
    )
}

fn env_did_csv_cap(
    values: &BTreeMap<String, String>,
    name: &str,
) -> anyhow::Result<Option<Vec<arkret_identifiers::DidCoreId>>> {
    let Some(parsed) = env_csv_cap(values, name) else {
        return Ok(None);
    };
    parsed
        .into_iter()
        .map(|value| {
            arkret_identifiers::DidCoreId::new(value.clone()).map_err(|error| {
                anyhow::anyhow!("{name} contains invalid DID core id `{value}`: {error}")
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()
        .map(Some)
}

fn env_csv(values: &BTreeMap<String, String>, name: &str) -> Option<Vec<String>> {
    let parsed: Vec<String> = lookup(values, name)
        .ok()?
        .split(',')
        .map(|value| value.trim().trim_start_matches("did:").to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .collect();
    if parsed.is_empty() {
        None
    } else {
        Some(parsed)
    }
}

fn default_did_resolver_allow_methods() -> Vec<String> {
    // did:webvh-only red line: `web` is intentionally absent from the default
    // resolver allow-list. Deployments that must interoperate with bare
    // did:web peers can opt in explicitly via COLAND_DID_RESOLVER_ALLOW_METHODS.
    vec!["webvh".to_owned(), "key".to_owned(), "uuid".to_owned()]
}

fn env_non_empty(values: &BTreeMap<String, String>, name: &str) -> Option<String> {
    lookup(values, name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn required_env(values: &BTreeMap<String, String>, name: &str) -> anyhow::Result<String> {
    env_non_empty(values, name).ok_or_else(|| anyhow::anyhow!("{name} is required"))
}

fn env_bool(values: &BTreeMap<String, String>, name: &str) -> anyhow::Result<Option<bool>> {
    let Some(value) = env_non_empty(values, name) else {
        return Ok(None);
    };
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(Some(true)),
        "0" | "false" | "no" | "off" => Ok(Some(false)),
        _ => anyhow::bail!("{name} must be true or false"),
    }
}

fn lookup(values: &BTreeMap<String, String>, name: &str) -> Result<String, std::env::VarError> {
    values
        .get(name)
        .cloned()
        .ok_or(std::env::VarError::NotPresent)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_ed25519_public_key_multibase(seed: u8) -> String {
        let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]).verifying_key();
        let mut multicodec = vec![0xed, 0x01];
        multicodec.extend_from_slice(key.as_bytes());
        format!("z{}", bs58::encode(multicodec).into_string())
    }

    fn registered_internal_channel_values() -> BTreeMap<String, String> {
        BTreeMap::from([
            (
                "COLAND_TRUST_DOMAIN".to_owned(),
                "ak:trust_domain:station.example".to_owned(),
            ),
            ("COLAND_DEVELOPMENT_MODE".to_owned(), "true".to_owned()),
            (
                "COLAND_ACCOUNT_AUTHORITY_URL".to_owned(),
                "https://auth.example".to_owned(),
            ),
            (
                "COLAND_ACCOUNT_AUTHORITY_TRUST_DOMAIN".to_owned(),
                "ak:trust_domain:auth.example".to_owned(),
            ),
            (
                "COLAND_INTERNAL_AUTHORITY_SHARED_SECRET".to_owned(),
                "test-internal-channel-secret".to_owned(),
            ),
            (
                "COLAND_SESSION_GRANT_INTROSPECTION_URL".to_owned(),
                "https://auth.example:443/_coauth/internal/session-grants/introspect".to_owned(),
            ),
            (
                "COLAND_AUTH_SESSION_LOGOUT_URL".to_owned(),
                "https://auth.example/_coauth/internal/auth-sessions/logout".to_owned(),
            ),
        ])
    }

    #[test]
    fn registered_internal_channel_binds_every_bearer_target_to_authority_origin() {
        let config = AppConfig::from_values(
            &registered_internal_channel_values(),
            StartupOverrides::default(),
        )
        .unwrap();
        assert_eq!(
            config.account_authority_url.as_deref(),
            Some("https://auth.example/")
        );
        assert_eq!(
            config
                .internal_authority_channel
                .as_ref()
                .unwrap()
                .controller_gate_url(),
            "https://auth.example/_coauth/internal/controller-gate-attestations"
        );
    }

    #[test]
    fn trusted_push_gateway_registry_is_validated_and_injected_from_config() {
        let mut values = BTreeMap::from([
            ("COLAND_DEVELOPMENT_MODE".to_owned(), "true".to_owned()),
            (
                "COLAND_TRUST_DOMAIN".to_owned(),
                "ak:trust_domain:station.example".to_owned(),
            ),
        ]);
        values.insert(
            "COLAND_TRUSTED_PUSH_GATEWAYS".to_owned(),
            serde_json::json!([{
                "canonical_origin": "https://push.example",
                "service_did": "did:web:push.example",
                "receipt_verification_method": "did:web:push.example#receipt",
                "receipt_public_key_multibase": test_ed25519_public_key_multibase(9),
            }])
            .to_string(),
        );
        let config =
            AppConfig::from_values(&values, StartupOverrides::default()).expect("valid registry");
        let origin = arkret_wire::WebOrigin::new("https://push.example").unwrap();
        let gateway = config.trusted_push_gateways.get(&origin).unwrap();
        assert_eq!(gateway.service_did().as_str(), "did:web:push.example");
        assert_eq!(
            gateway.receipt_verification_method().as_str(),
            "did:web:push.example#receipt"
        );
    }

    #[test]
    fn signed_pairing_transport_does_not_require_the_shared_secret_channel() {
        let mut values = registered_internal_channel_values();
        values.remove("COLAND_INTERNAL_AUTHORITY_SHARED_SECRET");
        values.remove("COLAND_SESSION_GRANT_INTROSPECTION_URL");
        values.remove("COLAND_AUTH_SESSION_LOGOUT_URL");
        let config =
            AppConfig::from_values(&values, StartupOverrides::default()).expect("valid config");
        assert!(config.internal_authority_channel.is_none());
        assert!(config.internal_authority_shared_secret.is_none());
        assert_eq!(
            config
                .account_authority_trust_domain
                .as_ref()
                .map(TrustDomainId::as_str),
            Some("ak:trust_domain:auth.example")
        );
    }

    #[test]
    fn deactivation_propagation_window_is_explicit_and_positive() {
        let mut values = registered_internal_channel_values();
        values.insert(
            "COLAND_DEACTIVATION_PROPAGATION_WINDOW_MS".to_owned(),
            "1234".to_owned(),
        );
        let config =
            AppConfig::from_values(&values, StartupOverrides::default()).expect("valid window");
        assert_eq!(config.deactivation_propagation_window_ms, 1234);

        values.insert(
            "COLAND_DEACTIVATION_PROPAGATION_WINDOW_MS".to_owned(),
            "0".to_owned(),
        );
        let error = AppConfig::from_values(&values, StartupOverrides::default())
            .expect_err("zero disables the normative timeout and must fail");
        assert!(
            error
                .to_string()
                .contains("COLAND_DEACTIVATION_PROPAGATION_WINDOW_MS")
        );
    }

    #[test]
    fn registered_internal_channel_rejects_cross_origin_or_inexact_bearer_targets() {
        for (env_name, invalid) in [
            ("COLAND_ACCOUNT_AUTHORITY_URL", "https://user@auth.example/"),
            (
                "COLAND_ACCOUNT_AUTHORITY_URL",
                "https://auth.example/?routing=unsafe",
            ),
            (
                "COLAND_ACCOUNT_AUTHORITY_URL",
                "https://auth.example/#routing",
            ),
            (
                "COLAND_SESSION_GRANT_INTROSPECTION_URL",
                "https://other.example/_coauth/internal/session-grants/introspect",
            ),
            (
                "COLAND_SESSION_GRANT_INTROSPECTION_URL",
                "http://auth.example/_coauth/internal/session-grants/introspect",
            ),
            (
                "COLAND_SESSION_GRANT_INTROSPECTION_URL",
                "https://auth.example:444/_coauth/internal/session-grants/introspect",
            ),
            (
                "COLAND_SESSION_GRANT_INTROSPECTION_URL",
                "https://user@auth.example/_coauth/internal/session-grants/introspect",
            ),
            (
                "COLAND_SESSION_GRANT_INTROSPECTION_URL",
                "https://auth.example/_coauth/internal/session-grants/introspect?copy=1",
            ),
            (
                "COLAND_SESSION_GRANT_INTROSPECTION_URL",
                "https://auth.example/_coauth/internal/session-grants/introspect#copy",
            ),
            (
                "COLAND_SESSION_GRANT_INTROSPECTION_URL",
                "https://auth.example/_coauth/internal/session-grants/introspect/",
            ),
            (
                "COLAND_AUTH_SESSION_LOGOUT_URL",
                "https://other.example/_coauth/internal/auth-sessions/logout",
            ),
        ] {
            let mut values = registered_internal_channel_values();
            values.insert(env_name.to_owned(), invalid.to_owned());
            let error = AppConfig::from_values(&values, StartupOverrides::default())
                .expect_err("a bearer target outside the registered endpoint must fail startup");
            assert!(
                error.to_string().contains(env_name),
                "{env_name}={invalid}: {error}"
            );
        }
    }

    #[test]
    fn key_store_config_selects_backends() {
        use base64::Engine as _;

        assert!(matches!(
            KeyStoreConfig::from_values(&BTreeMap::new()).unwrap(),
            KeyStoreConfig::Disabled
        ));

        let platform_values =
            BTreeMap::from([("COLAND_KEYSTORE_BACKEND".to_owned(), "platform".to_owned())]);
        assert!(matches!(
            KeyStoreConfig::from_values(&platform_values).unwrap(),
            KeyStoreConfig::Platform
        ));

        let encoded = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let encrypted_values = BTreeMap::from([
            (
                "COLAND_KEYSTORE_BACKEND".to_owned(),
                "encrypted_file".to_owned(),
            ),
            (
                "COLAND_KEYSTORE_PATH".to_owned(),
                "coland-test-keystore.v1".to_owned(),
            ),
            ("COLAND_KEYSTORE_MASTER_KEY".to_owned(), encoded.clone()),
        ]);
        let encrypted = KeyStoreConfig::from_values(&encrypted_values).unwrap();
        assert_eq!(encrypted.backend_name(), Some("encrypted_file"));
        assert!(!format!("{encrypted:?}").contains(&encoded));
    }

    #[test]
    fn persistent_database_requires_durable_key_store() {
        let error =
            validate_persistence_key_store(Some("postgres://example"), &KeyStoreConfig::Disabled)
                .expect_err("persistent database with ephemeral keys must fail");
        assert!(error.to_string().contains("DATABASE_URL requires"));
        validate_persistence_key_store(Some("postgres://example"), &KeyStoreConfig::Platform)
            .unwrap();
        validate_persistence_key_store(None, &KeyStoreConfig::Disabled).unwrap();
    }

    #[test]
    fn auth_session_logout_url_is_an_explicit_exact_operation_endpoint() {
        validate_auth_session_logout_url(
            "https://auth.example/_coauth/internal/auth-sessions/logout",
        )
        .unwrap();
        for invalid in [
            "https://auth.example/_coauth/internal/session-grants/introspect",
            "https://user@auth.example/_coauth/internal/auth-sessions/logout",
            "https://auth.example/_coauth/internal/auth-sessions/logout?version=1",
            "ftp://auth.example/_coauth/internal/auth-sessions/logout",
        ] {
            assert!(
                validate_auth_session_logout_url(invalid).is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn default_did_resolver_allow_methods_webvh_only_no_bare_web() {
        // did:webvh-only red line: bare `web` must never be in the default
        // resolver allow-list; it is opt-in via env override only.
        let methods = default_did_resolver_allow_methods();
        assert_eq!(methods, vec!["webvh", "key", "uuid"]);
        assert!(!methods.iter().any(|m| m == "web"));
    }

    #[test]
    fn ice_servers_defaults_match_historical_hardcoded_values() {
        // These defaults must keep the pre-externalization wire behavior so
        // deployments that do not set `COLAND_ICE_*` / `COLAND_TURN_*` see no
        // change in their issued ICE configs.
        let ice = IceServersConfig::default();
        assert_eq!(ice.stun_urls, vec!["stun:stun.l.google.com:19302"]);
        assert_eq!(
            ice.turn_urls,
            vec!["turn:turn.coland.local:3478?transport=udp"]
        );
        assert_eq!(ice.ttl_seconds, 300);
        assert_eq!(ice.refresh_lead_seconds, 75);
        assert_eq!(ice.turn_secret_rotation_window_seconds, 86_400);
        assert!(ice.turn_shared_secret.is_none());
    }

    #[test]
    fn load_ice_servers_config_parses_overrides() {
        let ice = IceServersConfig::resolve(
            Some("stun:stun.example:3478 , stun:stun2.example:3478"),
            Some("turn:turn.example:3478?transport=udp"),
            Some("120"),
            Some("30"),
            Some("3600"),
            None,
        );
        assert_eq!(
            ice.stun_urls,
            vec!["stun:stun.example:3478", "stun:stun2.example:3478"]
        );
        assert_eq!(ice.turn_urls, vec!["turn:turn.example:3478?transport=udp"]);
        assert_eq!(ice.ttl_seconds, 120);
        assert_eq!(ice.refresh_lead_seconds, 30);
        assert_eq!(ice.turn_secret_rotation_window_seconds, 3600);
    }

    #[test]
    fn a_non_positive_ice_ttl_falls_back_to_the_default() {
        let ice = IceServersConfig::resolve(None, None, Some("0"), None, None, None);
        assert_eq!(ice.ttl_seconds, 300);
    }

    #[test]
    fn pq_hybrid_tls_probe_parser_accepts_only_artifact_success_values() {
        assert!(AppConfig::pq_hybrid_tls_probe_verified_from_value(Some(
            "verified"
        )));
        assert!(AppConfig::pq_hybrid_tls_probe_verified_from_value(Some(
            "X25519MLKEM768"
        )));
        assert!(AppConfig::pq_hybrid_tls_probe_verified_from_value(Some(
            "tls13+x25519mlkem768"
        )));
        assert!(!AppConfig::pq_hybrid_tls_probe_verified_from_value(Some(
            "classical-x25519"
        )));
        assert!(!AppConfig::pq_hybrid_tls_probe_verified_from_value(None));
    }
}
