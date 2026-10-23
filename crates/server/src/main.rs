use anyhow::Context;
use coland::process_config::arg_value;
use coland_http::config::{AppConfig, StartupOverrides};
use coland_http::service;
use coland_http::state::AppState;
use coland_storage_postgres::Db;
use salvo::conn::rustls::{Keycert, RustlsConfig};
use salvo::conn::tcp::{TcpAcceptor, TcpCoupler};
use salvo::conn::{Accepted, Acceptor, ConnCtrl, Holding, Listener, StraightStream};
use salvo::fuse::{ArcFusePolicy, FuseAction, FuseInfo, TransProto};
use salvo::prelude::*;
use tokio::signal;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

pub(crate) mod bootstrap;
pub(crate) mod object_storage;
pub(crate) mod otel;
pub(crate) mod runtime;

/// Apply the native TCP latency policy before Salvo wraps the socket or starts TLS.
/// All normal and identity-bootstrap listeners use this same typed factory.
fn low_latency_tcp_listener(bind: String) -> NoDelayTcpListener {
    NoDelayTcpListener(TcpListener::new(bind))
}

struct NoDelayTcpListener(TcpListener<String>);

impl NoDelayTcpListener {
    fn rustls(
        self,
        config: RustlsConfig,
    ) -> salvo::conn::rustls::RustlsListener<RustlsConfig, RustlsConfig, Self, std::io::Error> {
        salvo::conn::rustls::RustlsListener::new(config, self)
    }
}

impl Listener for NoDelayTcpListener {
    type Acceptor = NoDelayTcpAcceptor;

    async fn try_bind(self) -> salvo::Result<Self::Acceptor> {
        Ok(NoDelayTcpAcceptor {
            inner: self.0.try_bind().await?,
            pending: None,
        })
    }
}

struct NoDelayTcpAcceptor {
    inner: TcpAcceptor,
    pending: Option<(tokio::net::TcpStream, std::net::SocketAddr)>,
}

impl NoDelayTcpAcceptor {
    async fn accept_pending_tcp(&mut self) -> std::io::Result<()> {
        if self.pending.is_none() {
            let (stream, remote_addr) = self.inner.inner().accept().await?;
            // Failure rejects this connection; never serve an unconfigured fallback.
            stream.set_nodelay(true)?;
            self.pending = Some((stream, remote_addr));
        }
        Ok(())
    }
}

impl Acceptor for NoDelayTcpAcceptor {
    type Coupler = TcpCoupler<Self::Stream>;
    type Stream = StraightStream<tokio::net::TcpStream>;

    fn holdings(&self) -> &[Holding] {
        self.inner.holdings()
    }

    async fn accept(
        &mut self,
        fuse_policy: Option<ArcFusePolicy>,
    ) -> std::io::Result<Accepted<Self::Coupler, Self::Stream>> {
        loop {
            self.accept_pending_tcp().await?;
            // As in Salvo's native acceptor, keep the socket across cancellation
            // while async admission runs, and preserve the original fuse observer.
            let remote_addr = self.pending.as_ref().expect("accepted TCP socket").1;
            let local_addr = self.holdings()[0].local_addr.clone();
            let conn_ctrl = ConnCtrl::new();
            let (fuse_config, observer) = match &fuse_policy {
                Some(policy) => {
                    let info = FuseInfo {
                        trans_proto: TransProto::Tcp,
                        remote_addr: remote_addr.into(),
                        local_addr: local_addr.clone(),
                    };
                    match policy.decide(&info).await {
                        FuseAction::Accept(config) => {
                            (Some(config), policy.observe(&info, &conn_ctrl))
                        }
                        FuseAction::Reject => {
                            self.pending = None;
                            continue;
                        }
                    }
                }
                None => (None, None),
            };
            let (stream, remote_addr) = self.pending.take().expect("accepted TCP socket");
            return Ok(Accepted {
                coupler: TcpCoupler::new(),
                stream: StraightStream::new(stream, fuse_config, conn_ctrl.clone(), observer),
                fuse_config,
                conn_ctrl,
                remote_addr: remote_addr.into(),
                local_addr,
                http_scheme: salvo::http::uri::Scheme::HTTP,
            });
        }
    }
}

fn main() -> anyhow::Result<()> {
    let raw_args: Vec<String> = std::env::args().collect();
    if raw_args.len() == 2 && matches!(raw_args[1].as_str(), "--version" | "-V") {
        println!("coland {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    // The dependency graph includes rustls consumers that enable different
    // provider features. Select Coland's declared `ring` provider before any
    // listener or outbound client can ask rustls for a process default.
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("a different rustls CryptoProvider was already installed"))?;
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run(raw_args))
}

async fn run(raw_args: Vec<String>) -> anyhow::Result<()> {
    // P5 (5.5) — `coland healthcheck` subcommand. Distroless / minimal
    // runtime images cannot rely on an external `curl` binary for the
    // Docker HEALTHCHECK. Detect the subcommand BEFORE we initialize
    // tracing so the healthcheck process stays quiet (no startup chatter,
    // no opening of COLAND_LOG_FILE), exits with status 0 on probe
    // success and 1 on failure, and never starts the Salvo listener.
    if raw_args
        .iter()
        .skip(1)
        .any(|arg| arg == "healthcheck" || arg == "--healthcheck")
    {
        return run_healthcheck(&raw_args).await;
    }

    if raw_args.get(1).map(String::as_str) == Some("service-identity")
        && raw_args.get(2).map(String::as_str) == Some("migrate-base")
    {
        let values = coland::process_config::load(&raw_args)?;
        let config = AppConfig::from_values(
            &values,
            StartupOverrides {
                bind: None,
                first_provisioning: false,
            },
        )?;
        let from = arg_value(&raw_args, "--from").context("migrate-base requires --from URL")?;
        let to = arg_value(&raw_args, "--to").context("migrate-base requires --to URL")?;
        let db = Db::connect(config.database_url.as_deref(), Default::default()).await?;
        let report = crate::bootstrap::public_base::migrate(
            &config,
            &db,
            &from,
            &to,
            crate::bootstrap::public_base::MigrationOptions {
                preflight: raw_args.iter().any(|arg| arg == "--preflight"),
                preserve_did_host: raw_args.iter().any(|arg| arg == "--preserve-did-host"),
            },
        )
        .await?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    // Initialization has a large poll frame even when its future is boxed.
    // Complete that frame before entering synchronous router / OpenAPI schema
    // construction on the same default-size main-thread stack.
    let serve = prepare_server_on_heap(raw_args).await?;
    serve.await
}

type ServingFuture = std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>>>>;

// Construct the startup future outside the small driver's poll frame. Boxing
// only `run` at Runtime::block_on does not remove its active poll stack frame.
#[inline(never)]
fn prepare_server_on_heap(
    raw_args: Vec<String>,
) -> std::pin::Pin<Box<impl std::future::Future<Output = anyhow::Result<ServingFuture>>>> {
    Box::pin(prepare_server(raw_args))
}

async fn prepare_server(raw_args: Vec<String>) -> anyhow::Result<ServingFuture> {
    // Configuration comes first: the subscriber, the exporter and everything
    // after all read `AppConfig`, so there is one parse of every value.
    // Logging deliberately does not precede this. A configuration failure
    // means the process does not start, and that error returns from `main` for
    // the runtime to print — there is nothing for a subscriber to add. Before
    // this order, `COLAND_DEVELOPMENT_MODE` was parsed a second time here with
    // a case-sensitive matcher that did not accept `on`, so
    // `COLAND_DEVELOPMENT_MODE=on` produced a development-mode server writing
    // production logs.
    let values = coland::process_config::load(&raw_args)?;
    let mut config = AppConfig::from_values(
        &values,
        StartupOverrides {
            bind: arg_value(&raw_args, "--bind"),
            first_provisioning: raw_args.iter().any(|arg| arg == "--first-provisioning"),
        },
    )?;

    // Keep this guard alive for the process lifetime so the non-blocking
    // file appender drains its channel on shutdown. Dropping the guard
    // flushes pending writes; storing it in `_file_guard` defers that drop
    // until `main` returns.
    let _tracing_guards = init_tracing(&config)?;

    // Connect the database and resolve this deployment's own service identity
    // before anything derived from it is constructed. The DID remains runtime
    // state; only the derived trust-domain value is copied into operational
    // config for existing policy consumers.
    let db = Db::connect(
        config.database_url.as_deref(),
        coland_storage_postgres::PoolTuning {
            max_size: config.db_pool_max_size,
            acquire_timeout_seconds: config.db_pool_acquire_timeout_seconds,
        },
    )
    .await?;
    let bootstrap = crate::bootstrap::resolve_and_build_persistence(&config, &db).await?;
    let bootstrap = if matches!(
        bootstrap.state,
        arkret_identity::service_identity::DidCoreIdentityState::WaitingProvider { .. }
    ) {
        tracing::warn!(
            retry_seconds = 5,
            "service identity Provider is unavailable; serving fail-closed health endpoints while retrying"
        );
        if config.tls_enabled() {
            let keycert = Keycert::new()
                .cert_from_path(
                    config
                        .tls_cert_path
                        .as_ref()
                        .expect("tls_enabled guarantees cert path"),
                )
                .context("failed to read COLAND_TLS_CERT_PATH")?
                .key_from_path(
                    config
                        .tls_key_path
                        .as_ref()
                        .expect("tls_enabled guarantees key path"),
                )
                .context("failed to read COLAND_TLS_KEY_PATH")?;
            let acceptor = low_latency_tcp_listener(config.bind.to_string())
                .rustls(RustlsConfig::new(keycert))
                .bind()
                .await;
            wait_for_service_identity(acceptor, config.clone(), bootstrap).await?
        } else {
            let acceptor = low_latency_tcp_listener(config.bind.to_string())
                .bind()
                .await;
            wait_for_service_identity(acceptor, config.clone(), bootstrap).await?
        }
    } else {
        bootstrap
    };
    let _service_id = bootstrap
        .state
        .identity()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "service identity bootstrap did not produce a serving identity: {:?}",
                bootstrap.state
            )
        })?
        .service_id
        .to_string();
    // Probe the optional external webvh provider before advertising it as
    // active. The configured URL remains visible in `/identity/describe` even
    // when the probe fails so coauth can show the operator's intended setup.
    if let Some(url) = config.external_webvh_provider_url.clone() {
        let expected_trust_domain = config
            .external_webvh_provider_trust_domain
            .clone()
            .unwrap_or_else(|| config.trust_domain.to_string());
        match coland_http::state::did_resolver_chain::probe_webvh_provider_describe(
            &url,
            std::time::Duration::from_secs(3),
            None,
            Some(expected_trust_domain.as_str()),
            config.development_mode,
        )
        .await
        {
            Ok(()) => {
                tracing::info!(
                    webvh_provider_url = %url,
                    "external webvh provider /describe probe succeeded"
                );
                config.external_webvh_provider_active = true;
            }
            Err(error) => {
                tracing::warn!(
                    webvh_provider_url = %url,
                    %error,
                    "external webvh provider /describe probe failed"
                );
            }
        }
    }
    let supervisor_persistence = bootstrap.persistence.clone();
    let supervisor_key_store = bootstrap.key_store.clone();
    let resolution_commitment = bootstrap
        .resolution_commitment
        .clone()
        .ok_or_else(|| anyhow::anyhow!("serving service identity has no resolution commitment"))?;
    let mut state = crate::runtime::build_app_state(
        config.clone(),
        db,
        bootstrap.persistence,
        bootstrap.state,
        resolution_commitment,
        bootstrap.signing_seed,
    )?;
    if let Some(store) = supervisor_key_store.clone() {
        state = state.with_verifier_private_keystore(store);
    }
    spawn_service_identity_supervisor(state.clone(), supervisor_persistence, supervisor_key_store);
    // Finish boot: seed demo data + hydrate the Realm directory and
    // projections from the (now async) persistence store.
    state.hydrate().await?;
    let _native_public_replies = crate::runtime::start_native_arkret_public_replies(
        state.clone(),
        values.get("COLAND_ARKRET_RUNTIME_HOME").map(String::as_str),
    )
    .await?;
    spawn_federation_peer_discovery(state.clone());

    // Sovereign enclave security invariants. When
    // `COLAND_SOVEREIGN_ENCLAVE=1` the configured posture MUST satisfy:
    //   * federation_outbound_enabled = false
    //   * did_resolver_allow_methods non-empty
    // Fail fast at startup if either invariant is violated.
    let enclave_assertion = coland_http::security::assert_enclave_invariants(state.config());
    if !enclave_assertion.is_compliant() {
        anyhow::bail!(
            "COLAND_SOVEREIGN_ENCLAVE=1 but enclave invariants are not satisfied: {}",
            enclave_assertion.violations.join("; ")
        );
    }
    if enclave_assertion.enabled {
        tracing::info!(
            target: "sovereign_boundary_audit",
            allowed_outbound_hosts = ?state.config().sovereign_enclave_allowed_outbound_hosts,
            "sovereign enclave security posture enabled; outbound federation is disabled \
             and outbound HTTP must be on the allow-list",
        );
    }

    let _consent_effect_publication_worker =
        coland_http::routing::spawn_effect_publication_worker(state.clone());
    let _account_erasure_worker = coland_http::account_erasure_worker::spawn(state.clone());
    // security-transactions.md §3 — the Station, not a client, advances the
    // coordinator-owned SecurityRotation `revoke` step and resumes it after a
    // restart from the durable proposal/terminal units.
    let _security_rotation_worker = coland_http::security_rotation_worker::spawn(state.clone());
    tracing::info!(
        worker = "account_erasure",
        enabled = true,
        service_id = %state.service_id(),
        "background worker configured"
    );

    // account-lifecycle.md §7.1 — retries the push-gateway deactivation
    // fanout until the gateway acks, keeping `deactivation_partial` honest.
    // `None` when no gateway is configured (single-box posture: the local
    // push-route purge completes the Push-route fanout row).
    let _deactivation_push_fanout_worker =
        coland_http::deactivation_push_fanout::spawn(state.clone());
    tracing::info!(
        worker = "deactivation_push_fanout",
        enabled = _deactivation_push_fanout_worker.is_some(),
        "background worker configured"
    );

    // Public Gateway uninstall tombstones are durable before any network
    // request. Reconcile them after restart or an interrupted synchronous
    // unregister without sharing the federation outbox protocol.
    let _public_push_revoke_retry_worker =
        coland_http::routing::spawn_public_push_revoke_retry_worker(state.clone());
    tracing::info!(
        worker = "public_push_revoke_retry",
        enabled = _public_push_revoke_retry_worker.is_some(),
        "background worker configured"
    );

    // TTL backstop for the durable sync-cursor handle table (forward-progress
    // pruning on cursor presentation handles the steady state; this clears
    // rows whose client never returned).
    let _sync_cursor_ttl_sweeper =
        coland_http::routing::spawn_sync_cursor_ttl_sweeper(state.clone());
    let _account_data_change_retention_sweeper =
        coland_http::routing::spawn_account_data_change_retention_sweeper(state.clone());
    tracing::info!(
        worker = "sync_cursor_ttl_sweep",
        "background worker configured"
    );

    // GC for expired incomplete resumable (tus) blob upload parts — spec
    // media-and-blob.md §2.1: incomplete parts have a bounded lifetime and
    // never produce a referencable blob_ref.
    let _resumable_upload_ttl_sweeper =
        coland_http::routing::spawn_resumable_upload_ttl_sweeper(state.clone());
    tracing::info!(
        worker = "resumable_upload_ttl_sweep",
        "background worker configured"
    );

    // G3.S0 — durable outbound federation HTTP delivery worker. No-op
    // when `COLAND_FEDERATION_OUTBOUND=0` (used by integration tests
    // that don't want background HTTP traffic). The dispatcher drains
    // the `federation_outbox` table populated by
    // `routing::federation::broadcast_*_to_peers`.
    let _federation_dispatcher = coland_http::routing::federation::outbox::spawn(state.clone());
    // Member Station replica anchors a restart or an unreachable governing
    // Station left pending (`federation.md` section 4.1.1).
    let _replica_anchor_sweeper = coland_http::state::spawn_pending_anchor_sweeper(state.clone());
    let _franking_sweeper = coland_http::state::spawn_pending_franking_sweeper(state.clone());
    let _applet_completion_sweeper =
        coland_http::state::spawn_pending_applet_completion_sweeper(state.clone());
    tracing::info!(
        worker = "federation_outbox",
        enabled = state.config().federation_outbound_enabled,
        "background worker configured"
    );
    let _metrics_server =
        coland_http::metrics::spawn_metrics_server(state.clone(), config.metrics_bind).await?;
    tracing::info!(
        worker = "metrics_server",
        bind = %config.metrics_bind,
        "background worker configured"
    );

    Ok(Box::pin(async move {
        // Keep exactly the original runtime guards alive until serving ends.
        // Tuple fields drop in order, so reverse the original independent
        // local declarations: metrics first, native runtime then tracing last.
        let _runtime_guards = (
            _metrics_server,
            _applet_completion_sweeper,
            _franking_sweeper,
            _replica_anchor_sweeper,
            _federation_dispatcher,
            _resumable_upload_ttl_sweeper,
            _account_data_change_retention_sweeper,
            _sync_cursor_ttl_sweeper,
            _public_push_revoke_retry_worker,
            _deactivation_push_fanout_worker,
            _security_rotation_worker,
            _account_erasure_worker,
            _consent_effect_publication_worker,
            _native_public_replies,
            _tracing_guards,
        );
        tracing::info!(
            bind = %config.bind,
            metrics_bind = %config.metrics_bind,
            public_base_url = %config.public_base_url,
            service_id = %state.service_id(),
            tls_enabled = config.tls_enabled(),
            tls_cert_path = ?config.tls_cert_path,
            tls_key_path = ?config.tls_key_path,
            embedded_webvh_provider_enabled = config.embedded_webvh_provider_enabled,
            external_webvh_provider_url = ?config.external_webvh_provider_url,
            object_storage_backend = %config.object_storage.backend_name(),
            object_storage_target = %config.object_storage.log_target(),
            development_mode = config.development_mode,
            storage = state.storage_mode(),
            "starting coland"
        );
        if config.tls_enabled() {
            let keycert = Keycert::new()
                .cert_from_path(
                    config
                        .tls_cert_path
                        .as_ref()
                        .expect("tls_enabled guarantees cert path"),
                )
                .context("failed to read COLAND_TLS_CERT_PATH")?
                .key_from_path(
                    config
                        .tls_key_path
                        .as_ref()
                        .expect("tls_enabled guarantees key path"),
                )
                .context("failed to read COLAND_TLS_KEY_PATH")?;
            let acceptor = low_latency_tcp_listener(config.bind.to_string())
                .rustls(RustlsConfig::new(keycert))
                .bind()
                .await;
            tracing::info!(
                event = "tls_listener_enabled",
                tls_provider = "rustls",
                bind = %config.bind,
                "TLS listener enabled"
            );
            run_server(acceptor, state).await;
        } else {
            let acceptor = low_latency_tcp_listener(config.bind.to_string())
                .bind()
                .await;
            run_server(acceptor, state).await;
        }
        tracing::info!(event = "shutdown_complete", "coland stopped");
        Ok(())
    }))
}

/// Build the tracing subscriber.
///
/// Always writes to stdout (the default, interactive-friendly destination —
/// `cargo run` users see logs as usual). When `COLAND_LOG_FILE` is set we
/// additionally tee output to that path through a non-blocking appender so
/// runner harnesses (cotest's `run-joint-e2e.ps1`) get a durable trace they
/// can `tail -f` even when Windows fully buffers stdout under
/// `Start-Process -RedirectStandardOutput`.
///
/// Returns the appender's worker guard. The caller MUST hold it for the
/// process lifetime; dropping it earlier flushes and closes the channel
/// (typical pattern: bind to `_guard` in `main`).
struct TracingGuards {
    _file_guard: Option<tracing_appender::non_blocking::WorkerGuard>,
    _otel_guard: crate::otel::OtelGuard,
}

fn init_tracing(config: &AppConfig) -> anyhow::Result<TracingGuards> {
    let log_format = config.log_format;
    let development_mode = config.development_mode;
    use coland_http::config::LogFormat;
    use tracing_subscriber::{Layer, Registry, fmt};

    let filter = match config.log_filter.as_deref() {
        Some(directive) => tracing_subscriber::EnvFilter::new(directive),
        None if development_mode => tracing_subscriber::EnvFilter::new("debug"),
        None => tracing_subscriber::EnvFilter::new(""),
    };
    // Stdout writer: structured JSON in production, ANSI-decorated text in
    // development. JSON is required by the runbook log-search recipes; the
    // operator can force either side via `COLAND_LOG_FORMAT=json|plain`.
    let stdout_layer: Box<dyn Layer<Registry> + Send + Sync> = match log_format {
        LogFormat::Json => Box::new(
            fmt::layer()
                .json()
                .with_current_span(true)
                .with_span_list(false)
                .with_writer(std::io::stdout),
        ),
        LogFormat::Plain => Box::new(fmt::layer().with_writer(std::io::stdout)),
    };
    let mut layers: Vec<Box<dyn Layer<Registry> + Send + Sync>> = vec![stdout_layer];

    let log_file = config.log_file.clone();

    let file_guard = if let Some(path) = log_file {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create parent directory for COLAND_LOG_FILE: {}",
                    parent.display()
                )
            })?;
        }
        let file_name = path
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("COLAND_LOG_FILE must include a file name"))?
            .to_owned();
        let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
        // `rolling::never` is misnamed: it produces a non-rotating appender
        // that just opens (or creates) the file and appends each event.
        let appender = match dir {
            Some(dir) => tracing_appender::rolling::never(dir, &file_name),
            None => tracing_appender::rolling::never(".", &file_name),
        };
        let (writer, guard) = tracing_appender::non_blocking(appender);
        let file_layer: Box<dyn Layer<Registry> + Send + Sync> = match log_format {
            LogFormat::Json => Box::new(
                fmt::layer()
                    .json()
                    .with_current_span(true)
                    .with_span_list(false)
                    .with_writer(writer),
            ),
            LogFormat::Plain => Box::new(fmt::layer().with_ansi(false).with_writer(writer)),
        };
        layers.push(file_layer);
        Some(guard)
    } else {
        None
    };

    let (otel_guard, otel_layer) = crate::otel::init_layer(&config.otel, "coland")?;
    if let Some(layer) = otel_layer {
        layers.push(layer);
    }

    tracing_subscriber::registry()
        .with(layers)
        .with(filter)
        .try_init()
        .map_err(|error| anyhow::anyhow!("tracing init failed: {error}"))?;

    Ok(TracingGuards {
        _file_guard: file_guard,
        _otel_guard: otel_guard,
    })
}

/// Drain window used when `COLAND_SHUTDOWN_GRACE_SECS` is unset. The request
/// grace stays "wait indefinitely" in that case, but a drained peer still needs
/// a deadline it can plan its checkpoint against.
const DEFAULT_CONNECTION_DRAIN_GRACE: std::time::Duration = std::time::Duration::from_secs(10);

async fn run_server<A>(acceptor: A, state: AppState)
where
    A: Acceptor + Send + 'static,
{
    let server = Server::new(acceptor);
    let handle = server.handle();
    // Bounded drain: after a shutdown signal, stop accepting and wait up to
    // `COLAND_SHUTDOWN_GRACE_SECS` for in-flight requests to finish before
    // forcibly closing the listener. Unset (or 0) preserves the previous
    // "wait indefinitely" behavior. A finite bound matters under an
    // orchestrator (Kubernetes / systemd) that will SIGKILL after its own
    // grace period — a long-lived `events.subscribe` stream would otherwise
    // block a clean shutdown until the hard kill.
    let shutdown_grace = state
        .config()
        .shutdown_grace_seconds
        .map(std::time::Duration::from_secs);
    // Long-lived transports get an explicit drain notice before the listener
    // stops, so peers checkpoint and reconnect instead of discovering the
    // shutdown as a dropped socket. The notice needs a finite deadline even
    // when the request grace is "wait indefinitely".
    let drain_grace = shutdown_grace.unwrap_or(DEFAULT_CONNECTION_DRAIN_GRACE);
    let drain_state = state.clone();
    tokio::spawn(async move {
        shutdown_signal().await;
        drain_state.begin_connection_drain(drain_grace);
        handle.stop_graceful(shutdown_grace);
    });
    server.serve(service(state)).await;
}

async fn wait_for_service_identity<A>(
    acceptor: A,
    config: AppConfig,
    bootstrap: crate::bootstrap::ServiceIdentityBootstrap,
) -> anyhow::Result<crate::bootstrap::ServiceIdentityBootstrap>
where
    A: Acceptor + Send + 'static,
{
    let persistence = bootstrap.persistence;
    let key_store = bootstrap.key_store;
    let server = Server::new(acceptor);
    let handle = server.handle();
    let server_task = tokio::spawn(async move {
        server.serve(waiting_service()).await;
    });
    let resolve = async {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            match crate::bootstrap::retry_service_identity(
                &config,
                persistence.clone(),
                key_store.clone(),
            )
            .await
            {
                Ok(bootstrap) if bootstrap.state.identity().is_some() => break Ok(bootstrap),
                Ok(bootstrap)
                    if matches!(
                        bootstrap.state,
                        arkret_identity::service_identity::DidCoreIdentityState::WaitingProvider { .. }
                    ) =>
                {
                    tracing::warn!("service identity Provider remains unavailable; retrying");
                }
                Ok(bootstrap) => {
                    break Err(anyhow::anyhow!(
                        "service identity cannot become ready: {:?}",
                        bootstrap.state
                    ));
                }
                Err(error) => {
                    tracing::error!(%error, "service identity retry failed; retaining waiting state");
                }
            }
        }
    };
    let result = tokio::select! {
        result = resolve => result,
        _ = shutdown_signal() => Err(anyhow::anyhow!("shutdown requested while waiting for service identity Provider")),
    };
    handle.stop_graceful(Some(std::time::Duration::from_secs(2)));
    let _ = server_task.await;
    result
}

fn waiting_service() -> Service {
    Service::new(
        Router::new()
            .push(Router::with_path("health").get(service_identity_waiting))
            .push(Router::with_path("readyz").get(service_identity_waiting))
            .push(Router::with_path("_arkret/describe").get(service_identity_waiting)),
    )
}

#[handler]
async fn service_identity_waiting(res: &mut Response) {
    res.status_code(StatusCode::SERVICE_UNAVAILABLE);
    res.headers_mut().insert(
        salvo::http::header::RETRY_AFTER,
        salvo::http::HeaderValue::from_static("5"),
    );
    res.render(Json(serde_json::json!({
        "ok": false,
        "errcode": "service_identity_unavailable",
        "error": "service identity Provider is temporarily unavailable",
        "service_identity": {
            "state": "waiting_provider",
            "service_id": null,
            "retry_after_seconds": 5
        }
    })));
}

fn spawn_service_identity_supervisor(
    state: AppState,
    persistence: coland_services::persistence::PersistenceHandle,
    key_store: Option<std::sync::Arc<dyn arkret_keystore::KeyStore>>,
) {
    if !matches!(
        state.service_identity_state().as_ref(),
        arkret_identity::service_identity::DidCoreIdentityState::DegradedStored { .. }
    ) {
        return;
    }
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            match crate::bootstrap::retry_service_identity(
                state.config(),
                persistence.clone(),
                key_store.clone(),
            )
            .await
            {
                Ok(bootstrap) => {
                    let keep_retrying = matches!(
                        bootstrap.state,
                        arkret_identity::service_identity::DidCoreIdentityState::DegradedStored { .. }
                            | arkret_identity::service_identity::DidCoreIdentityState::WaitingProvider { .. }
                    );
                    if let Some(identity) = bootstrap.state.identity()
                        && identity.service_id.as_str() != state.service_id()
                    {
                        tracing::error!(
                            runtime_service_id = %state.service_id(),
                            provider_id = %identity.service_id,
                            "service identity supervisor rejected a runtime identity switch"
                        );
                        break;
                    }
                    if let Some(commitment) = bootstrap.resolution_commitment {
                        state.replace_service_resolution_commitment(commitment);
                    }
                    state.replace_service_identity_state(bootstrap.state);
                    if !keep_retrying {
                        break;
                    }
                }
                Err(error) => {
                    tracing::error!(%error, "service identity supervisor retry failed");
                }
            }
        }
    });
}

/// Resolve federation peers through the standard service describe and DID
/// document operations. Runtime settings retain the discovered DID and the
/// in-memory verifier retains its endpoint-bound assertion key; boot
/// configuration remains free of copied identities and public-key pins.
fn spawn_federation_peer_discovery(state: AppState) {
    tokio::spawn(async move {
        let initial_retry = std::time::Duration::from_millis(250);
        let max_retry = std::time::Duration::from_secs(5);
        let mut retry_delay = initial_retry;
        loop {
            tokio::time::sleep(retry_delay).await;
            let peers = state
                .settings()
                .federation_peers
                .iter()
                .filter_map(|entry| {
                    federation_peer_endpoint(entry).map(|endpoint| (entry.clone(), endpoint))
                })
                .collect::<Vec<_>>();
            if peers.is_empty() {
                retry_delay = max_retry;
                continue;
            }

            let mut resolved = std::collections::HashMap::new();
            for (configured, endpoint) in peers {
                let (base_url, http) =
                    match coland_http::security::validate_http_url_for_egress_with_pinned_client(
                        endpoint.as_str(),
                        "federation peer discovery",
                        state.config().development_mode,
                        std::time::Duration::from_secs(10),
                    ) {
                        Ok(validated) => validated,
                        Err(error) => {
                            tracing::warn!(%endpoint, %error, "invalid federation peer endpoint");
                            continue;
                        }
                    };
                let client = match arkret_http_client::ClientBuilder::new(base_url)
                    .http_client(http)
                    .build()
                {
                    Ok(client) => client,
                    Err(error) => {
                        tracing::warn!(%endpoint, %error, "invalid federation peer endpoint");
                        continue;
                    }
                };
                match client.describe().await {
                    Ok(description)
                        if description.service_kind == arkret_wire::ServiceKind::Station
                            && description.service_id.as_str() != state.service_id() =>
                    {
                        let document_view = match client
                            .identity_document(description.service_resolution.did.as_str(), None)
                            .await
                        {
                            Ok(document) => document,
                            Err(error) => {
                                tracing::debug!(
                                    %endpoint,
                                    peer_id = %description.service_id,
                                    %error,
                                    "federation peer DID document is not ready; retrying"
                                );
                                continue;
                            }
                        };
                        let document_value = serde_json::Value::Object(
                            document_view.did_document.into_iter().collect(),
                        );
                        let document = match serde_json::from_value::<
                            arkret_models_identity::service_identity::ServiceDidDocument,
                        >(document_value.clone())
                        {
                            Ok(document) => document,
                            Err(error) => {
                                tracing::warn!(
                                    %endpoint,
                                    peer_id = %description.service_id,
                                    %error,
                                    "federation peer returned an invalid service DID document"
                                );
                                continue;
                            }
                        };
                        let public_base_url = match arkret_models_identity::service_identity::CanonicalServiceUrl::canonicalize(
                            endpoint.as_str(),
                        ) {
                            Ok(public_base_url) => public_base_url,
                            Err(error) => {
                                tracing::warn!(%endpoint, %error, "invalid federation peer endpoint");
                                continue;
                            }
                        };
                        let registration_key = match arkret_models_identity::service_identity::ServiceRegistrationKey::new(
                            arkret_wire::ServiceKind::Station,
                            public_base_url,
                        ) {
                            Ok(key) => key,
                            Err(error) => {
                                tracing::warn!(%endpoint, %error, "invalid federation peer registration key");
                                continue;
                            }
                        };
                        let expected_verification_method =
                            coland_http::routing::federation::federation_service_signature_key_id(
                                description.service_resolution.did.as_str(),
                            );
                        let receipt_verification_method =
                            format!("{}#notary-key", description.service_resolution.did);
                        if document.id != description.service_resolution.did
                            || document.validate_for(&registration_key).is_err()
                            || !document
                                .assertion_method
                                .iter()
                                .any(|method| method == &expected_verification_method)
                            || !document
                                .assertion_method
                                .iter()
                                .any(|method| method == &receipt_verification_method)
                        {
                            tracing::warn!(
                                %endpoint,
                                peer_id = %description.service_id,
                                "federation peer DID document does not bind the described Station identity"
                            );
                            continue;
                        }
                        let Some(public_key_multibase) = document
                            .verification_method
                            .iter()
                            .find(|method| method.id == expected_verification_method)
                            .map(|method| method.public_key_multibase.as_str())
                        else {
                            tracing::warn!(
                                %endpoint,
                                peer_id = %description.service_id,
                                "federation peer DID document has no active assertion key"
                            );
                            continue;
                        };
                        let Some(receipt_public_key_multibase) = document
                            .verification_method
                            .iter()
                            .find(|method| method.id == receipt_verification_method)
                            .map(|method| method.public_key_multibase.as_str())
                        else {
                            tracing::warn!(
                                %endpoint,
                                peer_id = %description.service_id,
                                "federation peer DID document has no active receipt assertion key"
                            );
                            continue;
                        };
                        let verifying_key =
                            match arkret_canonical::decode_ed25519_multibase(public_key_multibase)
                                .map_err(|error| error.to_string())
                                .and_then(|raw| {
                                    ed25519_dalek::VerifyingKey::from_bytes(&raw)
                                        .map_err(|error| error.to_string())
                                }) {
                                Ok(key) => key,
                                Err(error) => {
                                    tracing::warn!(
                                        %endpoint,
                                        peer_id = %description.service_id,
                                        %error,
                                        "federation peer assertion key is invalid"
                                    );
                                    continue;
                                }
                            };
                        let receipt_verifying_key =
                            match arkret_canonical::decode_ed25519_multibase(
                                receipt_public_key_multibase,
                            )
                            .map_err(|error| error.to_string())
                            .and_then(|raw| {
                                ed25519_dalek::VerifyingKey::from_bytes(&raw)
                                    .map_err(|error| error.to_string())
                            }) {
                                Ok(key) => key,
                                Err(error) => {
                                    tracing::warn!(
                                        %endpoint,
                                        peer_id = %description.service_id,
                                        %error,
                                        "federation peer receipt assertion key is invalid"
                                    );
                                    continue;
                                }
                            };
                        let now = chrono::Utc::now();
                        let resolved_document = coland_services::identity::DidDocumentState {
                            did: document.id.to_string(),
                            did_document: document_value,
                            key_log_head: None,
                            seq: document_view.seq.unwrap_or_default(),
                            method_evidence: serde_json::json!({
                                "source": "peer_identity_document",
                                "receipts": document_view.receipts,
                            }),
                            fetched_at: now,
                            expires_at: now
                                + chrono::Duration::seconds(
                                    coland_services::identity::DID_DOCUMENT_HIGH_RISK_TTL_SECS,
                                ),
                            updated_at: now,
                        };
                        if let Err(error) =
                            state.cache_verified_federation_peer_document(resolved_document)
                        {
                            tracing::warn!(
                                %endpoint,
                                peer_id = %description.service_id,
                                %error,
                                "federation peer DID document could not enter the verified resolver snapshot"
                            );
                            continue;
                        }
                        let discovered = format!(
                            "{}|{}|{}",
                            endpoint.trim_end_matches('/'),
                            description.service_id,
                            description.trust_domain,
                        );
                        let previous_service_id = federation_peer_id(&configured);
                        let key_changed = state
                            .federation_peer_verifying_key(description.service_id.as_str())
                            .as_ref()
                            != Some(&verifying_key);
                        state.install_discovered_federation_peer_keys(
                            previous_service_id.as_deref(),
                            description.service_id.as_str(),
                            &expected_verification_method,
                            verifying_key,
                            &receipt_verification_method,
                            receipt_verifying_key,
                        );
                        if configured != discovered || key_changed {
                            tracing::info!(
                                peer_endpoint = %endpoint,
                                peer_id = %description.service_id,
                                peer_verification_method = %expected_verification_method,
                                "resolved federation peer service identity and assertion key"
                            );
                        }
                        resolved.insert(configured, discovered);
                    }
                    Ok(description) => {
                        tracing::warn!(
                            peer_endpoint = %endpoint,
                            peer_service_kind = %description.service_kind.as_str(),
                            peer_id = %description.service_id,
                            "federation peer describe returned an ineligible service"
                        );
                    }
                    Err(error) => {
                        tracing::debug!(%endpoint, %error, "federation peer identity is not ready; retrying");
                    }
                }
            }
            if resolved.is_empty() {
                retry_delay = retry_delay.saturating_mul(2).min(max_retry);
                continue;
            }
            state.apply_resolved_federation_peers(&resolved);
            retry_delay = max_retry;
        }
    });
}

fn federation_peer_endpoint(entry: &str) -> Option<String> {
    let entry = entry.trim();
    if entry.is_empty() {
        return None;
    }
    let (left, right) = entry
        .split_once('|')
        .map(|(left, right)| (left.trim(), right.trim()))
        .unwrap_or((entry, entry));
    [left, right]
        .into_iter()
        .find(|candidate| candidate.starts_with("https://") || candidate.starts_with("http://"))
        .map(|endpoint| endpoint.trim_end_matches('/').to_owned())
}

fn federation_peer_id(entry: &str) -> Option<String> {
    entry
        .split('|')
        .map(str::trim)
        .find(|candidate| arkret_identifiers::DidCoreId::new((*candidate).to_owned()).is_ok())
        .map(ToOwned::to_owned)
}

#[cfg(test)]
fn unresolved_federation_peer_endpoint(entry: &str) -> Option<String> {
    if federation_peer_id(entry).is_some() {
        return None;
    }
    federation_peer_endpoint(entry)
}

#[cfg(test)]
mod federation_peer_discovery_tests {
    use super::{federation_peer_endpoint, unresolved_federation_peer_endpoint};

    #[test]
    fn endpoint_only_peer_requires_runtime_discovery() {
        assert_eq!(
            unresolved_federation_peer_endpoint("https://peer.example/"),
            Some("https://peer.example".to_owned())
        );
        assert_eq!(
            unresolved_federation_peer_endpoint("https://peer.example|ak:did_core:webvh:zPeer"),
            None
        );
        assert_eq!(
            federation_peer_endpoint("https://peer.example|ak:did_core:webvh:zPeer"),
            Some("https://peer.example".to_owned())
        );
    }
}

/// Resolves once an OS shutdown signal arrives. On Unix this is `SIGINT`
/// (Ctrl-C) or `SIGTERM` (`docker stop`, Kubernetes pod termination, systemd
/// `stop`); on Windows it is the Ctrl-C signal that `cmd.exe`, PowerShell,
/// and the service control manager translate to a console close.
async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(error) = signal::ctrl_c().await {
            tracing::error!(%error, "failed to install Ctrl-C handler");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            Err(error) => {
                tracing::error!(%error, "failed to install SIGTERM handler");
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!(event = "shutdown_signal", signal = "SIGINT", "shutting down");
        }
        _ = terminate => {
            tracing::info!(event = "shutdown_signal", signal = "SIGTERM", "shutting down");
        }
    }
}

/// P5 (5.5) — container HEALTHCHECK subcommand. Hits the running
/// coland's `/health` endpoint over loopback and exits 0 on success,
/// 1 on any failure. The bind URL is derived from `COLAND_BIND` (defaults
/// `127.0.0.1:8698`); operators can override per-invocation with
/// `COLAND_HEALTHCHECK_URL` or by passing `--url <url>` after the
/// subcommand. This eliminates the runtime `curl` dependency the
/// previous Dockerfile relied on (incompatible with distroless bases).
async fn run_healthcheck(args: &[String]) -> anyhow::Result<()> {
    // Allow `coland healthcheck --url https://...` to override the
    // default. The CLI is intentionally trivial — there is no clap
    // dependency on the binary's hot path.
    let url_override = args
        .windows(2)
        .find(|pair| pair[0] == "--url")
        .map(|pair| pair[1].clone());
    let url = url_override
        .or_else(|| std::env::var("COLAND_HEALTHCHECK_URL").ok())
        .unwrap_or_else(|| {
            let bind = std::env::var("COLAND_BIND").unwrap_or_else(|_| "127.0.0.1:8698".to_owned());
            // COLAND_BIND uses a `host:port` shape — assume plain HTTP on
            // loopback, which matches the in-container HEALTHCHECK call
            // pattern (TLS termination lives at the reverse proxy).
            format!("http://{bind}/health")
        });

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    match client.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => {
            eprintln!("coland healthcheck OK: {url} → {}", resp.status());
            Ok(())
        }
        Ok(resp) => {
            eprintln!(
                "coland healthcheck FAIL: {url} → {} (non-success)",
                resp.status()
            );
            std::process::exit(1);
        }
        Err(err) => {
            eprintln!("coland healthcheck FAIL: {url} → {err}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tcp_latency_policy_tests {
    use std::sync::Arc;

    use salvo::fuse::{FuseConfig, FusePolicy};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::Notify;

    use super::*;

    #[tokio::test]
    async fn shared_listener_factory_sets_nodelay_on_real_accepted_socket() {
        let mut acceptor = low_latency_tcp_listener("127.0.0.1:0".to_owned())
            .try_bind()
            .await
            .unwrap();
        let address = acceptor.inner.local_addr().unwrap();
        let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
        acceptor.accept_pending_tcp().await.unwrap();
        let (stream, remote) = acceptor.pending.as_ref().unwrap();
        assert!(stream.nodelay().unwrap());
        assert_eq!(*remote, client.local_addr().unwrap());
        client.write_all(b"native tcp").await.unwrap();
        let mut accepted = acceptor.accept(None).await.unwrap();
        let mut bytes = [0; 10];
        accepted.stream.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"native tcp");
    }

    #[tokio::test]
    async fn configured_socket_survives_cancelled_fuse_admission() {
        struct PendingAdmission(Arc<Notify>);
        #[async_trait::async_trait]
        impl FusePolicy for PendingAdmission {
            async fn decide(&self, _info: &FuseInfo) -> FuseAction {
                self.0.notify_one();
                std::future::pending::<()>().await;
                FuseAction::Accept(FuseConfig::disabled())
            }
        }
        let mut acceptor = low_latency_tcp_listener("127.0.0.1:0".to_owned())
            .try_bind()
            .await
            .unwrap();
        let mut client = tokio::net::TcpStream::connect(acceptor.inner.local_addr().unwrap())
            .await
            .unwrap();
        let entered = Arc::new(Notify::new());
        let policy: ArcFusePolicy = Arc::new(PendingAdmission(entered.clone()));
        tokio::select! {
            result = acceptor.accept(Some(policy)) => panic!("admission unexpectedly completed: {}", result.is_ok()),
            () = entered.notified() => {}
        }
        let (stream, remote) = acceptor.pending.as_ref().unwrap();
        assert!(stream.nodelay().unwrap());
        assert_eq!(*remote, client.local_addr().unwrap());
        client.write_all(b"resumed").await.unwrap();
        let mut accepted = acceptor.accept(None).await.unwrap();
        assert_eq!(
            accepted.remote_addr.into_std().unwrap(),
            client.local_addr().unwrap()
        );
        let mut bytes = [0; 7];
        accepted.stream.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"resumed");
    }

    #[test]
    fn tls_listener_uses_the_same_native_nodelay_acceptor_before_handshake() {
        fn require_common_acceptor<L>(_: L)
        where
            L: Listener<Acceptor = salvo::conn::rustls::RustlsAcceptor<NoDelayTcpAcceptor>>,
        {
        }
        require_common_acceptor(
            low_latency_tcp_listener("127.0.0.1:0".to_owned())
                .rustls(RustlsConfig::new(Keycert::new())),
        );
    }
}
