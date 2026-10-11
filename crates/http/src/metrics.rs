use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use metrics::{counter, describe_counter, describe_gauge, describe_histogram, gauge, histogram};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};
use parking_lot::Mutex;
use salvo::http::Method;
use salvo::prelude::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use crate::state::AppState;

/// Fixed latency buckets for `coland_request_duration_seconds`. Kept byte-for-byte
/// identical to the historical hand-rolled exposition so `prometheus-alerts.yml`
/// and the Grafana dashboard continue to match.
const DURATION_BUCKETS: [f64; 11] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// P5 (5.4 metrics cardinality cap) — soft cap on the number of distinct
/// `op` label values we will emit on `coland_request_total` /
/// `coland_request_duration_seconds`. Above this we still record (no
/// data loss) but emit a sticky warning so on-call can audit whether a
/// path normalizer regressed and started leaking an unbounded id segment
/// (e.g. forgot to fold `ak:...` ids in `normalize_path_for_metrics`).
const REQUEST_OP_LABEL_CARDINALITY_THRESHOLD: usize = 200;

// ─────────────────────────────────────────────────────────────────────────
// Metric names. The `metrics-exporter-prometheus` text exporter renders metric
// keys verbatim — it does NOT auto-append the `_total` counter suffix — so the
// full wire name (including `_total`) is registered here. These exact names are
// referenced by `examples/prometheus-alerts.yml` and
// `docs/grafana-operational-dashboard.json` and MUST stay byte-stable.
// ─────────────────────────────────────────────────────────────────────────
const REQUEST_COUNTER: &str = "coland_request_total";
const REQUEST_DURATION: &str = "coland_request_duration_seconds";
const STREAM_SCAN_BYTES: &str = "coland_stream_scan_response_bytes_total";
const AUDIT_APPEND_FAILURES: &str = "coland_audit_append_failures_total";
const FEDERATION_DLQ: &str = "coland_federation_outbox_dead_letter_total";
const EGRESS_DENIED: &str = "coland_egress_denied_total";
const DIGEST_MISMATCH: &str = "coland_digest_mismatch_total";
const FEDERATION_RETRY: &str = "coland_federation_retry_total";
const FEDERATION_RETRY_DELAY: &str = "coland_federation_retry_delay_seconds";
const FEDERATION_LEASE_TAKEOVER: &str = "coland_federation_outbox_lease_takeover_total";
const DB_POOL_IN_USE: &str = "coland_db_pool_in_use";
const FEDERATION_OUTBOX_DEPTH: &str = "coland_federation_outbox_depth";
const FEDERATION_OUTBOX_STATE_DEPTH: &str = "coland_federation_outbox_state_depth";
const FEDERATION_OUTBOX_OLDEST_PENDING_AGE: &str =
    "coland_federation_outbox_oldest_pending_age_seconds";

// ─────────────────────────────────────────────────────────────────────────
// DID boundary counters (`did-usage-and-verification.md` §6, DID-P1-A03).
//
// These two counters are deliberately independent: "verify one signature"
// and "resolve one DID" are separate events, and only the first one is
// allowed to scale with ordinary traffic. `coland_did_resolve_total` carries
// a `source` label so a joint test can tell a local/binding-store hit from a
// real outbound fetch; `authority_network_call_count` is by definition the
// delta of the `source="network"` series.
// ─────────────────────────────────────────────────────────────────────────
const DID_RESOLVE: &str = "coland_did_resolve_total";
const SIGNATURE_VERIFY: &str = "coland_signature_verify_total";

/// The DID document came from coland's in-process document snapshot or its
/// durable local DID store. No outbound request.
pub const DID_RESOLVE_SOURCE_LOCAL_SNAPSHOT: &str = "local_snapshot";
/// The DID document came from an SDK resolver that performs no I/O
/// (`did:key` derivation, cached `did:web` / `did:webvh` entries).
pub const DID_RESOLVE_SOURCE_SDK_CACHE: &str = "sdk_cache";
/// The key material came from an accepted [`arkret_identity::VerifiedDidBinding`].
pub const DID_RESOLVE_SOURCE_BINDING_STORE: &str = "binding_store";
/// An actual outbound DID resolution / history fetch was issued. This is the
/// only source that counts as an authority network call.
pub const DID_RESOLVE_SOURCE_NETWORK: &str = "network";

/// A self Event producer proof verified under the device key its accepted
/// local PCR authorization binds; no DID resolution is involved.
pub const SIGNATURE_SCHEME_ACCEPTED_BINDING: &str = "ed25519_accepted_binding";
pub const SIGNATURE_SCHEME_PINNED_DOCUMENT: &str = "ed25519_pinned_document";
pub const SIGNATURE_SCHEME_MINIMAL_METADATA: &str = "ed25519_minimal_metadata";
pub const SIGNATURE_SCHEME_AGENT_SESSION: &str = "ed25519_agent_session";
pub const SIGNATURE_SCHEME_FEDERATED_SIGNER_EVIDENCE: &str = "ed25519_federated_signer_evidence";
pub const SIGNATURE_SCHEME_DEVELOPMENT: &str = "ed25519_development";

/// Buckets for `coland_federation_retry_delay_seconds` — spans the whole
/// scheduling range from a 1s dependency resubmission to the 1h transport cap.
const RETRY_DELAY_BUCKETS: [f64; 9] = [
    1.0, 5.0, 15.0, 60.0, 300.0, 900.0, 1_800.0, 3_600.0, 7_200.0,
];

static PROMETHEUS_HANDLE: OnceLock<Result<PrometheusHandle, String>> = OnceLock::new();

/// Cardinality tracker for the `op` label. The exporter does not surface the
/// live label-set count, so we track distinct `op` values here purely to drive
/// the P5 (5.4) sticky warning; this is observability bookkeeping, not the
/// metric store.
static OP_CARDINALITY: OnceLock<Mutex<OpCardinality>> = OnceLock::new();

#[derive(Default)]
struct OpCardinality {
    seen: BTreeSet<String>,
    warning_emitted: bool,
}

#[derive(Clone)]
pub struct MetricsMiddleware;

#[async_trait]
impl Handler for MetricsMiddleware {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        let op = request_op_label(req);
        let started = Instant::now();
        ctrl.call_next(req, depot, res).await;
        let status = res.status_code.unwrap_or(StatusCode::OK).as_u16();
        record_http_request(&op, status, started.elapsed());
        if req.method() == Method::POST
            && req.uri().path() == "/_arkret/self/streams/scan"
            && (200..300).contains(&status)
            && let Some(bytes) = res.body.size()
        {
            counter!(STREAM_SCAN_BYTES).increment(bytes);
        }
        if matches!(
            req.uri().path(),
            "/_arkret/self/streams/scan"
                | "/_arkret/open/realm-authority/bundle"
                | "/_arkret/self/committed-events/subscribe"
                | "/_arkret/ws"
        ) {
            tracing::debug!(target:"sync_network",method=%req.method(),path=req.uri().path(),status,
                response_body_bytes=res.body.size(),elapsed_ms=started.elapsed().as_millis() as u64,"realtime request");
        }
    }
}

/// Install (idempotently) the global Prometheus recorder and register metric
/// descriptions + the fixed latency buckets. Returns a reference to the shared
/// [`PrometheusHandle`] used to render the exposition on scrape.
fn prometheus_handle() -> Result<&'static PrometheusHandle, String> {
    match PROMETHEUS_HANDLE.get_or_init(|| {
        let handle = PrometheusBuilder::new()
            .set_buckets_for_metric(
                Matcher::Full(REQUEST_DURATION.to_owned()),
                &DURATION_BUCKETS,
            )
            .map_err(|err| err.to_string())?
            .set_buckets_for_metric(
                Matcher::Full(FEDERATION_RETRY_DELAY.to_owned()),
                &RETRY_DELAY_BUCKETS,
            )
            .map_err(|err| err.to_string())?
            .install_recorder()
            .map_err(|err| err.to_string())?;

        describe_counter!(REQUEST_COUNTER, "HTTP requests by operation and status.");
        describe_histogram!(REQUEST_DURATION, "HTTP request duration by operation.");
        describe_counter!(STREAM_SCAN_BYTES,"Successful caller-scoped stream scan JSON body bytes, excluding HTTP framing.");
        describe_counter!(
            AUDIT_APPEND_FAILURES,
            "Audit-log append failures (spec C.3.7)."
        );
        describe_counter!(
            FEDERATION_DLQ,
            "Federation outbox rows moved to the dead-letter ledger."
        );
        describe_counter!(
            EGRESS_DENIED,
            "Outbound requests denied by the deployment egress policy."
        );
        describe_counter!(
            DIGEST_MISMATCH,
            "Payload digest mismatches rejected by admission paths."
        );
        describe_counter!(
            FEDERATION_RETRY,
            "Federation delivery retry state transitions."
        );
        describe_histogram!(
            FEDERATION_RETRY_DELAY,
            "Scheduled delay until the next federation delivery attempt."
        );
        describe_counter!(
            FEDERATION_LEASE_TAKEOVER,
            "Federation delivery results discarded because the row's lease had already moved to another worker."
        );
        describe_counter!(
            DID_RESOLVE,
            "DID document resolutions by method and source; source=\"network\" is the authority network call count."
        );
        describe_counter!(
            SIGNATURE_VERIFY,
            "Cryptographic signature verifications by scheme and outcome. Counted once per signature, independently of DID resolution."
        );
        describe_gauge!(
            DB_POOL_IN_USE,
            "PostgreSQL pool connections currently checked out."
        );
        describe_gauge!(
            FEDERATION_OUTBOX_DEPTH,
            "Federation outbox rows still owed to a peer (pending or leased)."
        );
        describe_gauge!(
            FEDERATION_OUTBOX_STATE_DEPTH,
            "Federation outbox rows by lifecycle state and peer."
        );
        describe_gauge!(
            FEDERATION_OUTBOX_OLDEST_PENDING_AGE,
            "Age of the oldest federation outbox row still owed to a peer."
        );
        Ok(handle)
    }) {
        Ok(handle) => Ok(handle),
        Err(err) => Err(err.clone()),
    }
}

fn op_cardinality() -> &'static Mutex<OpCardinality> {
    OP_CARDINALITY.get_or_init(|| Mutex::new(OpCardinality::default()))
}

pub async fn spawn_metrics_server(
    state: AppState,
    bind: SocketAddr,
) -> anyhow::Result<JoinHandle<()>> {
    let listener = TcpListener::bind(bind).await?;
    Ok(spawn_metrics_server_on(state, listener))
}

/// Serve `/metrics` on an already-bound listener. Split out from
/// [`spawn_metrics_server`] so a test can bind port 0, learn the port, and then
/// scrape it without racing another binder.
pub fn spawn_metrics_server_on(state: AppState, listener: TcpListener) -> JoinHandle<()> {
    // Install the recorder eagerly so the very first request after startup
    // records into the global recorder rather than the no-op fallback.
    if let Err(error) = prometheus_handle() {
        tracing::error!(%error, "failed to install Prometheus metrics recorder");
    }
    // Bound the number of concurrent in-flight scrape connections so a flood of
    // slow/zombie connections cannot leak unbounded tasks + socket handles
    // (SOL-02-005). A scrape endpoint never needs high concurrency.
    let connection_limit = std::sync::Arc::new(tokio::sync::Semaphore::new(
        METRICS_MAX_CONCURRENT_CONNECTIONS,
    ));
    tokio::spawn(async move {
        loop {
            let (stream, remote_addr) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(error) => {
                    tracing::error!(%error, "metrics listener accept failed");
                    continue;
                }
            };
            // Acquire a permit before spawning; if all permits are held, drop the
            // connection rather than queueing unbounded work.
            let Ok(permit) = connection_limit.clone().try_acquire_owned() else {
                tracing::debug!(%remote_addr, "metrics scrape rejected: connection limit reached");
                drop(stream);
                continue;
            };
            let state = state.clone();
            tokio::spawn(async move {
                let _permit = permit;
                // Cap total connection lifetime so a connection that never sends a
                // request (slowloris/zombie) cannot pin its task forever.
                match tokio::time::timeout(
                    METRICS_CONNECTION_TIMEOUT,
                    handle_metrics_connection(stream, state),
                )
                .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        tracing::debug!(%remote_addr, %error, "metrics scrape failed")
                    }
                    Err(_) => {
                        tracing::debug!(%remote_addr, "metrics scrape timed out")
                    }
                }
            });
        }
    })
}

/// Upper bound on concurrent metrics scrape connections (SOL-02-005).
const METRICS_MAX_CONCURRENT_CONNECTIONS: usize = 64;
/// Maximum wall-clock lifetime for a single scrape connection (SOL-02-005).
const METRICS_CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

async fn handle_metrics_connection(mut stream: TcpStream, state: AppState) -> anyhow::Result<()> {
    let mut buffer = [0_u8; 2048];
    let read = stream.read(&mut buffer).await?;
    let request = std::str::from_utf8(&buffer[..read]).unwrap_or_default();
    let mut parts = request
        .lines()
        .next()
        .unwrap_or_default()
        .split_whitespace();
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or_default();

    let (status, body) = if (method == "GET" || method == "HEAD") && path == "/metrics" {
        ("200 OK", render_metrics(&state).await)
    } else {
        ("404 Not Found", "not found\n".to_owned())
    };

    let include_body = method != "HEAD";
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    if include_body {
        stream.write_all(body.as_bytes()).await?;
    }
    Ok(())
}

/// Render the Prometheus exposition. Scrape-time gauges (DB pool depth,
/// federation outbox depth) are sampled from live [`AppState`] just before
/// the exposition is rendered, mirroring the pull semantics of the previous
/// hand-rolled endpoint.
pub async fn render_metrics(state: &AppState) -> String {
    // Sample scrape-time gauges into the recorder right before rendering.
    gauge!(DB_POOL_IN_USE).set(state.jobs().database_pool_in_use() as f64);
    sample_federation_outbox_gauges(state).await;

    match prometheus_handle() {
        Ok(handle) => handle.render(),
        Err(error) => {
            tracing::error!(%error, "metrics recorder unavailable");
            format!("# metrics recorder unavailable: {error}\n")
        }
    }
}

/// Increment the audit-append-failure counter. Called from
/// `routing::admin::audit::append_audit_log` when the persistence layer
/// rejects the append; the counter feeds the `coland_audit_append_failures_total`
/// metric for alerting. Spec: C.3.7.
pub fn record_audit_append_failure() {
    counter!(AUDIT_APPEND_FAILURES).increment(1);
}

/// P5 (5.4) — bump the federation-outbox dead-letter counter. Called from
/// `routing::federation::outbox` at the *decision* boundary (we have given up
/// on this row), not at the persistence outcome, so an alert fires even if the
/// durable ledger write also failed. Feeds
/// `coland_federation_outbox_dead_letter_total`.
pub fn record_federation_outbox_dead_letter(reason: &str) {
    counter!(FEDERATION_DLQ, "reason" => normalize_label(reason)).increment(1);
}

/// Delay the dispatcher scheduled before the next attempt on one row.
pub fn record_federation_retry_delay(delay_secs: i64) {
    histogram!(FEDERATION_RETRY_DELAY).record(delay_secs.max(0) as f64);
}

/// One worker's delivery result was dropped because the row's lease had
/// already been taken over — the signal that a dispatcher replica overran its
/// lease or died mid-delivery and another replica resumed the row.
pub fn record_federation_outbox_lease_takeover() {
    counter!(FEDERATION_LEASE_TAKEOVER).increment(1);
}

pub fn record_egress_denied(reason: &str, target_class: &str) {
    counter!(
        EGRESS_DENIED,
        "reason" => normalize_label(reason),
        "target_class" => normalize_label(target_class)
    )
    .increment(1);
}

/// Record one DID document resolution.
///
/// `source` MUST be one of the `DID_RESOLVE_SOURCE_*` constants.
/// `DID_RESOLVE_SOURCE_NETWORK` MUST only be used when an outbound request was
/// actually issued — the joint call-count contract reads that series as
/// `authority_network_call_count`.
pub fn record_did_resolve(method: &str, source: &'static str) {
    counter!(
        DID_RESOLVE,
        "method" => normalize_label(method),
        "source" => source,
    )
    .increment(1);
}

/// Record one signature verification. Called once per signature on every
/// verification path, including the zero-resolver ones, so that
/// "verified N signatures while resolving 0 DIDs" is directly observable.
pub fn record_signature_verify(scheme: &'static str, ok: bool) {
    counter!(
        SIGNATURE_VERIFY,
        "scheme" => scheme,
        "outcome" => if ok { "success" } else { "failure" },
    )
    .increment(1);
}

pub fn record_digest_mismatch(scope: &str) {
    counter!(DIGEST_MISMATCH, "scope" => normalize_label(scope)).increment(1);
}

pub fn record_federation_retry_state(state: &str) {
    counter!(FEDERATION_RETRY, "state" => normalize_label(state)).increment(1);
}

/// Sample the outbox depth gauges from the aggregate the store computes.
///
/// Per-`(state, peer)` depth plus the oldest still-owed row's age are what an
/// operator needs to tell "one peer is down" from "the dispatcher is stuck",
/// which a single scalar depth cannot express.
async fn sample_federation_outbox_gauges(state: &AppState) {
    let buckets = match state.federation().delivery_state_depth().await {
        Ok(buckets) => buckets,
        Err(error) => {
            tracing::warn!(%error, "federation outbox depth gauge unavailable");
            return;
        }
    };
    let now = chrono::Utc::now().timestamp();
    let mut owed = 0_i64;
    let mut oldest_owed: Option<i64> = None;
    for bucket in &buckets {
        gauge!(
            FEDERATION_OUTBOX_STATE_DEPTH,
            "state" => bucket.state.as_str(),
            "peer" => normalize_label(bucket.peer_id.as_str()),
        )
        .set(bucket.depth as f64);
        if bucket.state.is_terminal() {
            continue;
        }
        owed += bucket.depth;
        if let Some(created_at) = bucket.oldest_created_at {
            oldest_owed = Some(oldest_owed.map_or(created_at, |oldest| oldest.min(created_at)));
        }
    }
    gauge!(FEDERATION_OUTBOX_DEPTH).set(owed as f64);
    gauge!(FEDERATION_OUTBOX_OLDEST_PENDING_AGE)
        .set(oldest_owed.map_or(0.0, |created_at| (now - created_at).max(0) as f64));
}

fn record_http_request(op: &str, status: u16, duration: Duration) {
    counter!(
        REQUEST_COUNTER,
        "op" => op.to_owned(),
        "status" => status.to_string()
    )
    .increment(1);
    histogram!(REQUEST_DURATION, "op" => op.to_owned()).record(duration.as_secs_f64());

    // Cardinality cap: warn (sticky, once per crossing) when the unique `op`
    // label count crosses `REQUEST_OP_LABEL_CARDINALITY_THRESHOLD`. We do not
    // drop any labels here — the counter still records — but a sustained
    // upward drift typically means `normalize_path_for_metrics` failed to fold
    // an id segment and the time-series store is about to explode.
    let warning_payload = {
        let mut card = op_cardinality().lock();
        card.seen.insert(op.to_owned());
        let unique_ops = card.seen.len();
        if unique_ops > REQUEST_OP_LABEL_CARDINALITY_THRESHOLD && !card.warning_emitted {
            card.warning_emitted = true;
            Some(unique_ops)
        } else {
            None
        }
    };

    if let Some(unique_ops) = warning_payload {
        tracing::warn!(
            target: "metrics_cardinality",
            unique_op_labels = unique_ops,
            threshold = REQUEST_OP_LABEL_CARDINALITY_THRESHOLD,
            "coland_request_total operation label cardinality crossed the warning threshold; \
             audit normalize_path_for_metrics for an id segment that is not being folded"
        );
    }
}

fn request_op_label(req: &Request) -> String {
    if let Some(operation_id) = canonical_event_read_operation(req) {
        return operation_id.to_owned();
    }
    format!(
        "{} {}",
        req.method(),
        normalize_path_for_metrics(req.uri().path())
    )
}

fn canonical_event_read_operation(req: &Request) -> Option<&'static str> {
    let method = req.method().as_str();
    let path = req.uri().path();
    match (method, path) {
        ("POST", "/_arkret/self/streams/scan") => {
            Some(arkret_wire::ServiceOperationId::SELF_COMMITTED_EVENT_READ_SCAN_V1)
        }
        ("GET", "/_arkret/self/committed-events/subscribe") => {
            Some(arkret_wire::ServiceOperationId::SELF_COMMITTED_EVENT_STREAM_SUBSCRIBE_V1)
        }
        ("POST", "/_arkret/peer/mls/group-state-material") => {
            Some(arkret_wire::ServiceOperationId::PEER_MLS_READ_GROUP_STATE_MATERIAL_V1)
        }
        ("POST", "/_arkret/peer/streams/scan") => {
            Some(arkret_wire::ServiceOperationId::PEER_COMMITTED_EVENT_READ_SCAN_V1)
        }
        _ => None,
    }
}

fn normalize_path_for_metrics(path: &str) -> String {
    if path == "/" {
        return "/".to_owned();
    }
    let segments = path
        .trim_start_matches('/')
        .split('/')
        .map(|segment| {
            if looks_like_path_id(segment) {
                "{id}"
            } else {
                segment
            }
        })
        .collect::<Vec<_>>();
    format!("/{}", segments.join("/"))
}

fn looks_like_path_id(segment: &str) -> bool {
    segment.starts_with("ak:")
        || segment.starts_with("did:")
        || (segment.len() >= 16
            && segment
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == ':'))
}

fn normalize_label(value: &str) -> String {
    let normalized = value
        .trim()
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
                ch.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>();
    let normalized = normalized.trim_matches('_').to_owned();
    if normalized.is_empty() {
        "unknown".to_owned()
    } else {
        normalized
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Render against the live global recorder. Tests share one process-wide
    /// recorder, so assertions check for substring presence (monotonic
    /// counters never decrease) rather than exact values.
    fn render() -> String {
        prometheus_handle().expect("recorder installs").render()
    }

    #[test]
    fn metrics_render_required_http_series() {
        // Recorder must be installed before any record, else metrics land in
        // the global no-op recorder (production installs it at startup via
        // `spawn_metrics_server`).
        let _ = prometheus_handle();
        let op = "GET /_arkret/self/committed-events/{event_id}";
        record_http_request(op, 200, Duration::from_millis(25));
        let rendered = render();

        // Byte-stable wire names referenced by prometheus-alerts.yml + Grafana.
        assert!(rendered.contains("coland_request_total"));
        assert!(rendered.contains("status=\"200\""));
        assert!(rendered.contains("coland_request_duration_seconds_bucket"));
        assert!(rendered.contains("coland_request_duration_seconds_sum"));
        assert!(rendered.contains("coland_request_duration_seconds_count"));
        // Fixed bucket boundaries must survive the migration.
        assert!(rendered.contains("le=\"0.005\""));
        assert!(rendered.contains("le=\"10\"") || rendered.contains("le=\"10.0\""));
        assert!(rendered.contains("le=\"+Inf\""));
    }

    #[test]
    fn event_read_query_bindings_use_registered_metrics_operation_labels() {
        use salvo::test::TestClient;

        let request = TestClient::post("http://localhost/_arkret/self/streams/scan").build();
        assert_eq!(
            request_op_label(&request),
            "ak.self.committed_event.read.scan.v1"
        );

        let peer_request = TestClient::post("http://localhost/_arkret/peer/streams/scan").build();
        assert_eq!(
            request_op_label(&peer_request),
            "ak.peer.committed_event.read.scan.v1"
        );

        let peer_mls =
            TestClient::post("http://localhost/_arkret/peer/mls/group-state-material").build();
        assert_eq!(
            request_op_label(&peer_mls),
            "ak.peer.mls.read.group_state_material.v1"
        );

        for path in [
            "/_arkret/self/seals/mls-governance-proof",
            "/_arkret/peer/seals/mls-governance-proof",
        ] {
            let retired = TestClient::post(format!("http://localhost{path}")).build();
            assert_eq!(canonical_event_read_operation(&retired), None);
        }
    }

    #[test]
    fn metrics_render_operational_counters() {
        let _ = prometheus_handle();
        record_egress_denied("blocked address", "federation outbox");
        record_digest_mismatch("blob upload");
        record_federation_retry_state("retry scheduled");
        record_audit_append_failure();
        record_federation_outbox_dead_letter("retry_budget_exhausted");
        record_federation_retry_delay(42);
        record_federation_outbox_lease_takeover();
        let rendered = render();

        // Byte-stable wire names (counters carry the exporter `_total` suffix).
        assert!(rendered.contains("coland_egress_denied_total"));
        assert!(rendered.contains("reason=\"blocked_address\""));
        assert!(rendered.contains("target_class=\"federation_outbox\""));
        assert!(rendered.contains("coland_digest_mismatch_total"));
        assert!(rendered.contains("scope=\"blob_upload\""));
        assert!(rendered.contains("coland_federation_retry_total"));
        assert!(rendered.contains("state=\"retry_scheduled\""));
        assert!(rendered.contains("coland_audit_append_failures_total"));
        assert!(rendered.contains("coland_federation_outbox_dead_letter_total"));
        assert!(rendered.contains("reason=\"retry_budget_exhausted\""));
        assert!(rendered.contains("coland_federation_retry_delay_seconds"));
        assert!(rendered.contains("coland_federation_outbox_lease_takeover_total"));
    }

    /// Read one Prometheus counter sample value out of a rendered exposition.
    fn sample(rendered: &str, series_prefix: &str) -> f64 {
        rendered
            .lines()
            .find(|line| line.starts_with(series_prefix))
            .and_then(|line| line.rsplit(' ').next())
            .and_then(|value| value.parse::<f64>().ok())
            .unwrap_or_default()
    }

    // DID-P1-A03 / DID-P1-C01 — the joint call-count contract reads these two
    // series, so they must exist, carry their labels, and increase.
    #[test]
    fn did_boundary_counters_are_exposed_and_grow() {
        let _ = prometheus_handle();
        let resolve_series = "coland_did_resolve_total{method=\"webvh\",source=\"network\"}";
        // The exporter renders labels in declaration order, so these series
        // names mirror the `counter!` call sites exactly.
        let verify_series = "coland_signature_verify_total{scheme=\"ed25519_accepted_binding\",outcome=\"success\"}";

        record_did_resolve("webvh", DID_RESOLVE_SOURCE_NETWORK);
        record_signature_verify(SIGNATURE_SCHEME_ACCEPTED_BINDING, true);
        let before = render();
        let resolve_before = sample(&before, resolve_series);
        let verify_before = sample(&before, verify_series);
        assert!(
            before.contains("coland_did_resolve_total"),
            "resolve counter must be exposed"
        );
        assert!(
            before.contains("coland_signature_verify_total"),
            "signature counter must be exposed"
        );
        assert!(before.contains(resolve_series), "{before}");
        assert!(before.contains(verify_series), "{before}");

        // Five ordinary verifications served from accepted bindings, zero
        // network resolutions: exactly the property the joint test asserts.
        for _ in 0..5 {
            record_signature_verify(SIGNATURE_SCHEME_ACCEPTED_BINDING, true);
            record_did_resolve("webvh", DID_RESOLVE_SOURCE_BINDING_STORE);
        }
        let after = render();
        assert_eq!(
            sample(&after, verify_series),
            verify_before + 5.0,
            "every signature must be counted"
        );
        assert_eq!(
            sample(&after, resolve_series),
            resolve_before,
            "binding-store hits must not increment the network source"
        );
        assert!(
            after.contains("source=\"binding_store\""),
            "binding-store source label must be exposed: {after}"
        );
    }

    #[tokio::test]
    async fn metrics_endpoint_serves_the_did_boundary_counters() {
        let _ = prometheus_handle();
        record_did_resolve("key", DID_RESOLVE_SOURCE_SDK_CACHE);
        record_signature_verify("ed25519_detached_jws", true);

        let state = AppState::new(
            crate::config::AppConfig {
                object_storage: crate::config::ObjectStorageConfig::local(
                    std::env::temp_dir().join("coland-metrics-endpoint-test"),
                ),
                ..crate::config::AppConfig::test_default()
            },
            coland_storage_postgres::Db { pool: None },
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let server = spawn_metrics_server_on(state, listener);

        let mut stream = TcpStream::connect(addr).await.expect("connect");
        stream
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .expect("request");
        let mut body = Vec::new();
        stream.read_to_end(&mut body).await.expect("response");
        server.abort();

        let body = String::from_utf8_lossy(&body);
        assert!(body.starts_with("HTTP/1.1 200 OK"), "{body}");
        assert!(body.contains("coland_did_resolve_total"), "{body}");
        assert!(body.contains("coland_signature_verify_total"), "{body}");
        assert!(body.contains("source=\"sdk_cache\""), "{body}");
    }

    #[test]
    fn path_ids_are_normalized_for_operation_label() {
        assert_eq!(
            normalize_path_for_metrics(
                "/_coland/self/realms/ak:realm:AS1N4QnbZ6JgVObAF-yTx1GWoK2XnO_vUaZ2qe0WCyQV/events"
            ),
            "/_coland/self/realms/{id}/events"
        );
    }
}
