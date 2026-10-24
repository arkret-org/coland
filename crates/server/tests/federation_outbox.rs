//! G3.S0 integration test — covers the `routing::federation::outbox`
//! enqueue → background-dispatch → success-recording loop.
//!
//! The test spins up a tiny TCP mock peer so we don't add a new dev dependency,
//! enqueues an outbox row directly, runs one dispatcher pass, then
//! asserts:
//!
//!   1. The mock peer received exactly one POST with the spec-required `Idempotency-Key` +
//!      `Content-Digest` headers (RFC 9530, and the deterministic key shape G3.S0 emits).
//!   2. The outbox row was marked `delivered_at IS NOT NULL` and `last_status` records the mock's
//!      2xx response.
//!
//! The dispatcher's background loop is NOT spawned here — we drive
//! `FederationDispatcher::run_one_pass` directly so the test stays
//! deterministic without sleeping for the 5s poll interval.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::sync::{Arc, LazyLock, mpsc};
use std::time::Duration;

use arkret_models_collaboration::authority_commit::{
    CommittedEventReplicationOutcome, CommittedEventSubmission, CommittedReplicationBranch,
    PeerAuthoritySubmitRequestBody, PeerAuthoritySubmitResponseBody,
    PeerCommittedReplicationRequestBody, PeerCommittedReplicationResponseBody,
};
use arkret_models_identity::ResolutionCommitment;
use arkret_wire::{Did, DidCoreId, ServiceKind, TrustDomainId};
use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use coland_http::config::{AppConfig, ObjectStorageConfig};
use coland_http::routing::federation::outbox::{FederationDispatcher, enqueue_outbound};
use coland_http::routing::federation::outbox_operator;
use coland_http::state::AppState;
use coland_services::ServiceResult;
use coland_services::service_route::{
    ServiceRouteFetcher, VerifiedRouteCandidate, VerifiedServiceDescribeMetadata,
};
use coland_storage::FederationOutboxState;
use coland_test_support::AppStateTestExt as _;
use ed25519_dalek::{Signature, SigningKey, Verifier as _, VerifyingKey};
use sha2::{Digest, Sha256};

const PEER_SERVICE_DID: &str = "did:web:peer.example";
const PEER_SERVICE_ID: &str = "ak:did_core:web:peer.example";
const DENIED_PEER_SERVICE_DID: &str = "did:web:denied-peer.example";
const DENIED_PEER_SERVICE_ID: &str = "ak:did_core:web:denied-peer.example";
const FEDERATION_ENDPOINT: &str = "/_arkret/peer/events";
const IDEMPOTENCY_KEY: &str = "ak:outbox:test-idem-key-0001";
/// The current `/_arkret/peer/events` carrier the Realm fanout planner
/// queues: one committed Realm Event with its source RealmCommit, encoded as
/// canonical JSON (`PeerAuthoritySubmitRequestBody::CommittedReplication`).
static PAYLOAD_JSON: LazyLock<String> = LazyLock::new(committed_replication_payload);
/// The peer's typed receive outcome for [`PAYLOAD_JSON`].
static STORED_OUTCOME: LazyLock<String> =
    LazyLock::new(|| replication_outcome(CommittedEventReplicationOutcome::Stored {}));
static DUPLICATE_OUTCOME: LazyLock<String> =
    LazyLock::new(|| replication_outcome(CommittedEventReplicationOutcome::Duplicate {}));

fn committed_replication_payload() -> String {
    let created_at = chrono::DateTime::parse_from_rfc3339("2026-09-03T00:00:00.000Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let genesis = arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        arkret_canonical::sha256_bytes(b"federation-outbox-realm-genesis"),
    );
    let realm_id = arkret_wire::RealmId::from_event_id(&genesis);
    let author = DidCoreId::new("ak:did_core:web:author.outbox.internal").unwrap();
    let station = DidCoreId::new("ak:did_core:web:sender.outbox.internal").unwrap();
    let mut event = arkret_wire::test_support::raw_event_at(
        arkret_wire::EventKind::MessageCreate.as_str(),
        arkret_wire::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        author,
        station,
        serde_json::json!({
            "strand_id": arkret_wire::StrandId::from_event_id(&genesis),
            "track_name": "discussion",
            "content": {"kind": "ak.content.text", "body": "outbox", "format": "plain"}
        }),
        created_at,
    )
    .unwrap();
    let event_digest = arkret_wire::Hash::new(
        event
            .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap(),
    )
    .unwrap();
    // Delivery is the unit under test, not producer verification, so the
    // Event carries the structural-only detached JWS bound to its bytes.
    event.producer_proof = Some(arkret_wire::ProducerEventProof {
        kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
        verification_method: arkret_wire::DidUrl::new("did:web:author.outbox.internal#device")
            .unwrap(),
        event_digest: event_digest.clone(),
        created_at,
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: arkret_wire::test_support::structural_only_detached_jws(&event_digest),
    });
    let source_commit = arkret_wire::RealmCommit {
        producer_signer_fact_digest: None,
        commit_id: arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
            b"federation-outbox-commit-1",
        )),
        realm_id: realm_id.clone(),
        stream_ref: arkret_wire::CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        },
        stream_position: 1,
        previous_commit_ref: Some(arkret_wire::RealmCommitId::from_digest(
            arkret_canonical::sha256_bytes(b"federation-outbox-commit-0"),
        )),
        event_ref: event.event_id.clone(),
        governance_generation: 0,
        authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(genesis),
        committed_at: created_at,
        signature: arkret_wire::DetachedObjectSignature {
            context: arkret_wire::DetachedSignatureContext::RealmCommit,
            signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
            verification_method: arkret_wire::DidUrl::new(
                "did:web:sender.outbox.internal#authority",
            )
            .unwrap(),
            signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "3".repeat(64))).unwrap(),
            created_at,
            signature: arkret_wire::Base64UrlString::new("c2lnbmF0dXJl".to_owned()).unwrap(),
        },
    };
    let request =
        PeerAuthoritySubmitRequestBody::CommittedReplication(PeerCommittedReplicationRequestBody {
            branch: CommittedReplicationBranch::CommittedReplication,
            replications: vec![CommittedEventSubmission {
                producer_signer_fact: None,
                event_submission: arkret_wire::EventAdmissionSubmission::new(event),
                source_commit,
                genesis_event_ref: None,
                welcomes: None,
            }],
        });
    request
        .validate()
        .expect("fixture is a current committed replication carrier");
    String::from_utf8(arkret_canonical::canonical_json_bytes(&request).unwrap()).unwrap()
}

fn replication_outcome(record: CommittedEventReplicationOutcome) -> String {
    serde_json::to_string(&PeerAuthoritySubmitResponseBody::CommittedReplication(
        PeerCommittedReplicationResponseBody {
            branch: CommittedReplicationBranch::CommittedReplication,
            replication_outcomes: vec![record],
        },
    ))
    .unwrap()
}

#[derive(Clone)]
struct VerifiedPeerRoute {
    service_id: DidCoreId,
    candidate: VerifiedRouteCandidate,
}

struct FixtureVerifiedRouteFetcher {
    routes: BTreeMap<(String, String), VerifiedRouteCandidate>,
}

impl FixtureVerifiedRouteFetcher {
    /// Model the output of independent current DID-method and Describe
    /// verification without turning the delivery peer into a second mock
    /// discovery server. The production resolver still validates every stable
    /// binding and accepted native method state before exposing the route to the dispatcher.
    fn new(routes: &[VerifiedPeerRoute]) -> Self {
        Self {
            routes: routes
                .iter()
                .map(|route| {
                    (
                        (
                            route.service_id.to_string(),
                            ServiceKind::Station.as_str().to_owned(),
                        ),
                        route.candidate.clone(),
                    )
                })
                .collect(),
        }
    }

    fn route(&self, service_id: &DidCoreId, service_kind: &str) -> Option<VerifiedRouteCandidate> {
        self.routes
            .get(&(service_id.to_string(), service_kind.to_owned()))
            .cloned()
    }
}

#[async_trait]
impl ServiceRouteFetcher for FixtureVerifiedRouteFetcher {
    async fn fetch_current(
        &self,
        service_id: &DidCoreId,
        service_kind: &str,
    ) -> ServiceResult<Option<VerifiedRouteCandidate>> {
        Ok(self.route(service_id, service_kind))
    }
}

fn verified_peer_route(
    did: &str,
    expected_core_id: &str,
    base_url: &str,
    trust_domain: &str,
) -> VerifiedPeerRoute {
    let did = Did::new(did.to_owned()).expect("fixture peer DID");
    let service_id =
        arkret_wire::project_did_to_core_id(&did).expect("fixture peer core projection");
    assert_eq!(service_id.as_str(), expected_core_id);
    let base_url = format!("{}/", base_url.trim_end_matches('/'));
    let evidence = fixture_route_evidence(&did, &service_id, &base_url);
    let boundary = evidence.method_history_evidence.boundary();
    let commitment = ResolutionCommitment {
        did: did.clone(),
        method_history_head: boundary.to_method_history_head.clone(),
        version_id: boundary.to_version_id.clone(),
    };
    VerifiedPeerRoute {
        service_id: service_id.clone(),
        candidate: VerifiedRouteCandidate {
            evidence,
            description: VerifiedServiceDescribeMetadata {
                supported_profiles: Vec::new(),
                service_id,
                service_kind: ServiceKind::Station.as_str().to_owned(),
                service_resolution: commitment,
                http_json_base_url: base_url,
                trust_domain: TrustDomainId::new(trust_domain).expect("fixture peer trust domain"),
                protocol_version: arkret_wire::PROTOCOL_VERSION.to_owned(),
                supported_operation_bundles: vec![
                    arkret_wire::role_describe_bundle_descriptor(ServiceKind::Station)
                        .unwrap()
                        .operation_bundle_id
                        .to_owned(),
                ],
            },
        },
    }
}

/// Peer trust domains stay outside the reserved test-material registry
/// (`example`, `invalid`, `localhost`, `test` top labels): a formal route
/// resolution refuses those with `test_signing_material_denied` before any
/// delivery is attempted.
fn standard_peer_route(base_url: &str) -> VerifiedPeerRoute {
    verified_peer_route(
        PEER_SERVICE_DID,
        PEER_SERVICE_ID,
        base_url,
        "ak:trust_domain:peer.outbox.internal",
    )
}

fn denied_peer_route() -> VerifiedPeerRoute {
    verified_peer_route(
        DENIED_PEER_SERVICE_DID,
        DENIED_PEER_SERVICE_ID,
        "https://169.254.169.254",
        "ak:trust_domain:denied-peer.outbox.internal",
    )
}

fn unique_peer_route(prefix: &str, base_url: &str) -> VerifiedPeerRoute {
    let suffix = uuid::Uuid::now_v7().simple().to_string();
    let did = format!("did:web:{prefix}-{suffix}.example");
    let core_id = format!("ak:did_core:web:{prefix}-{suffix}.example");
    verified_peer_route(
        &did,
        &core_id,
        base_url,
        "ak:trust_domain:peer.outbox.internal",
    )
}

fn install_verified_routes(state: &AppState, routes: &[VerifiedPeerRoute]) {
    state.test_install_service_route_fetcher(Arc::new(FixtureVerifiedRouteFetcher::new(routes)));
}

struct CapturedSignedRequestBody {
    captured: String,
    target_uri: String,
    state: AppState,
    row_id: String,
}

/// Spin up a single-shot HTTP/1.1 mock peer on a random local port.
/// Returns the base URL the dispatcher posts to + a channel receiver
/// that the test reads the captured raw request from after the worker
/// finishes its delivery pass.
/// One canned reply from the mock peer.
#[derive(Clone, Copy)]
struct MockResponse {
    status: &'static str,
    /// Extra header lines, each already `\r\n`-terminated.
    extra_headers: &'static str,
    body: &'static [u8],
}

impl MockResponse {
    const fn new(status: &'static str, body: &'static [u8]) -> Self {
        Self {
            status,
            extra_headers: "",
            body,
        }
    }

    const fn with_headers(
        status: &'static str,
        extra_headers: &'static str,
        body: &'static [u8],
    ) -> Self {
        Self {
            status,
            extra_headers,
            body,
        }
    }
}

fn spawn_mock_peer() -> (String, mpsc::Receiver<String>) {
    spawn_mock_peer_with_status("200 OK", STORED_OUTCOME.as_bytes())
}

fn spawn_mock_peer_with_status(
    status: &'static str,
    body: &'static [u8],
) -> (String, mpsc::Receiver<String>) {
    spawn_mock_peer_responses(vec![MockResponse::new(status, body)])
}

/// Serve one canned reply per entry, in order, then stop. Multi-response tests
/// (retry, resubmission) need more than the single-shot peer.
fn spawn_mock_peer_responses(responses: Vec<MockResponse>) -> (String, mpsc::Receiver<String>) {
    coland_test_support::native_tls::require_trust_store();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("https://{}", listener.local_addr().unwrap());
    let tls = Arc::new(coland_test_support::native_tls::server_config());
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for response in responses {
            let Ok((stream, _)) = listener.accept() else {
                return;
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut stream = rustls::StreamOwned::new(
                rustls::ServerConnection::new(tls.clone()).unwrap(),
                stream,
            );
            let mut received = Vec::new();
            let mut buffer = [0u8; 16384];
            loop {
                let n = stream.read(&mut buffer).unwrap_or(0);
                if n == 0 {
                    break;
                }
                received.extend_from_slice(&buffer[..n]);
                if let Some(end) = received.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&received[..end]).to_ascii_lowercase();
                    let length = headers
                        .lines()
                        .find_map(|l| {
                            l.strip_prefix("content-length:")
                                .and_then(|v| v.trim().parse::<usize>().ok())
                        })
                        .unwrap_or(0);
                    if received.len() >= end + 4 + length {
                        break;
                    }
                }
                assert!(received.len() < 1024 * 1024, "mock request exceeds 1 MiB");
            }
            let request = String::from_utf8_lossy(&received).to_string();
            let head = format!(
                "HTTP/1.1 {}\r\ncontent-type: application/json\r\n{}content-length: {}\r\nconnection: close\r\n\r\n",
                response.status,
                response.extra_headers,
                response.body.len(),
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(response.body);
            let _ = tx.send(request);
        }
    });
    (url, rx)
}

fn outbox_test_config() -> AppConfig {
    AppConfig {
        object_storage: ObjectStorageConfig::local(std::env::temp_dir().join("coland-outbox-test")),
        development_mode: true,
        did_resolver_allow_methods: vec!["web".to_owned(), "key".to_owned()],
        trust_domain: arkret_identifiers::TrustDomainId::new("ak:trust_domain:coland-outbox.local")
            .unwrap(),
        ..coland_test_support::app_config()
    }
}

#[tokio::test]
async fn enqueue_then_dispatch_delivers_payload_with_spec_headers() {
    let captured = capture_signed_request().await;

    // Header assertions — Idempotency-Key, Content-Digest, trust-domain
    // binding, and RFC 9421 Signature headers are mandatory on every
    // outbound POST per spec federation.md §3.2 + §8.5.
    let lower = captured.captured.to_ascii_lowercase();
    assert!(
        lower.contains("idempotency-key: ak:outbox:test-idem-key-0001"),
        "captured request missing Idempotency-Key header; got: {}",
        captured.captured
    );
    assert!(
        lower.contains("content-digest: sha-256=:"),
        "captured request missing Content-Digest (RFC 9530) header; got: {}",
        captured.captured
    );
    assert!(
        lower.contains(&format!(
            "source-service-id: {}",
            captured.state.service_id().to_ascii_lowercase()
        )),
        "captured request missing Source-Service-ID binding; got: {}",
        captured.captured
    );
    assert!(
        lower.contains("destination-service-id: ak:did_core:web:peer.example"),
        "captured request missing Destination-Service-ID binding; got: {}",
        captured.captured
    );
    assert!(
        lower.contains("source-trust-domain: ak:trust_domain:coland-outbox.local"),
        "captured request missing Source-Trust-Domain binding; got: {}",
        captured.captured
    );
    assert!(
        lower.contains("destination-trust-domain: ak:trust_domain:peer.outbox.internal"),
        "captured request missing Destination-Trust-Domain binding; got: {}",
        captured.captured
    );
    assert!(
        !lower.contains("request-canonical-digest:"),
        "captured request must not carry retired Request-Canonical-Digest; got: {}",
        captured.captured
    );
    assert!(
        lower.contains("signature-input: sig1=")
            && lower.contains("\"@authority\"")
            && lower.contains(&format!(
                "keyid=\"{}#federation-fanout-key\"",
                captured
                    .state
                    .service_did()
                    .to_string()
                    .to_ascii_lowercase()
            )),
        "captured request missing RFC 9421 Signature-Input; got: {}",
        captured.captured
    );
    assert!(
        lower.contains("signature: sig1=:"),
        "captured request missing RFC 9421 Signature; got: {}",
        captured.captured
    );
    assert!(
        captured.captured.starts_with("POST /_arkret/peer/events"),
        "request line should target the configured endpoint; got: {}",
        captured.captured
    );
    assert!(
        captured.captured.contains(PAYLOAD_JSON.as_str()),
        "captured request body should match enqueued payload; got: {}",
        captured.captured
    );
    assert_http_signature_verifies(&captured.captured, &captured.target_uri, &captured.state);

    // Outbox row must be marked delivered with the mock's 2xx status.
    let updated = captured
        .state
        .test_persistence()
        .federation_outbox()
        .get(&captured.row_id)
        .await
        .expect("outbox lookup")
        .expect("row still present");
    assert_eq!(
        updated.state,
        FederationOutboxState::Delivered,
        "row should reach the delivered terminal state after a 2xx, got: {updated:?}"
    );
    assert!(updated.completed_at.is_some());
    assert_eq!(
        updated.last_http_status,
        Some(200),
        "last_http_status should record the 2xx the mock peer returned"
    );
    assert!(
        updated.lease_token.is_none(),
        "a completed row releases its lease"
    );
    assert_eq!(
        updated.attempts, 1,
        "exactly one delivery attempt should be recorded for a first-pass 2xx",
    );
}

#[tokio::test]
async fn outbound_signature_rejects_body_digest_tamper() {
    let captured = capture_signed_request().await;
    let mut headers = parse_headers(&captured.captured);
    let original_digest = headers
        .get("content-digest")
        .expect("content-digest header")
        .to_owned();
    let tampered_digest = test_content_digest_header_value(br#"{"resource":"sha256:tampered"}"#);
    assert_ne!(
        original_digest, tampered_digest,
        "body tamper must produce a distinct Content-Digest binding"
    );
    headers.insert("content-digest".to_owned(), tampered_digest);

    let verifying_key = captured.state.notary_signing_key().verifying_key();
    assert!(
        !http_signature_verifies_with_headers(&headers, &captured.target_uri, &verifying_key),
        "changing the body digest after signing must invalidate the RFC 9421 transcript"
    );
}

#[tokio::test]
async fn permanent_4xx_routes_to_dead_letter() {
    let (peer_url, request_rx) =
        spawn_mock_peer_with_status("404 Not Found", br#"{"error":"unknown_peer"}"#);
    let state = coland_test_support::app_state(outbox_test_config());
    install_verified_routes(&state, &[standard_peer_route(&peer_url)]);
    let row = enqueue_outbound(
        &state,
        &peer_url,
        PEER_SERVICE_ID,
        FEDERATION_ENDPOINT,
        IDEMPOTENCY_KEY,
        &PAYLOAD_JSON,
    )
    .await
    .expect("enqueue must succeed");

    FederationDispatcher::new(state.clone())
        .run_one_pass()
        .await
        .expect("dispatch pass must succeed");
    let _ = request_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("mock peer should have received request");

    let updated = state
        .test_persistence()
        .federation_outbox()
        .get(&row.id)
        .await
        .expect("outbox lookup")
        .expect("row still present");
    assert_eq!(updated.state, FederationOutboxState::DeadLettered);
    assert_eq!(updated.last_http_status, Some(404));
    assert_eq!(updated.attempts, 1);
    assert!(updated.completed_at.is_some());

    let dead_letters = state
        .test_persistence()
        .federation_outbox()
        .dead_letters_snapshot()
        .await
        .expect("dead-letter snapshot");
    assert_eq!(
        dead_letters.len(),
        1,
        "the terminal transition and its failure ledger commit together"
    );
    let dead = &dead_letters[0];
    assert_eq!(dead.outbox_id, row.id);
    assert_eq!(dead.peer_id.as_str(), PEER_SERVICE_ID);
    assert_eq!(dead.last_http_status, Some(404));
    assert_eq!(dead.reason, "terminal_http_status");
    assert!(
        dead.response_excerpt
            .as_deref()
            .is_some_and(|body| body.contains("unknown_peer"))
    );

    // A dead letter is not redelivered by another pass, and a restart cannot
    // resurrect it either — only an explicit operator requeue can.
    FederationDispatcher::new(state.clone())
        .run_one_pass()
        .await
        .expect("second dispatch pass");
    let unchanged = state
        .test_persistence()
        .federation_outbox()
        .get(&row.id)
        .await
        .expect("outbox lookup")
        .expect("row still present");
    assert_eq!(unchanged.attempts, 1);
    assert_eq!(unchanged.state, FederationOutboxState::DeadLettered);
}

#[tokio::test]
async fn retryable_5xx_keeps_the_same_transport_identity_and_backs_off() {
    let (peer_url, request_rx) =
        spawn_mock_peer_with_status("503 Service Unavailable", br#"{"error":"unavailable"}"#);
    let state = coland_test_support::app_state(outbox_test_config());
    install_verified_routes(&state, &[standard_peer_route(&peer_url)]);
    let row = enqueue_outbound(
        &state,
        &peer_url,
        PEER_SERVICE_ID,
        FEDERATION_ENDPOINT,
        IDEMPOTENCY_KEY,
        &PAYLOAD_JSON,
    )
    .await
    .expect("enqueue");

    let before = chrono::Utc::now().timestamp();
    FederationDispatcher::new(state.clone())
        .run_one_pass()
        .await
        .expect("dispatch pass");
    let _ = request_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("mock peer received the request");

    let updated = outbox_row(&state, &row.id).await;
    // No response body was accepted, so this is a *transport* retry: same
    // canonical body, same key, only the schedule moves.
    assert_eq!(updated.state, FederationOutboxState::Pending);
    assert_eq!(updated.attempts, 1);
    assert_eq!(updated.semantic_attempts, 0);
    assert_eq!(updated.idempotency_key, IDEMPOTENCY_KEY);
    assert_eq!(updated.payload_json, *PAYLOAD_JSON);
    assert_eq!(updated.last_http_status, Some(503));
    assert_eq!(
        updated.last_error_code.as_deref(),
        Some("retryable_http_status")
    );
    assert!(
        updated.next_attempt_at > before,
        "a retryable failure must be scheduled into the future, got {}",
        updated.next_attempt_at
    );
    assert!(updated.completed_at.is_none());
    assert!(updated.lease_token.is_none());
}

#[tokio::test]
async fn peer_retry_after_is_a_floor_the_dispatcher_never_undercuts() {
    // A 429 with `Retry-After: 900` must push the next attempt at least that
    // far out, well past the ~5s first-attempt exponential backoff.
    let (peer_url, request_rx) = spawn_mock_peer_responses(vec![MockResponse::with_headers(
        "429 Too Many Requests",
        "retry-after: 900\r\n",
        br#"{"error":{"code":"rate_limited"}}"#,
    )]);
    let state = coland_test_support::app_state(outbox_test_config());
    install_verified_routes(&state, &[standard_peer_route(&peer_url)]);
    let row = enqueue_outbound(
        &state,
        &peer_url,
        PEER_SERVICE_ID,
        FEDERATION_ENDPOINT,
        IDEMPOTENCY_KEY,
        &PAYLOAD_JSON,
    )
    .await
    .expect("enqueue");

    let before = chrono::Utc::now().timestamp();
    FederationDispatcher::new(state.clone())
        .run_one_pass()
        .await
        .expect("dispatch pass");
    let _ = request_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("mock peer received the request");

    let updated = outbox_row(&state, &row.id).await;
    assert_eq!(updated.state, FederationOutboxState::Pending);
    assert!(
        updated.next_attempt_at >= before + 900,
        "Retry-After must not be undercut; scheduled {} vs floor {}",
        updated.next_attempt_at,
        before + 900
    );
}

#[tokio::test]
async fn dependency_missing_supersedes_the_attempt_with_a_fresh_key() {
    static PROBLEM: LazyLock<Vec<u8>> = LazyLock::new(|| {
        serde_json::to_vec(&arkret_wire::problem_details::Problem::new(
            "dependency_missing",
            409,
            "The prior committed dependency is unavailable.",
        ))
        .unwrap()
    });
    let (peer_url, request_rx) = spawn_mock_peer_with_status("409 Conflict", &PROBLEM);
    let state = coland_test_support::app_state(outbox_test_config());
    install_verified_routes(&state, &[standard_peer_route(&peer_url)]);
    let row = enqueue_outbound(
        &state,
        &peer_url,
        PEER_SERVICE_ID,
        FEDERATION_ENDPOINT,
        IDEMPOTENCY_KEY,
        &PAYLOAD_JSON,
    )
    .await
    .expect("enqueue");

    FederationDispatcher::new(state.clone())
        .run_one_pass()
        .await
        .expect("dispatch pass");
    let _ = request_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("mock peer received the request");

    // `federation.md` §8.5: a response was received, so the old transport
    // identity is finished. The old row MUST NOT be rescheduled under its key.
    let original = outbox_row(&state, &row.id).await;
    assert_eq!(original.state, FederationOutboxState::Superseded);
    assert_eq!(original.idempotency_key, IDEMPOTENCY_KEY);
    assert_eq!(
        original.last_error_code.as_deref(),
        Some("dependency_missing")
    );
    assert!(original.completed_at.is_some());

    let rows = state
        .test_persistence()
        .federation_outbox()
        .snapshot_all()
        .await
        .expect("outbox snapshot");
    let successor = rows
        .iter()
        .find(|candidate| candidate.id != row.id)
        .expect("a replacement intent was created");
    assert_eq!(successor.state, FederationOutboxState::Pending);
    assert_eq!(
        successor.supersedes_outbox_id.as_deref(),
        Some(row.id.as_str()),
        "the replacement keeps a diagnostic link to the attempt it replaced"
    );
    assert_ne!(
        successor.idempotency_key, IDEMPOTENCY_KEY,
        "re-evaluation after a response MUST use a new Idempotency-Key"
    );
    assert!(successor.idempotency_key.starts_with("ak:outbox:resubmit:"));
    assert_eq!(
        successor.payload_json, *PAYLOAD_JSON,
        "a whole-batch rejection resubmits the same events, only under a new key"
    );
    assert_eq!(successor.semantic_attempts, 1);
}

#[tokio::test]
async fn egress_policy_denial_is_policy_suppressed_rather_than_delivered() {
    let state = coland_test_support::app_state(outbox_test_config());
    install_verified_routes(&state, &[denied_peer_route()]);
    // The cloud metadata endpoint is hard-blocked regardless of posture, so
    // this exercises a denial without depending on env-var configuration.
    let row = enqueue_outbound(
        &state,
        "https://169.254.169.254",
        DENIED_PEER_SERVICE_ID,
        FEDERATION_ENDPOINT,
        IDEMPOTENCY_KEY,
        &PAYLOAD_JSON,
    )
    .await
    .expect("enqueue");

    FederationDispatcher::new(state.clone())
        .run_one_pass()
        .await
        .expect("dispatch pass");

    let updated = outbox_row(&state, &row.id).await;
    assert_eq!(
        updated.state,
        FederationOutboxState::PolicySuppressed,
        "a local policy denial is neither a delivery nor a network failure"
    );
    assert_eq!(
        updated.attempts, 0,
        "no socket was opened, so the transport retry budget is untouched"
    );
    assert!(
        updated.policy_version.is_some(),
        "the suppressing policy version is recorded so revalidation is possible"
    );
    assert_eq!(
        updated.last_error_code.as_deref(),
        Some("egress_policy_denied")
    );
    assert!(
        state
            .test_persistence()
            .federation_outbox()
            .dead_letters_snapshot()
            .await
            .expect("dead-letter snapshot")
            .is_empty(),
        "policy suppression is recoverable and is not a dead letter"
    );

    // Restarting the dispatcher must not bypass a policy that still denies.
    FederationDispatcher::new(state.clone())
        .run_one_pass()
        .await
        .expect("second dispatch pass");
    assert_eq!(
        outbox_row(&state, &row.id).await.state,
        FederationOutboxState::PolicySuppressed
    );
}

#[tokio::test]
async fn persisted_peer_url_is_not_service_resolution_evidence() {
    let state = coland_test_support::app_state(outbox_test_config());
    let row = enqueue_outbound(
        &state,
        "https://127.0.0.1:9",
        PEER_SERVICE_ID,
        FEDERATION_ENDPOINT,
        IDEMPOTENCY_KEY,
        &PAYLOAD_JSON,
    )
    .await
    .expect("enqueue");

    FederationDispatcher::new(state.clone())
        .run_one_pass()
        .await
        .expect("dispatch pass");

    let updated = outbox_row(&state, &row.id).await;
    assert_eq!(updated.state, FederationOutboxState::Pending);
    assert_eq!(updated.attempts, 1);
    assert!(
        updated
            .last_response_excerpt
            .as_deref()
            .is_some_and(|excerpt| excerpt.contains("service_route_unavailable")),
        "the diagnostic peer_url must not become a raw delivery fallback: {updated:?}"
    );
}

#[tokio::test]
async fn a_stale_lease_holder_cannot_overwrite_the_new_holders_state() {
    use coland_storage::{
        FederationOutboxClaim, FederationOutboxOutcome, FederationOutboxTransition,
    };

    let state = coland_test_support::app_state(outbox_test_config());
    let outbox = state.test_persistence();
    let outbox = outbox.federation_outbox();
    let row = enqueue_outbound(
        &state,
        "https://127.0.0.1:9",
        PEER_SERVICE_ID,
        FEDERATION_ENDPOINT,
        IDEMPOTENCY_KEY,
        &PAYLOAD_JSON,
    )
    .await
    .expect("enqueue");
    let now = row.created_at;

    let claim = |token: &str, owner: &str, at: i64, lease: i64| FederationOutboxClaim {
        now_unix_secs: at,
        limit: 8,
        lease_owner: owner.to_owned(),
        lease_token: token.to_owned(),
        lease_duration_secs: lease,
    };
    let transition = |token: &str, at: i64| FederationOutboxTransition {
        id: row.id.clone(),
        lease_token: token.to_owned(),
        attempts: 1,
        semantic_attempts: 0,
        last_http_status: Some(200),
        last_error_code: None,
        last_response_excerpt: None,
        observed_at: at,
        outcome: FederationOutboxOutcome::Delivered,
    };

    // Worker A claims with a short lease and then stalls.
    let claimed = outbox
        .claim_due(&claim("token-a", "worker-a", now, 10))
        .await
        .expect("worker A claim");
    assert_eq!(claimed.len(), 1);

    // Worker B takes over once the lease expires.
    let taken_over = outbox
        .claim_due(&claim("token-b", "worker-b", now + 60, 120))
        .await
        .expect("worker B claim");
    assert_eq!(taken_over.len(), 1, "an expired lease is reclaimable");

    // Worker A's late response must be discarded, not written.
    assert!(
        !outbox
            .complete(&transition("token-a", now + 61))
            .await
            .expect("stale write"),
        "a stale holder's result MUST be dropped"
    );
    assert_eq!(
        outbox_row(&state, &row.id).await.state,
        FederationOutboxState::Leased,
        "the row stays owned by the current holder"
    );

    // The current holder's write lands.
    assert!(
        outbox
            .complete(&transition("token-b", now + 62))
            .await
            .expect("current holder write")
    );
    assert_eq!(
        outbox_row(&state, &row.id).await.state,
        FederationOutboxState::Delivered
    );
}

#[tokio::test]
async fn operator_requeue_mints_a_new_intent_and_records_the_audit() {
    let (peer_url, request_rx) =
        spawn_mock_peer_with_status("404 Not Found", br#"{"error":"unknown_peer"}"#);
    let state = coland_test_support::app_state(outbox_test_config());
    install_verified_routes(&state, &[standard_peer_route(&peer_url)]);
    // The private operations rail carries its own envelope, so requeue
    // revalidation only requires the stored body to still be parseable JSON.
    // The peer-Event rail additionally re-runs `validate_federation_transport`,
    // which a synthetic fixture body cannot satisfy — and must not, since
    // replaying a body the wire contract rejects would only fail again.
    let row = enqueue_outbound(
        &state,
        &peer_url,
        PEER_SERVICE_ID,
        "/_coland/peer/federation/operations",
        IDEMPOTENCY_KEY,
        &PAYLOAD_JSON,
    )
    .await
    .expect("enqueue");
    FederationDispatcher::new(state.clone())
        .run_one_pass()
        .await
        .expect("dispatch pass");
    let _ = request_rx.recv_timeout(Duration::from_secs(5));

    let dead_letters = state
        .test_persistence()
        .federation_outbox()
        .dead_letters_snapshot()
        .await
        .expect("dead-letter snapshot");
    let dead_letter_id = dead_letters[0].id.clone();

    let outcome = outbox_operator::requeue_dead_letter(
        &state,
        &dead_letter_id,
        "did:web:operator.example",
        "peer endpoint restored",
    )
    .await
    .expect("requeue");
    assert_eq!(outcome.original_outbox_id, row.id);
    assert_ne!(outcome.requeued_outbox_id, row.id);
    assert_ne!(
        outcome.idempotency_key, IDEMPOTENCY_KEY,
        "a replay is a new request and MUST carry a new key"
    );

    // The terminal row is untouched — a requeue never resurrects it.
    let original = outbox_row(&state, &row.id).await;
    assert_eq!(original.state, FederationOutboxState::DeadLettered);
    assert!(original.completed_at.is_some());

    let replay = outbox_row(&state, &outcome.requeued_outbox_id).await;
    assert_eq!(replay.state, FederationOutboxState::Pending);
    assert_eq!(replay.attempts, 0);
    assert_eq!(replay.payload_json, *PAYLOAD_JSON);
    assert_eq!(
        replay.supersedes_outbox_id.as_deref(),
        Some(row.id.as_str())
    );

    let stamped = state
        .test_persistence()
        .federation_outbox()
        .dead_letter(&dead_letter_id)
        .await
        .expect("dead-letter lookup")
        .expect("dead letter present");
    assert_eq!(
        stamped.requeued_outbox_id.as_deref(),
        Some(outcome.requeued_outbox_id.as_str())
    );
    assert_eq!(
        stamped.requeued_by.as_deref(),
        Some("did:web:operator.example")
    );
    assert_eq!(
        stamped.requeue_reason.as_deref(),
        Some("peer endpoint restored")
    );
    assert!(stamped.requeue_request_digest.is_some());
    assert!(stamped.requeued_at.is_some());

    // Replay is single-shot: a second operator click is refused.
    assert!(
        outbox_operator::requeue_dead_letter(
            &state,
            &dead_letter_id,
            "did:web:operator.example",
            "double click",
        )
        .await
        .is_err()
    );
}

async fn outbox_row(state: &AppState, id: &str) -> coland_storage::FederationOutboxRecord {
    state
        .test_persistence()
        .federation_outbox()
        .get(id)
        .await
        .expect("outbox lookup")
        .expect("row still present")
}

// ── PostgreSQL restart behaviour ────────────────────────────────────────────
//
// These are the tests that actually prove durability, so they must not reuse
// the previous process's in-memory objects: each "restart" builds a brand-new
// `AppState` and dispatcher over the same pool, exactly as a real restart does.
// Each case leases its own database, so they no longer contend for one
// `federation_outbox` table and no longer skip when no database is configured:
// the lease fails instead.

/// A fresh `AppState` over the same PostgreSQL pool — the test's "restart".
async fn pg_restart(
    database: &coland_storage_postgres::TestDatabase,
    routes: &[VerifiedPeerRoute],
) -> AppState {
    let db = database.db();
    let pool = db.pool.clone().expect("a leased test database has a pool");
    let config = outbox_test_config();
    let persistence_store: std::sync::Arc<dyn coland_storage::PersistenceStore> =
        std::sync::Arc::new(coland_storage_postgres::PgPersistenceStore::new(pool));
    let persistence =
        coland_services::persistence::PersistenceHandle::from_shared(persistence_store.clone());
    let identity = coland_test_support::fixture_service_identity(&config);
    let signing_seed = coland_test_support::fixture_signing_seed(&config, &identity);
    let fixture_identity = identity.identity().expect("fixture serving identity");
    let resolution_commitment = arkret_models_identity::ResolutionCommitment {
        did: fixture_identity.did.clone(),
        method_history_head: format!("sha256:{}", "0".repeat(64)),
        version_id: "fixture-v1".to_owned(),
    };
    let state = coland::runtime::build_app_state(
        config,
        db,
        persistence,
        identity,
        resolution_commitment,
        signing_seed,
    )
    .expect("postgres AppState");
    coland_test_support::register_persistence(&state, &persistence_store);
    if !routes.is_empty() {
        install_verified_routes(&state, routes);
    }
    state
}

/// A `(peer, idempotency_key)` pair unique to one test run, so concurrent runs
/// against a shared database never collide on the unique index.
fn unique_key(prefix: &str) -> String {
    format!("ak:outbox:{prefix}:{}", uuid::Uuid::now_v7())
}

#[tokio::test]
async fn postgres_pending_row_is_delivered_by_a_restarted_dispatcher() {
    let database = coland_storage_postgres::TestDatabase::lease().await;
    let state = pg_restart(&database, &[]).await;
    let (peer_url, request_rx) = spawn_mock_peer();
    let route = unique_peer_route("restart-pending", &peer_url);
    let key = unique_key("restart-pending");
    let row = enqueue_outbound(
        &state,
        &peer_url,
        route.service_id.as_str(),
        FEDERATION_ENDPOINT,
        &key,
        &PAYLOAD_JSON,
    )
    .await
    .expect("enqueue");
    // Drop every in-process object and rebuild from the database alone.
    drop(state);

    let restarted = pg_restart(&database, std::slice::from_ref(&route)).await;
    FederationDispatcher::new(restarted.clone())
        .run_one_pass()
        .await
        .expect("dispatch pass after restart");
    let _ = request_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("the restarted dispatcher delivers the pending row");
    let delivered = outbox_row(&restarted, &row.id).await;
    assert_eq!(delivered.state, FederationOutboxState::Delivered);
}

#[tokio::test]
async fn postgres_future_next_attempt_is_not_sent_early_after_restart() {
    let database = coland_storage_postgres::TestDatabase::lease().await;
    let state = pg_restart(&database, &[]).await;
    let (peer_url, request_rx) =
        spawn_mock_peer_with_status("503 Service Unavailable", br#"{"error":"unavailable"}"#);
    let route = unique_peer_route("restart-backoff", &peer_url);
    install_verified_routes(&state, std::slice::from_ref(&route));
    let key = unique_key("restart-backoff");
    let row = enqueue_outbound(
        &state,
        &peer_url,
        route.service_id.as_str(),
        FEDERATION_ENDPOINT,
        &key,
        &PAYLOAD_JSON,
    )
    .await
    .expect("enqueue");
    FederationDispatcher::new(state.clone())
        .run_one_pass()
        .await
        .expect("first dispatch pass");
    let _ = request_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("first attempt reaches the peer");
    let scheduled = outbox_row(&state, &row.id).await;
    assert_eq!(scheduled.state, FederationOutboxState::Pending);
    assert_eq!(scheduled.attempts, 1);
    drop(state);

    // The mock peer has no second response queued: if the restarted dispatcher
    // sent early, the delivery would fail and `attempts` would advance.
    let restarted = pg_restart(&database, std::slice::from_ref(&route)).await;
    FederationDispatcher::new(restarted.clone())
        .run_one_pass()
        .await
        .expect("dispatch pass after restart");
    let after = outbox_row(&restarted, &row.id).await;
    assert_eq!(
        after.attempts, 1,
        "a restart must not pull a scheduled retry forward"
    );
    assert_eq!(after.next_attempt_at, scheduled.next_attempt_at);
    assert_eq!(after.state, FederationOutboxState::Pending);
}

#[tokio::test]
async fn postgres_crash_before_recording_resends_the_same_transport_identity() {
    let database = coland_storage_postgres::TestDatabase::lease().await;
    let state = pg_restart(&database, &[]).await;
    // Model a peer that accepted the abandoned first transport: the restarted
    // sender receives the formal duplicate outcome for the unchanged
    // Idempotency-Key (`federation.md` §8.5).
    let (peer_url, request_rx) =
        spawn_mock_peer_with_status("200 OK", DUPLICATE_OUTCOME.as_bytes());
    let route = unique_peer_route("restart-inflight", &peer_url);
    let key = unique_key("restart-inflight");
    let row = enqueue_outbound(
        &state,
        &peer_url,
        route.service_id.as_str(),
        FEDERATION_ENDPOINT,
        &key,
        &PAYLOAD_JSON,
    )
    .await
    .expect("enqueue");

    // Simulate "sent, peer accepted, we never wrote the result": claim the row
    // under a lease and then abandon it without completing.
    let claimed = state
        .test_persistence()
        .federation_outbox()
        .claim_due(&coland_storage::FederationOutboxClaim {
            now_unix_secs: chrono::Utc::now().timestamp(),
            limit: 8,
            lease_owner: "crashed-worker".to_owned(),
            lease_token: "crashed-token".to_owned(),
            lease_duration_secs: -1,
        })
        .await
        .expect("claim");
    assert!(claimed.iter().any(|claimed| claimed.id == row.id));
    drop(state);

    let restarted = pg_restart(&database, std::slice::from_ref(&route)).await;
    FederationDispatcher::new(restarted.clone())
        .run_one_pass()
        .await
        .expect("dispatch pass after restart");
    let resent = request_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("the restarted dispatcher re-sends the abandoned row");
    assert!(
        resent
            .to_ascii_lowercase()
            .contains(&format!("idempotency-key: {}", key.to_ascii_lowercase())),
        "a transport retry MUST reuse the original key so the peer can dedupe; got: {resent}"
    );
    assert_eq!(
        outbox_row(&restarted, &row.id).await.state,
        FederationOutboxState::Delivered
    );
}

#[tokio::test]
async fn postgres_terminal_rows_are_not_resent_after_restart() {
    let database = coland_storage_postgres::TestDatabase::lease().await;
    let state = pg_restart(&database, &[]).await;
    let (peer_url, request_rx) =
        spawn_mock_peer_with_status("404 Not Found", br#"{"error":"unknown_peer"}"#);
    let peer_route = unique_peer_route("restart-dead", &peer_url);
    let denied_route = unique_peer_route("restart-denied", "https://169.254.169.254");
    install_verified_routes(&state, &[peer_route.clone(), denied_route.clone()]);
    let dead_key = unique_key("restart-dead");
    let dead = enqueue_outbound(
        &state,
        &peer_url,
        peer_route.service_id.as_str(),
        FEDERATION_ENDPOINT,
        &dead_key,
        &PAYLOAD_JSON,
    )
    .await
    .expect("enqueue dead-letter candidate");
    // A policy-suppressed row alongside it: neither may move on restart.
    let suppressed_key = unique_key("restart-suppressed");
    let suppressed = enqueue_outbound(
        &state,
        "https://169.254.169.254",
        denied_route.service_id.as_str(),
        FEDERATION_ENDPOINT,
        &suppressed_key,
        &PAYLOAD_JSON,
    )
    .await
    .expect("enqueue policy-suppression candidate");
    FederationDispatcher::new(state.clone())
        .run_one_pass()
        .await
        .expect("first dispatch pass");
    let _ = request_rx.recv_timeout(Duration::from_secs(5));
    assert_eq!(
        outbox_row(&state, &dead.id).await.state,
        FederationOutboxState::DeadLettered
    );
    assert_eq!(
        outbox_row(&state, &suppressed.id).await.state,
        FederationOutboxState::PolicySuppressed
    );
    drop(state);

    let restarted = pg_restart(&database, &[peer_route, denied_route]).await;
    FederationDispatcher::new(restarted.clone())
        .run_one_pass()
        .await
        .expect("dispatch pass after restart");
    let dead_after = outbox_row(&restarted, &dead.id).await;
    assert_eq!(dead_after.state, FederationOutboxState::DeadLettered);
    assert_eq!(
        dead_after.attempts, 1,
        "a restart is not a replay: only an operator requeue re-sends a dead letter"
    );
    let suppressed_after = outbox_row(&restarted, &suppressed.id).await;
    assert_eq!(
        suppressed_after.state,
        FederationOutboxState::PolicySuppressed,
        "a restart must not bypass a policy that still denies the target"
    );
    assert_eq!(suppressed_after.attempts, 0);
}

#[tokio::test]
async fn outbound_signature_rejects_missing_trust_domain_component() {
    let captured = capture_signed_request().await;
    let mut headers = parse_headers(&captured.captured);
    headers.remove("destination-trust-domain");

    let verifying_key = captured.state.notary_signing_key().verifying_key();
    assert!(
        !http_signature_verifies_with_headers(&headers, &captured.target_uri, &verifying_key),
        "missing destination trust-domain must fail verification"
    );
}

#[tokio::test]
async fn outbound_signature_rejects_trust_domain_mismatch() {
    let captured = capture_signed_request().await;
    let mut headers = parse_headers(&captured.captured);
    headers.insert(
        "destination-trust-domain".to_owned(),
        "ak:trust_domain:evil.example".to_owned(),
    );

    let verifying_key = captured.state.notary_signing_key().verifying_key();
    assert!(
        !http_signature_verifies_with_headers(&headers, &captured.target_uri, &verifying_key),
        "trust-domain mismatch must fail verification"
    );
}

#[tokio::test]
async fn outbound_enqueue_is_idempotent_for_same_peer_and_key() {
    let state = coland_test_support::app_state(outbox_test_config());

    let first = enqueue_outbound(
        &state,
        "https://127.0.0.1:9",
        PEER_SERVICE_ID,
        FEDERATION_ENDPOINT,
        IDEMPOTENCY_KEY,
        &PAYLOAD_JSON,
    )
    .await
    .expect("first enqueue");
    let second = enqueue_outbound(
        &state,
        "https://127.0.0.1:9",
        PEER_SERVICE_ID,
        FEDERATION_ENDPOINT,
        IDEMPOTENCY_KEY,
        &PAYLOAD_JSON,
    )
    .await
    .expect("second enqueue with same peer/key");

    assert_eq!(
        first.id, second.id,
        "same peer + idempotency key must return the original outbox row"
    );
    let snapshot = state
        .test_persistence()
        .federation_outbox()
        .snapshot_all()
        .await
        .expect("outbox snapshot");
    assert_eq!(
        snapshot.len(),
        1,
        "idempotent replay must not create a duplicate outbox row"
    );
}

#[tokio::test]
async fn outbound_signature_fails_after_service_key_rotation() {
    let captured = capture_signed_request().await;
    let headers = parse_headers(&captured.captured);
    let original_key = captured.state.notary_signing_key().verifying_key();
    assert!(
        http_signature_verifies_with_headers(&headers, &captured.target_uri, &original_key),
        "sanity: original service key should verify the signed request"
    );

    let rotated_key = SigningKey::from_bytes(&[7_u8; 32]).verifying_key();
    assert!(
        !http_signature_verifies_with_headers(&headers, &captured.target_uri, &rotated_key),
        "service-key rotation/revoke must invalidate replay of the old signed request"
    );
}

async fn capture_signed_request() -> CapturedSignedRequestBody {
    let (peer_url, request_rx) = spawn_mock_peer();
    let state = coland_test_support::app_state(outbox_test_config());
    install_verified_routes(&state, &[standard_peer_route(&peer_url)]);

    // Enqueue one outbound row through the standard peer-event delivery path.
    // funnels through after computing the deterministic idempotency
    // key.
    let row = enqueue_outbound(
        &state,
        &peer_url,
        PEER_SERVICE_ID,
        FEDERATION_ENDPOINT,
        IDEMPOTENCY_KEY,
        &PAYLOAD_JSON,
    )
    .await
    .expect("enqueue must succeed");
    let persistence = state.test_persistence();
    let pending = persistence
        .federation_outbox()
        .get(&row.id)
        .await
        .expect("outbox query")
        .expect("freshly enqueued row remains pending");
    assert_eq!(pending.state, FederationOutboxState::Pending);

    // Drive one dispatch pass synchronously.
    let dispatcher = FederationDispatcher::new(state.clone());
    dispatcher
        .run_one_pass()
        .await
        .expect("dispatch pass must succeed");

    // Wait briefly for the mock peer thread to publish the captured
    // request; the dispatcher's send-and-read-response is already
    // complete by this point so this is just the thread-handoff wait.
    let captured = request_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("mock peer should have received exactly one request");

    CapturedSignedRequestBody {
        captured,
        target_uri: format!("{peer_url}{FEDERATION_ENDPOINT}"),
        state,
        row_id: row.id,
    }
}

fn assert_http_signature_verifies(captured: &str, target_uri: &str, state: &AppState) {
    let headers = parse_headers(captured);
    let verifying_key = state.notary_signing_key().verifying_key();
    assert!(
        http_signature_verifies_with_headers(&headers, target_uri, &verifying_key),
        "RFC 9421 signature should verify against service key"
    );
}

fn http_signature_verifies_with_headers(
    headers: &BTreeMap<String, String>,
    target_uri: &str,
    verifying_key: &VerifyingKey,
) -> bool {
    let signature_input = headers
        .get("signature-input")
        .and_then(|value| value.strip_prefix("sig1="));
    let Some(signature_params) = signature_input else {
        return false;
    };
    let signature_b64 = headers
        .get("signature")
        .and_then(|value| value.strip_prefix("sig1=:"))
        .and_then(|value| value.strip_suffix(':'));
    let Some(signature_b64) = signature_b64 else {
        return false;
    };
    let Ok(signature_bytes) = STANDARD.decode(signature_b64) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(&signature_bytes) else {
        return false;
    };

    let (
        Some(content_digest),
        Some(source_id),
        Some(destination_id),
        Some(source_trust_domain),
        Some(destination_trust_domain),
    ) = (
        headers.get("content-digest"),
        headers.get("source-service-id"),
        headers.get("destination-service-id"),
        headers.get("source-trust-domain"),
        headers.get("destination-trust-domain"),
    )
    else {
        return false;
    };
    let authority = authority_from_target_uri(target_uri);

    let mut signature_base = format!(
        "\"@method\": POST\n\
         \"@target-uri\": {target_uri}\n\
         \"@authority\": {authority}\n\
         \"content-digest\": {content_digest}\n\
         \"source-service-id\": {source_id}\n\
         \"destination-service-id\": {destination_id}\n\
         \"source-trust-domain\": {source_trust_domain}\n\
         \"destination-trust-domain\": {destination_trust_domain}",
    );
    if let Some(operation) = headers.get("arkret-operation") {
        signature_base.push_str(&format!("\n\"arkret-operation\": {operation}"));
    }
    if let Some(idempotency_key) = headers.get("idempotency-key") {
        signature_base.push_str(&format!("\n\"idempotency-key\": {idempotency_key}"));
    }
    signature_base.push_str(&format!("\n\"@signature-params\": {signature_params}"));

    verifying_key
        .verify(signature_base.as_bytes(), &signature)
        .is_ok()
}

fn authority_from_target_uri(target_uri: &str) -> String {
    let Ok(url) = reqwest::Url::parse(target_uri) else {
        return String::new();
    };
    let Some(host) = url.host_str() else {
        return String::new();
    };
    url.port()
        .map(|port| format!("{host}:{port}"))
        .unwrap_or_else(|| host.to_owned())
}

fn test_content_digest_header_value(body: &[u8]) -> String {
    let digest = Sha256::digest(body);
    format!("sha-256=:{}:", STANDARD.encode(digest))
}

fn parse_headers(captured: &str) -> BTreeMap<String, String> {
    let mut headers = BTreeMap::new();
    for line in captured.lines().skip(1) {
        if line.trim().is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
        }
    }
    headers
}

fn fixture_route_evidence(
    did: &arkret_wire::Did,
    service_id: &DidCoreId,
    base_url: &str,
) -> arkret_models_identity::AuthenticatedServiceResolution {
    use arkret_models_identity::*;
    let document:DidDocument=serde_json::from_value(serde_json::json!({"id":did,"service":[{"id":format!("{did}#station"),"type":"ArkretService","serviceKind":"station","serviceEndpoint":base_url}]})).unwrap();
    let digest = arkret_identity::document_canonical_digest(&document).unwrap();
    let head = digest.to_string();
    let version = format!(
        "synthetic-jcs-sha256:{}",
        head.trim_start_matches("sha256:")
    );
    AuthenticatedServiceResolution {
        service_id: service_id.clone(),
        service_kind: "station".into(),
        normalized_did_document: document,
        method_history_evidence: ResolutionMethodHistoryEvidence::DidWebDocument {
            boundary: ResolutionMethodEvidenceBoundary {
                from_method_history_head: head.clone(),
                to_method_history_head: head,
                from_version_id: version.clone(),
                to_version_id: version,
            },
            evidence: ResolutionDidBindingEvidenceReceipt {
                kind: ResolutionDidBindingEvidenceKind::AkDidBindingEvidenceV1,
                method: "web".into(),
                document_digest: digest,
                method_proofs: vec![],
            },
        },
    }
}
