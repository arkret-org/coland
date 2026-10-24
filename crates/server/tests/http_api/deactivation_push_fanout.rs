//! Account deactivation must never invoke the retired identity-bearing Gateway API.
use coland_http::deactivation_push_fanout::Worker;

use super::common::*;

async fn admin_deactivate(state: AppState, admin: &str, did: &str) -> Value {
    let mut response =
        TestClient::post(format!("http://server/_coland/admin/accounts/{did}/status"))
            .add_header("authorization", format!("Bearer {admin}"), true)
            .json(&serde_json::json!({"status": "deactivated"}))
            .send(&app_from_state(state))
            .await;
    assert_eq!(
        response.status_code.unwrap().as_u16(),
        200,
        "deactivation must not fail on gateway trouble"
    );
    response.take_json().await.unwrap()
}

async fn admin_actor_row(state: AppState, admin: &str, did: &str) -> Value {
    let actors: Value = TestClient::get(format!(
        "http://server/_coland/admin/actors?filter[search]={}",
        did.trim_start_matches("ak:did_core:")
    ))
    .add_header("authorization", format!("Bearer {admin}"), true)
    .send(&app_from_state(state))
    .await
    .take_json()
    .await
    .unwrap();
    actors["actors"]
        .as_array()
        .and_then(|rows| rows.iter().find(|row| row["id"] == did).cloned())
        .unwrap_or_else(|| panic!("actor {did} missing from admin actors: {actors}"))
}

#[test]
fn deactivation_never_sends_principal_to_legacy_gateway() {
    run_on_test_runtime(
        "deactivation_never_sends_principal_to_legacy_gateway",
        || async {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            // Raw deployment input for the retired URL must not re-enable a
            // transport after its config fields and producer have been removed.
            let fixture = test_config();
            let stable_notary_seed = [86; 32];
            let values = std::collections::BTreeMap::from([
                (
                    "COLAND_TRUST_DOMAIN".to_owned(),
                    fixture.trust_domain.to_string(),
                ),
                (
                    "COLAND_NOTARY_SIGNING_KEY".to_owned(),
                    arkret_canonical::base64url_encode(stable_notary_seed),
                ),
                (
                    "COLAND_DEACTIVATION_PUSH_GATEWAY_URL".to_owned(),
                    format!("http://{}", listener.local_addr().unwrap()),
                ),
                (
                    "COLAND_DEACTIVATION_PUSH_GATEWAY_BEARER".to_owned(),
                    "retired-token".to_owned(),
                ),
            ]);
            let parsed =
                AppConfig::from_values(&values, coland_http::config::StartupOverrides::default())
                    .unwrap();
            assert!(
                !parsed.development_mode,
                "retain the production startup key gate"
            );
            assert_eq!(parsed.notary_signing_key_seed, Some(stable_notary_seed));
            assert_eq!(parsed.trust_domain, fixture.trust_domain);
            let state = coland_test_support::app_state(AppConfig {
                public_base_url: fixture.public_base_url,
                object_storage: fixture.object_storage,
                did_resolver_allow_methods: fixture.did_resolver_allow_methods,
                development_mode: fixture.development_mode,
                embedded_webvh_registration_bearer: fixture.embedded_webvh_registration_bearer,
                seed_demo_data: fixture.seed_demo_data,
                federation_outbound_enabled: false,
                resumable_upload_dir: fixture.resumable_upload_dir,
                ..parsed
            });
            let admin = dev_token(state.clone()).await;
            let _token = register_account(
                state.clone(),
                "did:web:push-private.example",
                "@push-private",
                "ak:device:01904100-0000-7000-8000-de0c70000001",
            )
            .await;
            let did = fixture_actor_core_id("did:web:push-private.example");
            let body = admin_deactivate(state.clone(), &admin, did.as_str()).await;
            assert_eq!(body["state"], "deactivated");
            assert!(!state.deactivation_push_partial(did.as_str()));
            assert_eq!(Worker::new(state.clone()).run_once().await, 0);
            assert!(
                matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
                "legacy configured Gateway must receive no request, including after recovery"
            );
            let row = admin_actor_row(state, &admin, did.as_str()).await;
            assert_eq!(row["deactivation_partial"], false, "{row}");
        },
    );
}

#[test]
fn no_gateway_configured_completes_locally_without_partial() {
    run_on_test_runtime(
        "no_gateway_configured_completes_locally_without_partial",
        || async {
            let state = coland_test_support::app_state(test_config());
            let admin = dev_token(state.clone()).await;
            let _token = register_account(
                state.clone(),
                "did:web:push-local.example",
                "@push-local",
                "ak:device:01904100-0000-7000-8000-de0c70000004",
            )
            .await;
            let did = fixture_actor_core_id("did:web:push-local.example");
            let body = admin_deactivate(state.clone(), &admin, did.as_str()).await;
            assert_eq!(body["state"], "deactivated");
            assert!(!state.deactivation_push_partial(did.as_str()));
            assert_eq!(Worker::new(state).run_once().await, 0);
        },
    );
}

// The network peer below exercises the production Station coordinator. Discovery
// uses the same independently verified-route fixture boundary as federation_outbox;
// TLS, signed requests, Gateway JWS verification and Station PG writes stay real.
struct PushGatewayRoute(coland_services::service_route::VerifiedRouteCandidate);

#[async_trait::async_trait]
impl coland_services::service_route::ServiceRouteFetcher for PushGatewayRoute {
    async fn fetch_current(
        &self,
        id: &DidCoreId,
        kind: &str,
    ) -> coland_services::ServiceResult<
        Option<coland_services::service_route::VerifiedRouteCandidate>,
    > {
        Ok((id == &self.0.evidence.service_id && kind == "push_gateway").then(|| self.0.clone()))
    }
}

fn gateway_route(base: &str, key: &SigningKey) -> PushGatewayRoute {
    use arkret_models_identity::*;
    use coland_services::service_route::{VerifiedRouteCandidate, VerifiedServiceDescribeMetadata};
    let did = Did::new("did:web:push.deactivation.internal").unwrap();
    let id = arkret_wire::project_did_to_core_id(&did).unwrap();
    let method = format!("{did}#receipt");
    let document: DidDocument = serde_json::from_value(serde_json::json!({
        "id": did,
        "verificationMethod": [{"id":method,"controller":did,"type":"Multikey",
            "publicKeyMultibase":arkret_canonical::ed25519_pubkey_to_did_key_multibase(key.verifying_key().as_bytes())}],
        "assertionMethod":[method],
        "service":[{"id":format!("{did}#gateway"),"type":"ArkretService",
            "serviceKind":"push_gateway","serviceEndpoint":base}]
    })).unwrap();
    let digest = arkret_identity::document_canonical_digest(&document).unwrap();
    let head = digest.to_string();
    let version = format!(
        "synthetic-jcs-sha256:{}",
        head.trim_start_matches("sha256:")
    );
    let evidence = AuthenticatedServiceResolution {
        service_id: id.clone(),
        service_kind: "push_gateway".to_owned(),
        normalized_did_document: document,
        method_history_evidence: ResolutionMethodHistoryEvidence::DidWebDocument {
            boundary: ResolutionMethodEvidenceBoundary {
                from_method_history_head: head.clone(),
                to_method_history_head: head.clone(),
                from_version_id: version.clone(),
                to_version_id: version.clone(),
            },
            evidence: ResolutionDidBindingEvidenceReceipt {
                kind: ResolutionDidBindingEvidenceKind::AkDidBindingEvidenceV1,
                method: "web".to_owned(),
                document_digest: digest,
                method_proofs: vec![],
            },
        },
    };
    PushGatewayRoute(VerifiedRouteCandidate {
        evidence,
        description: VerifiedServiceDescribeMetadata {
            service_id: id,
            service_kind: "push_gateway".to_owned(),
            service_resolution: ResolutionCommitment {
                did,
                method_history_head: head,
                version_id: version,
            },
            http_json_base_url: base.to_owned(),
            trust_domain: arkret_wire::TrustDomainId::new(
                "ak:trust_domain:push.deactivation.internal",
            )
            .unwrap(),
            protocol_version: arkret_wire::PROTOCOL_VERSION.to_owned(),
            supported_operation_bundles: vec![
                "ak.operation_bundle.push_gateway.http_notify.v1".to_owned(),
                "ak.operation_bundle.push_gateway.registration_handoff.v1".to_owned(),
            ],
            supported_profiles: Vec::new(),
        },
    })
}

#[derive(Clone)]
struct GatewayExchange {
    request: arkret_models_integration::PushRegistrationHandoffRequestBody,
    response: Option<arkret_models_integration::PushRegistrationHandoffResponseBody>,
}

struct ReceiptGateway {
    base: String,
    // 0 = valid receipt, 1 = HTTP unavailable, 2 = wrong receipt signing key.
    mode: std::sync::Arc<std::sync::atomic::AtomicU8>,
    stopped: std::sync::Arc<std::sync::atomic::AtomicBool>,
    exchanges: std::sync::Arc<std::sync::Mutex<Vec<GatewayExchange>>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for ReceiptGateway {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let result = thread.join();
            if !std::thread::panicking() {
                result.expect("Gateway TLS fixture");
            }
        }
    }
}

impl ReceiptGateway {
    fn start(listener: std::net::TcpListener, station: &AppState, key: SigningKey) -> Self {
        use std::io::{Read as _, Write as _};
        use std::sync::atomic::{AtomicBool, AtomicU8};
        use std::sync::{Arc, Mutex};

        use rustls::pki_types::pem::PemObject as _;
        let read = |name: &str| {
            std::fs::read(
                std::env::var_os(name)
                    .unwrap_or_else(|| panic!("{name} required: use run-native-rust-tests.py")),
            )
            .unwrap()
        };
        assert_eq!(read("SSL_CERT_FILE"), read("COTEST_RUN_SCOPED_CA_PEM"));
        let certificates =
            rustls::pki_types::CertificateDer::pem_slice_iter(&read("COLAND_TLS_CERT_PATH"))
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
        let private_key =
            rustls::pki_types::PrivateKeyDer::from_pem_slice(&read("COLAND_TLS_KEY_PATH")).unwrap();
        let tls = Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certificates, private_key)
            .unwrap(),
        );
        let base = format!("https://{}/", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let mode = Arc::new(AtomicU8::new(0));
        let stopped = Arc::new(AtomicBool::new(false));
        let exchanges = Arc::new(Mutex::new(Vec::new()));
        let thread_mode = mode.clone();
        let thread_stopped = stopped.clone();
        let thread_exchanges = exchanges.clone();
        let source = station.service_core_id();
        let source_key = station.notary_signing_key().verifying_key();
        let target = format!("{base}_arkret/edge/push/registrations:apply");
        let authority = listener.local_addr().unwrap().to_string();
        let thread = std::thread::spawn(move || {
            let mut receipts = std::collections::BTreeMap::new();
            while !thread_stopped.load(Ordering::SeqCst) {
                let (socket, _) = match listener.accept() {
                    Ok(connection) => connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(error) => panic!("Gateway accept: {error}"),
                };
                // Windows inherits the listener's nonblocking mode. The TLS
                // connection uses blocking I/O with explicit read/write
                // deadlines; only the listener polls so Drop can stop it.
                socket.set_nonblocking(false).unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut stream = rustls::StreamOwned::new(
                    rustls::ServerConnection::new(tls.clone()).unwrap(),
                    socket,
                );
                let mut raw = Vec::new();
                let mut buffer = [0u8; 4096];
                let header_end = loop {
                    let count = stream.read(&mut buffer).unwrap();
                    assert_ne!(count, 0, "incomplete Gateway HTTP request");
                    raw.extend_from_slice(&buffer[..count]);
                    assert!(raw.len() < 1024 * 1024);
                    if let Some(end) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                        let header = std::str::from_utf8(&raw[..end]).unwrap();
                        let length = header
                            .lines()
                            .find_map(|line| {
                                line.split_once(':').and_then(|(name, value)| {
                                    name.eq_ignore_ascii_case("content-length")
                                        .then(|| value.trim().parse::<usize>().unwrap())
                                })
                            })
                            .unwrap();
                        if raw.len() >= end + 4 + length {
                            break end;
                        }
                    }
                };
                let header = std::str::from_utf8(&raw[..header_end]).unwrap();
                let mut lines = header.lines();
                assert_eq!(
                    lines.next().unwrap(),
                    "POST /_arkret/edge/push/registrations:apply HTTP/1.1"
                );
                let headers = lines
                    .map(|line| line.split_once(':').unwrap())
                    .map(|(name, value)| (name.trim().to_owned(), value.trim().to_owned()))
                    .collect::<Vec<_>>();
                let get = |name: &str| {
                    headers
                        .iter()
                        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
                        .map(|(_, v)| v.as_str())
                };
                assert_eq!(get("Source-Service-ID"), Some(source.as_str()));
                assert_eq!(
                    get("Destination-Service-ID"),
                    Some("ak:did_core:web:push.deactivation.internal")
                );
                assert_eq!(
                    get("Arkret-Operation"),
                    Some("ak.edge.push.command.apply_registration.v1")
                );
                assert!(
                    get("Authorization").is_none(),
                    "no Account session at Gateway"
                );
                let body = &raw[header_end + 4..];
                let policy=arkret_signatures::http_signature::SignatureVerificationPolicy::for_scenario(
                    arkret_signatures::http_signature::HttpSignatureScenario::ServiceToServiceV1,&["content-digest"]).unwrap();
                arkret_signatures::http_signature::verify_signed_http_message(
                    "POST",
                    &target,
                    &authority,
                    "/_arkret/edge/push/registrations:apply",
                    headers.iter().map(|(n, v)| (n.as_str(), v.as_str())),
                    body,
                    &source_key,
                    &policy,
                    chrono::Utc::now().timestamp(),
                )
                .unwrap();
                let request: arkret_models_integration::PushRegistrationHandoffRequestBody =
                    serde_json::from_slice(body).unwrap();
                request.validate().unwrap();
                let rendered = std::str::from_utf8(body).unwrap();
                for forbidden in [
                    "account_id",
                    "principal_id",
                    "actor_id",
                    "ak:did_core:",
                    "did:",
                ] {
                    assert!(
                        !rendered.contains(forbidden),
                        "identity-bearing Gateway request"
                    );
                }
                let mode = thread_mode.load(Ordering::SeqCst);
                let (status, bytes, response) = if mode == 1 {
                    ("503 Service Unavailable",br#"{"type":"https://arkret.org/problems/temporarily_unavailable","title":"Gateway unavailable","status":503}"#.to_vec(),None)
                } else {
                    let digest = request.request_digest().unwrap();
                    let outcome = receipts
                        .entry(digest.to_string())
                        .or_insert_with(|| gateway_receipt(&request, &source, &key))
                        .clone();
                    let mut response = outcome;
                    if mode == 2 {
                        response.receipt.proof.jws = arkret_signatures::sign_ed25519_detached_jws(
                            &SigningKey::from_bytes(&[91; 32]),
                            &response.receipt.proof_binding_bytes().unwrap(),
                        )
                        .unwrap();
                    }
                    (
                        "200 OK",
                        serde_json::to_vec(&response).unwrap(),
                        Some(response),
                    )
                };
                thread_exchanges
                    .lock()
                    .unwrap()
                    .push(GatewayExchange { request, response });
                let header = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    bytes.len()
                );
                stream.write_all(header.as_bytes()).unwrap();
                stream.write_all(&bytes).unwrap();
                stream.flush().unwrap();
            }
        });
        Self {
            base,
            mode,
            stopped,
            exchanges,
            thread: Some(thread),
        }
    }
}

fn gateway_receipt(
    request: &arkret_models_integration::PushRegistrationHandoffRequestBody,
    source: &DidCoreId,
    key: &SigningKey,
) -> arkret_models_integration::PushRegistrationHandoffResponseBody {
    use arkret_models_integration::{
        PushRegistrationHandoffResponseBody, PushRegistrationInstallationReceipt,
    };
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let mut receipt = PushRegistrationInstallationReceipt {
        registration_id: request.registration_id().clone(),
        push_target_id: request.push_target_id().clone(),
        device_id: request.device_id().clone(),
        state: request.state(),
        request_digest: request.request_digest().unwrap(),
        source_station_id: source.clone(),
        destination_gateway_id: DidCoreId::new("ak:did_core:web:push.deactivation.internal")
            .unwrap(),
        stored_at: at,
        proof: arkret_wire::PayloadProof {
            kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
            verification_method: arkret_wire::DidUrl::new(
                "did:web:push.deactivation.internal#receipt",
            )
            .unwrap(),
            payload_digest: request.request_digest().unwrap(),
            created_at: at,
            domain: None,
            audience: Some(arkret_wire::Audience::Single(source.to_string())),
            proof_purpose: None,
            jws: "eyJhbGciOiJFZDI1NTE5In0..placeholder".to_owned(),
        },
    };
    receipt.proof.payload_digest = receipt.expected_payload_digest().unwrap();
    receipt.proof.jws =
        arkret_signatures::sign_ed25519_detached_jws(key, &receipt.proof_binding_bytes().unwrap())
            .unwrap();
    arkret::verify_push_registration_installation_receipt(
        &receipt,
        request,
        source,
        &receipt.destination_gateway_id,
        &key.verifying_key(),
    )
    .unwrap();
    PushRegistrationHandoffResponseBody { receipt }
}

#[test]
fn opaque_deactivation_recovery_requires_verified_durable_gateway_receipt() {
    run_on_test_runtime(
        "opaque_deactivation_recovery_requires_verified_durable_gateway_receipt",
        opaque_deactivation_recovery_future,
    );
}

#[inline(never)]
fn opaque_deactivation_recovery_future() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()>>>
{
    Box::pin(opaque_deactivation_recovery_body())
}

async fn opaque_deactivation_recovery_body() {
    use arkret_models_integration::{PushRegisterDeviceResponseBody, PushRegistrationHandoffState};
    use coland_storage::PushRegistrationHandoffIntentStatus;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("https://{}/", listener.local_addr().unwrap());
    let gateway_key = SigningKey::from_bytes(&[87; 32]);
    let mut config = test_config();
    config.trusted_push_gateways=coland_http::push_gateway_registry::TrustedPushGatewayRegistry::from_json(
        &serde_json::json!([{
            "canonical_origin":base.trim_end_matches('/'),
            "service_did":"did:web:push.deactivation.internal",
            "receipt_verification_method":"did:web:push.deactivation.internal#receipt",
            "receipt_public_key_multibase":arkret_canonical::ed25519_pubkey_to_did_key_multibase(gateway_key.verifying_key().as_bytes()),
        }]).to_string()).unwrap();
    let (state, pool) = coland_test_support::app_state_with_pool(config.clone());
    state.test_install_service_route_fetcher(std::sync::Arc::new(gateway_route(
        &base,
        &gateway_key,
    )));
    let gateway = ReceiptGateway::start(listener, &state, gateway_key.clone());
    assert_eq!(gateway.base, base);
    let fixture = coland_test_support::pcr_genesis::PcrGenesisFixture::new(state.service_did());
    fixture.admit(&state).await.unwrap();
    let account = fixture.history.account.clone();
    let device = fixture.history.founding_device_id.clone();
    let token = dev_token_for_device(
        state.clone(),
        fixture.history.did.as_str(),
        device.as_str(),
        "Push device",
    )
    .await;
    let admin = dev_token(state.clone()).await;
    let mut response=TestClient::post("http://server/_arkret/edge/push/register-device")
        .add_header("authorization",format!("Bearer {token}"),true)
        .json(&serde_json::json!({"device_id":device,"push_gateway_url":base,"push_key":"provider-private-token",
            "platform":"desktop","app_id":"inkson"})).send(&app_from_state(state.clone())).await;
    assert_eq!(
        response.status_code,
        Some(StatusCode::OK),
        "real public-Gateway registration must succeed"
    );
    let installed: PushRegisterDeviceResponseBody = response.take_json().await.unwrap();
    let registration_id = arkret_models_integration::PushRegistrationId::new(
        installed
            .registration_id
            .as_ref()
            .expect("public Gateway registration id")
            .as_str()
            .to_owned(),
    )
    .unwrap();
    let persistence = state.test_persistence();
    let active = persistence
        .push_registration_handoffs()
        .get_intent(&account.station_id, &registration_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        active.status,
        PushRegistrationHandoffIntentStatus::ReceiptVerified
    );
    assert_eq!(active.desired_state, PushRegistrationHandoffState::Active);
    assert_eq!(active.local_route.account_id, account);
    assert_eq!(
        persistence
            .push_devices()
            .snapshot_all()
            .await
            .unwrap()
            .len(),
        1
    );
    gateway.mode.store(1, Ordering::SeqCst);
    let result = admin_deactivate(state.clone(), &admin, account.principal_id.as_str()).await;
    assert_eq!(result["state"], "deactivated");
    assert!(state.deactivation_push_partial(account.principal_id.as_str()));
    assert!(
        persistence
            .push_devices()
            .snapshot_all()
            .await
            .unwrap()
            .is_empty()
    );
    let pending = persistence
        .push_registration_handoffs()
        .get_intent(&account.station_id, &registration_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pending.desired_state, PushRegistrationHandoffState::Revoked);
    assert_eq!(
        pending.status,
        PushRegistrationHandoffIntentStatus::AwaitingReceipt
    );
    assert!(pending.receipt.is_none());
    let original = pending.canonical_request.clone();
    drop(state);
    // Rebuild all local projections and the worker from the same real PG
    // state; never inject the observation witness into the product ledger.
    let cold_store: std::sync::Arc<dyn coland_storage::PersistenceStore> = std::sync::Arc::new(
        coland_storage_postgres::PgPersistenceStore::new(pool.clone()),
    );
    let cold = coland_test_support::app_state_with_persistence(config.clone(), cold_store).await;
    cold.hydrate().await.unwrap();
    cold.test_install_service_route_fetcher(std::sync::Arc::new(gateway_route(
        &base,
        &gateway_key,
    )));
    assert_eq!(
        cold.account_lifecycle_state(account.principal_id.as_str()),
        "deactivated"
    );
    gateway.mode.store(2, Ordering::SeqCst);
    assert_eq!(Worker::new(cold.clone()).run_once().await, 0);
    assert!(
        cold.deactivation_push_partial(account.principal_id.as_str()),
        "wrong-key receipt cannot complete deactivation"
    );
    let refused = persistence
        .push_registration_handoffs()
        .get_intent(&account.station_id, &registration_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        refused.status,
        PushRegistrationHandoffIntentStatus::AwaitingReceipt
    );
    assert!(refused.receipt.is_none());
    assert_eq!(refused.canonical_request, original);
    gateway.mode.store(0, Ordering::SeqCst);
    assert_eq!(Worker::new(cold.clone()).run_once().await, 1);
    assert!(!cold.deactivation_push_partial(account.principal_id.as_str()));
    let committed = persistence
        .push_registration_handoffs()
        .get_intent(&account.station_id, &registration_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        committed.status,
        PushRegistrationHandoffIntentStatus::ReceiptVerified
    );
    assert_eq!(committed.canonical_request, original);
    let exact_request = committed.request().unwrap();
    let receipt = committed.receipt.clone().unwrap();
    arkret::verify_push_registration_installation_receipt(
        &receipt,
        &exact_request,
        &account.station_id,
        &committed.destination_gateway_id,
        &gateway_key.verifying_key(),
    )
    .unwrap();
    let exchanges = gateway.exchanges.lock().unwrap().clone();
    assert!(
        exchanges
            .iter()
            .any(|exchange| exchange.request.state() == PushRegistrationHandoffState::Active)
    );
    assert!(exchanges.iter().any(|exchange| exchange.request.state()
        == PushRegistrationHandoffState::Revoked
        && exchange.response.is_none()));
    let mut saw_exact_verified_receipt = false;
    for exchange in exchanges
        .iter()
        .filter(|exchange| exchange.request.state() == PushRegistrationHandoffState::Revoked)
    {
        assert_eq!(
            arkret_canonical::canonical_json_bytes(&exchange.request).unwrap(),
            original.as_slice()
        );
        if exchange
            .response
            .as_ref()
            .is_some_and(|outcome| outcome.receipt == receipt)
        {
            saw_exact_verified_receipt = true;
        }
    }
    assert!(
        saw_exact_verified_receipt,
        "the PG receipt must equal the Gateway's real signed response"
    );
    let before = gateway.exchanges.lock().unwrap().len();
    drop(cold);
    let reopened_store: std::sync::Arc<dyn coland_storage::PersistenceStore> =
        std::sync::Arc::new(coland_storage_postgres::PgPersistenceStore::new(pool));
    let reopened = coland_test_support::app_state_with_persistence(config, reopened_store).await;
    reopened.hydrate().await.unwrap();
    assert_eq!(Worker::new(reopened.clone()).run_once().await, 0);
    assert!(!reopened.deactivation_push_partial(account.principal_id.as_str()));
    assert_eq!(
        gateway.exchanges.lock().unwrap().len(),
        before,
        "durable completed revoke must not be re-sent"
    );
    let replay = persistence
        .push_registration_handoffs()
        .get_intent(&account.station_id, &registration_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(replay.canonical_request, original);
    assert_eq!(replay.receipt, Some(receipt));
}
