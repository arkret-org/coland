//! Registered Applet completion delivery after an independent Bot provision.
//! Run the completion test filter; the imported admission tests retain their
//! independent target and are not counted again as completion evidence.

#[path = "applet_admission.rs"]
#[allow(dead_code)]
mod admission;

use std::io::{Read, Write};

use arkret_models_integration::{AppletTransactionOutcome, AppletTransactionRequestBody};
use arkret_signatures::http_signature::{
    HttpSignatureScenario, SignatureVerificationPolicy, verify_signed_http_message,
};
use coland_test_support::AppStateTestExt as _;

fn request_bytes(socket: &mut impl Read) -> Vec<u8> {
    let mut raw = Vec::new();
    loop {
        let mut chunk = [0_u8; 4096];
        let count = socket.read(&mut chunk).unwrap();
        assert!(
            count > 0,
            "completion request ended before its complete body"
        );
        raw.extend_from_slice(&chunk[..count]);
        if let Some(end) = raw.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
            let headers = std::str::from_utf8(&raw[..end]).unwrap();
            let length = headers
                .lines()
                .find_map(|line| {
                    line.split_once(':').and_then(|(name, value)| {
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().unwrap())
                    })
                })
                .unwrap();
            if raw.len() >= end + 4 + length {
                return raw;
            }
        }
    }
}

#[tokio::test]
async fn durable_completion_retries_real_signed_delivery_before_ack() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let endpoint = format!("https://{addr}");
    let tls = std::sync::Arc::new(
        rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(
                include_bytes!("fixtures/outbox-test-cert.der").to_vec(),
            )],
            rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
                include_bytes!("fixtures/outbox-test-key.der").to_vec(),
            )),
        )
        .unwrap(),
    );
    let fixture = admission::Fixture::new().await;
    let install = fixture.install_at_endpoint(false, Some(&endpoint)).await;
    let pending = fixture
        .state
        .test_persistence()
        .applets()
        .pending_authoring_completions(16)
        .await
        .unwrap();
    assert_eq!(
        pending.len(),
        1,
        "the accepted production unit writes one durable completion"
    );
    let expected = pending[0].clone();
    assert_eq!(expected.endpoint, endpoint);
    assert_eq!(expected.applet_id, install.package.applet_id);
    assert_eq!(expected.destination_id, install.package.service_id);
    assert_eq!(expected.source_id, fixture.state.service_core_id());
    let body = AppletTransactionRequestBody::Authoring(Box::new(
        arkret_models_integration::AppletAuthoringTransactionRequestBody {
            applet_id: expected.applet_id.clone(),
            source_id: expected.source_id.clone(),
            authoring_context: expected.context.clone(),
        },
    ));
    let expected_bytes = arkret_canonical::canonical_json_bytes(&body).unwrap();
    let key = fixture.state.notary_signing_key().verifying_key();
    let (send, mut receive) = tokio::sync::mpsc::channel(2);
    let server = std::thread::spawn(move || {
        for attempt in 0..2 {
            let (socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut socket = rustls::StreamOwned::new(
                rustls::ServerConnection::new(tls.clone()).unwrap(),
                socket,
            );
            let raw = request_bytes(&mut socket);
            let end = raw
                .windows(4)
                .position(|bytes| bytes == b"\r\n\r\n")
                .unwrap();
            let header_block = std::str::from_utf8(&raw[..end]).unwrap();
            let mut lines = header_block.lines();
            assert_eq!(
                lines.next().unwrap(),
                "POST /_arkret/edge/applet/transactions HTTP/1.1"
            );
            let headers = lines
                .map(|line| line.split_once(':').unwrap())
                .map(|(name, value)| (name.to_owned(), value.trim().to_owned()))
                .collect::<Vec<_>>();
            let header = |name: &str| {
                headers
                    .iter()
                    .find(|(key, _)| key.eq_ignore_ascii_case(name))
                    .unwrap()
                    .1
                    .as_str()
            };
            assert_eq!(
                header("Arkret-Operation"),
                arkret_wire::ServiceOperationId::EDGE_APPLET_COMMAND_TRANSACTION_V1
            );
            assert_eq!(header("Source-Service-ID"), expected.source_id.as_str());
            assert_eq!(
                header("Destination-Service-ID"),
                expected.destination_id.as_str()
            );
            assert_eq!(header("Idempotency-Key"), expected.idempotency_key);
            assert!(
                !headers
                    .iter()
                    .any(|(name, _)| name.eq_ignore_ascii_case("Authorization"))
            );
            let body = &raw[end + 4..];
            assert_eq!(body, expected_bytes);
            let decoded: AppletTransactionRequestBody = serde_json::from_slice(body).unwrap();
            decoded.validate().unwrap();
            assert!(matches!(
                decoded,
                AppletTransactionRequestBody::Authoring(_)
            ));
            let policy = SignatureVerificationPolicy::for_scenario(
                HttpSignatureScenario::ServiceToServiceV1,
                &["content-digest", "idempotency-key"],
            )
            .unwrap();
            verify_signed_http_message(
                "POST",
                &format!("https://{addr}/_arkret/edge/applet/transactions"),
                &addr.to_string(),
                "/_arkret/edge/applet/transactions",
                headers
                    .iter()
                    .map(|(name, value)| (name.as_str(), value.as_str())),
                body,
                &key,
                &policy,
                chrono::Utc::now().timestamp(),
            )
            .unwrap();
            let signature_input = header("Signature-Input").to_owned();
            send.blocking_send((body.to_vec(), signature_input))
                .unwrap();
            let (status, response) = if attempt == 0 {
                ("503 Service Unavailable",serde_json::json!({"type":"https://arkret.org/problems/service_unavailable","title":"Service unavailable","status":503,"code":"service_unavailable"}).to_string())
            } else {
                (
                    "200 OK",
                    serde_json::to_string(&AppletTransactionOutcome::Accepted {
                        committed_event_refs: vec![],
                        rejections: vec![],
                        retry_after_ms: None,
                    })
                    .unwrap(),
                )
            };
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
                response.len()
            );
            socket.write_all(response.as_bytes()).unwrap();
            socket.conn.send_close_notify();
            socket.flush().unwrap();
        }
    });
    assert_eq!(
        coland_http::state::deliver_pending_applet_completions(&fixture.state)
            .await
            .unwrap(),
        0
    );
    let first = receive.recv().await.unwrap();
    let retained = fixture
        .state
        .test_persistence()
        .applets()
        .pending_authoring_completions(16)
        .await
        .unwrap();
    assert_eq!(
        retained.len(),
        1,
        "HTTP failure does not consume the durable completion"
    );
    assert_eq!(
        arkret_canonical::canonical_json_bytes(&retained[0].context).unwrap(),
        arkret_canonical::canonical_json_bytes(&pending[0].context).unwrap()
    );
    assert_eq!(retained[0].request_digest, pending[0].request_digest);
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    assert_eq!(
        coland_http::state::deliver_pending_applet_completions(&fixture.state)
            .await
            .unwrap(),
        1
    );
    let second = receive.recv().await.unwrap();
    assert_eq!(
        first.0, second.0,
        "retry sends the immutable accepted context"
    );
    assert_ne!(
        first.1, second.1,
        "the retry obtains a fresh per-delivery HTTP signature"
    );
    assert!(
        fixture
            .state
            .test_persistence()
            .applets()
            .pending_authoring_completions(16)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        coland_http::state::deliver_pending_applet_completions(&fixture.state)
            .await
            .unwrap(),
        0,
        "acknowledged completion is not redelivered"
    );
    server.join().unwrap();
}
