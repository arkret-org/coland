//! Integration tests — push-gateway deactivation fanout producer
//! (`account-lifecycle.md` §7.1 Push-route completion criterion).
//!
//! The mock gateway is a minimal thread-backed HTTP responder that echoes the
//! request's `fanout_id` back inside a floria-contracts ack, so the
//! deterministic first-attempt id and any minted retry id both validate.

use std::io::{Read, Write};
use std::sync::mpsc;
use std::time::Duration;

use coland_http::deactivation_push_fanout::Worker;

use super::common::*;

/// Serve `count` echoing ack responses (HTTP 200) then stop. Every received
/// request's raw text is sent through the returned channel.
fn spawn_mock_gateway(
    listener: std::net::TcpListener,
    count: usize,
    outcome: &'static str,
) -> mpsc::Receiver<String> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for _ in 0..count {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut buffer = [0_u8; 16384];
            let read = stream.read(&mut buffer).unwrap_or(0);
            let request = String::from_utf8_lossy(&buffer[..read]).to_string();
            let fanout_id = request
                .split("\"fanout_id\":\"")
                .nth(1)
                .and_then(|rest| rest.split('"').next())
                .unwrap_or("unknown")
                .to_owned();
            let body = format!(
                "{{\"fanout_id\":\"{fanout_id}\",\"outcome\":\"{outcome}\",\"actor_bindings_unbound\":1,\"device_bindings_unbound\":0,\"messages_drained\":0}}"
            );
            let head = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len(),
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(body.as_bytes());
            let _ = tx.send(request);
        }
    });
    rx
}

fn gateway_config(url: &str) -> AppConfig {
    AppConfig {
        deactivation_push_gateway_url: Some(url.to_owned()),
        deactivation_push_gateway_bearer: Some("internal-test-token".to_owned()),
        ..test_config()
    }
}

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
fn deactivation_notifies_configured_push_gateway_and_clears_partial() {
    run_on_test_runtime(
        "deactivation_notifies_configured_push_gateway_and_clears_partial",
        deactivation_notifies_configured_push_gateway_and_clears_partial_body,
    );
}

async fn deactivation_notifies_configured_push_gateway_and_clears_partial_body() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let requests = spawn_mock_gateway(listener, 1, "completed");

    let state = coland_test_support::app_state(gateway_config(&url));
    let admin = dev_token(state.clone()).await;
    let _token = register_account(
        state.clone(),
        "did:web:push-deact-a.example",
        "@push-deact-a",
        "ak:device:01904100-0000-7000-8000-de0c70000001",
    )
    .await;
    let did = fixture_actor_core_id("did:web:push-deact-a.example");

    let body = admin_deactivate(state.clone(), &admin, did.as_str()).await;
    assert_eq!(body["state"], "deactivated");
    assert_eq!(state.account_lifecycle_state(did.as_str()), "deactivated");

    // The inline attempt reached the gateway with the internal bearer and the
    // audited wire shape.
    let request = requests
        .recv_timeout(Duration::from_secs(5))
        .expect("gateway must receive the fanout broadcast");
    let request_lower = request.to_ascii_lowercase();
    assert!(
        request_lower.contains("post /_floria/internal/account_deactivate_fanout"),
        "fanout must target the contract path: {request}"
    );
    assert!(
        request_lower.contains("authorization: bearer internal-test-token"),
        "fanout must carry the internal bearer: {request}"
    );
    let json_body = request
        .split("\r\n\r\n")
        .nth(1)
        .expect("request carries a body");
    let broadcast: floria_contracts::AccountDeactivateFanoutBroadcast =
        serde_json::from_str(json_body).expect("body parses as the audited broadcast contract");
    assert_eq!(broadcast.actor_id, did.as_str());
    assert_eq!(
        broadcast.fanout_id,
        coland_http::deactivation_push_fanout::base_fanout_id(state.service_id(), did.as_str())
    );
    assert!(broadcast.devices.is_empty());

    // Gateway acked completed — no partial flag, and the admin projection
    // reports the flag honestly alongside the federation flag.
    assert!(!state.deactivation_push_partial(did.as_str()));
    let row = admin_actor_row(state.clone(), &admin, did.as_str()).await;
    assert_eq!(row["status"], "deactivated");
    assert_eq!(row["deactivation_partial"], false, "row: {row}");

    // Reconciliation finds nothing left to do (durable completion marker).
    assert_eq!(Worker::new(state.clone()).run_once().await, 0);
}

#[test]
fn gateway_failure_marks_partial_and_worker_retries_until_ack() {
    run_on_test_runtime(
        "gateway_failure_marks_partial_and_worker_retries_until_ack",
        gateway_failure_marks_partial_and_worker_retries_until_ack_body,
    );
}

async fn gateway_failure_marks_partial_and_worker_retries_until_ack_body() {
    // Reserve a port, then drop the listener so the inline attempt gets a
    // connection error.
    let parked = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = parked.local_addr().unwrap();
    drop(parked);
    let url = format!("http://{addr}");

    let state = coland_test_support::app_state(gateway_config(&url));
    let admin = dev_token(state.clone()).await;
    let _token = register_account(
        state.clone(),
        "did:web:push-deact-b.example",
        "@push-deact-b",
        "ak:device:01904100-0000-7000-8000-de0c70000002",
    )
    .await;
    let did = fixture_actor_core_id("did:web:push-deact-b.example");

    let body = admin_deactivate(state.clone(), &admin, did.as_str()).await;
    assert_eq!(body["state"], "deactivated");
    // §7.1: the failed leg keeps the deactivation but raises the
    // service-side `deactivation_partial` flag.
    assert!(state.deactivation_push_partial(did.as_str()));
    let row = admin_actor_row(state.clone(), &admin, did.as_str()).await;
    assert_eq!(row["deactivation_partial"], true, "row: {row}");

    // A restart empties the in-memory projection; the worker's first pass
    // MUST restore it from durable state even while the gateway stays down.
    state.set_deactivation_push_partial(did.as_str(), false);
    assert_eq!(Worker::new(state.clone()).run_once().await, 0);
    assert!(
        state.deactivation_push_partial(did.as_str()),
        "worker pass must restore deactivation_partial after restart"
    );

    // Gateway comes back on the same address — the retry completes the leg
    // and clears the flag.
    let listener = std::net::TcpListener::bind(addr).expect("rebind mock gateway port");
    let requests = spawn_mock_gateway(listener, 1, "completed");
    assert_eq!(Worker::new(state.clone()).run_once().await, 1);
    requests
        .recv_timeout(Duration::from_secs(5))
        .expect("gateway must receive the retried broadcast");
    assert!(!state.deactivation_push_partial(did.as_str()));
    let row = admin_actor_row(state.clone(), &admin, did.as_str()).await;
    assert_eq!(row["deactivation_partial"], false, "row: {row}");

    // Completion is durable: another pass has nothing to send.
    assert_eq!(Worker::new(state.clone()).run_once().await, 0);
}

#[test]
fn partially_completed_ack_keeps_partial_until_retry_completes() {
    run_on_test_runtime(
        "partially_completed_ack_keeps_partial_until_retry_completes",
        partially_completed_ack_keeps_partial_until_retry_completes_body,
    );
}

async fn partially_completed_ack_keeps_partial_until_retry_completes_body() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    // First answer: partially_completed (gateway bookkeeping incomplete).
    // Second answer (fresh fanout_id): completed.
    let requests = spawn_mock_gateway(listener, 2, "partially_completed");

    let state = coland_test_support::app_state(gateway_config(&url));
    let admin = dev_token(state.clone()).await;
    let _token = register_account(
        state.clone(),
        "did:web:push-deact-c.example",
        "@push-deact-c",
        "ak:device:01904100-0000-7000-8000-de0c70000003",
    )
    .await;
    let did = fixture_actor_core_id("did:web:push-deact-c.example");

    let _ = admin_deactivate(state.clone(), &admin, did.as_str()).await;
    let first = requests
        .recv_timeout(Duration::from_secs(5))
        .expect("gateway must receive the first broadcast");
    // A partially_completed ack is NOT completion (§7.1 — no gateway result,
    // no completion): the flag stays raised.
    assert!(state.deactivation_push_partial(did.as_str()));

    // A fresh worker (no in-memory retry state, e.g. after restart) falls
    // back to the deterministic base id and keeps retrying; the second
    // partial ack still does not complete the leg.
    assert_eq!(Worker::new(state.clone()).run_once().await, 0);
    let second = requests
        .recv_timeout(Duration::from_secs(5))
        .expect("gateway must receive the retried broadcast");
    let id_of = |request: &str| {
        request
            .split("\"fanout_id\":\"")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .unwrap_or_default()
            .to_owned()
    };
    assert_eq!(
        id_of(&first),
        coland_http::deactivation_push_fanout::base_fanout_id(state.service_id(), did.as_str())
    );
    assert_eq!(id_of(&second), id_of(&first));
    assert!(state.deactivation_push_partial(did.as_str()));
}

#[test]
fn no_gateway_configured_completes_locally_without_partial() {
    run_on_test_runtime(
        "no_gateway_configured_completes_locally_without_partial",
        no_gateway_configured_completes_locally_without_partial_body,
    );
}

async fn no_gateway_configured_completes_locally_without_partial_body() {
    // Default test config: no `deactivation_push_gateway_url`. The §7.1
    // criterion is conditional on a registered internal channel to a gateway
    // that independently holds delivery state; without one, the local
    // push-route purge completes the Push-route row and the flag never
    // rises.
    let state = coland_test_support::app_state(test_config());
    let admin = dev_token(state.clone()).await;
    let _token = register_account(
        state.clone(),
        "did:web:push-deact-d.example",
        "@push-deact-d",
        "ak:device:01904100-0000-7000-8000-de0c70000004",
    )
    .await;
    let did = fixture_actor_core_id("did:web:push-deact-d.example");

    let body = admin_deactivate(state.clone(), &admin, did.as_str()).await;
    assert_eq!(body["state"], "deactivated");
    assert!(!state.deactivation_push_partial(did.as_str()));
    let row = admin_actor_row(state.clone(), &admin, did.as_str()).await;
    assert_eq!(row["deactivation_partial"], false, "row: {row}");
    assert_eq!(Worker::new(state).run_once().await, 0);
}
