//! Integration tests — DeviceMessage send admission over real PostgreSQL
//! (`device-lifecycle.md` §7, `ak.vector.sync.device_message_send_admission.v1`).
//!
//! Exact idempotency (same `device_message_id` and canonical intent) is judged
//! first and returns the original enqueue result, even after `expires_at`.
//! Every other target whose `expires_at` is missing, already expired, not
//! later than the materialized `sent_at` or beyond the 24 hour default enqueue
//! TTL fails the whole request with top-level `param_invalid` and zero queue or
//! idempotency writes. `unknown_devices` rows carry only `device_message_id`
//! and `status`.

use coland_test_support::pcr_genesis::PcrGenesisFixture;

use super::common::*;

const SEND_PATH: &str = "http://server/_arkret/self/device_messages";
const APPLICATION_KIND: &str = "ak.mls.application";

struct Sender {
    state: AppState,
    service: salvo::Service,
    token: String,
    principal_id: String,
    device_id: String,
}

async fn accepted_sender() -> Sender {
    let state = coland_test_support::app_state(test_config());
    let fixture = PcrGenesisFixture::new(state.service_did());
    fixture.admit(&state).await.expect("accepted PCR genesis");
    let device_id = fixture.history.founding_device_id.to_string();
    let token = dev_token_for_device(
        state.clone(),
        fixture.history.did.as_str(),
        &device_id,
        "PCR device",
    )
    .await;
    Sender {
        service: app_from_state(state.clone()),
        principal_id: fixture.history.account.principal_id.to_string(),
        state,
        token,
        device_id,
    }
}

fn target(device_message_id: &str, expires_at: chrono::DateTime<chrono::Utc>) -> Value {
    serde_json::json!({
        "device_message_id": device_message_id,
        "kind": APPLICATION_KIND,
        "expires_at": canonical_timestamp(expires_at),
        "content": {"ciphertext": "b3BhcXVl"},
    })
}

async fn send(sender: &Sender, idempotency_key: &str, body: &Value) -> (StatusCode, Value) {
    let mut response = TestClient::post(SEND_PATH)
        .add_header("authorization", format!("Bearer {}", sender.token), true)
        .add_header("idempotency-key", idempotency_key, true)
        .json(body)
        .send(&sender.service)
        .await;
    let status = response.status_code.expect("status");
    let body = response.take_json::<Value>().await.expect("JSON body");
    (status, body)
}

/// Application messages durably queued in PostgreSQL for one recipient
/// endpoint. Session bootstrap may queue actor-private updates; only the
/// application messages under test are counted.
async fn queued_device_message_ids(sender: &Sender, device_id: &str) -> Vec<String> {
    sender
        .state
        .test_persistence()
        .device_messages()
        .list_after(&sender.principal_id, device_id, 0, 1_000)
        .await
        .expect("PostgreSQL device-message queue read")
        .into_iter()
        .filter(|message| message.envelope.kind.as_str() == APPLICATION_KIND)
        .map(|message| message.envelope.device_message_id.to_string())
        .collect()
}

fn assert_param_invalid(status: StatusCode, problem: &Value, case: &str) {
    assert_eq!(status, StatusCode::BAD_REQUEST, "{case}: {problem}");
    assert_eq!(problem_code(problem), "param_invalid", "{case}: {problem}");
}

#[test]
fn device_message_outside_the_enqueue_window_is_refused_with_zero_writes() {
    run_on_test_runtime(
        "device_message_outside_the_enqueue_window_is_refused_with_zero_writes",
        device_message_outside_the_enqueue_window_is_refused_with_zero_writes_body,
    );
}

async fn device_message_outside_the_enqueue_window_is_refused_with_zero_writes_body() {
    let sender = accepted_sender().await;
    let now = chrono::Utc::now();
    let admitted_id = "ak:device_message:0196419b-0000-7000-8000-0000000e0001";
    let refused = [
        ("already-expired", Some(now - chrono::Duration::minutes(1))),
        (
            "beyond-default-ttl",
            Some(now + chrono::Duration::hours(24) + chrono::Duration::minutes(5)),
        ),
        ("missing", None),
    ];
    for (case, expires_at) in refused {
        let mut message = target(admitted_id, now);
        match expires_at {
            Some(expires_at) => message["expires_at"] = canonical_timestamp(expires_at).into(),
            None => {
                message.as_object_mut().unwrap().remove("expires_at");
            }
        }
        let body = serde_json::json!({
            "messages": {
                sender.principal_id.as_str(): {
                    sender.device_id.as_str(): message,
                },
            },
        });
        for attempt in ["first", "retry"] {
            let (status, problem) = send(&sender, case, &body).await;
            assert_param_invalid(status, &problem, &format!("{case} {attempt}"));
        }
    }
    assert!(
        queued_device_message_ids(&sender, &sender.device_id)
            .await
            .is_empty(),
        "a refused enqueue must leave the PostgreSQL queue empty"
    );

    // Neither idempotency ledger was written: the refused request's HTTP key
    // accepts a different body, and the same logical message with an
    // admissible window is fresh instead of a device_message_id conflict.
    let body = serde_json::json!({
        "messages": {
            sender.principal_id.as_str(): {
                sender.device_id.as_str(): target(admitted_id, now + chrono::Duration::minutes(10)),
            },
        },
    });
    let (status, outcome) = send(&sender, refused[0].0, &body).await;
    assert_eq!(status, StatusCode::OK, "{outcome}");
    assert_eq!(
        outcome["delivered"][sender.principal_id.as_str()][sender.device_id.as_str()]["status"],
        "delivered",
        "{outcome}"
    );
    assert_eq!(outcome["unknown_devices"], serde_json::json!({}));
    assert_eq!(
        queued_device_message_ids(&sender, &sender.device_id).await,
        vec![admitted_id]
    );
}

#[test]
fn one_invalid_expires_at_rejects_the_whole_mixed_batch() {
    run_on_test_runtime(
        "one_invalid_expires_at_rejects_the_whole_mixed_batch",
        one_invalid_expires_at_rejects_the_whole_mixed_batch_body,
    );
}

async fn one_invalid_expires_at_rejects_the_whole_mixed_batch_body() {
    let sender = accepted_sender().await;
    let now = chrono::Utc::now();
    let admitted_id = "ak:device_message:0196419b-0000-7000-8000-0000000e0101";
    let refused_id = "ak:device_message:0196419b-0000-7000-8000-0000000e0102";
    let other_device = "ak:device:01904100-0000-7000-8000-0000000e0102";
    let valid = target(admitted_id, now + chrono::Duration::minutes(10));
    let variants = [
        ("expired", Some(now - chrono::Duration::seconds(1))),
        ("before-sent-at", Some(now - chrono::Duration::hours(1))),
        (
            "over-limit",
            Some(now + chrono::Duration::hours(24) + chrono::Duration::minutes(5)),
        ),
        ("missing", None),
    ];
    for (case, expires_at) in variants {
        let mut refused = target(refused_id, now);
        match expires_at {
            Some(expires_at) => refused["expires_at"] = canonical_timestamp(expires_at).into(),
            None => {
                refused.as_object_mut().unwrap().remove("expires_at");
            }
        }
        let body = serde_json::json!({
            "messages": {
                sender.principal_id.as_str(): {
                    sender.device_id.as_str(): valid.clone(),
                    other_device: refused,
                },
            },
        });
        let (status, problem) = send(&sender, case, &body).await;
        assert_param_invalid(status, &problem, case);
        assert!(
            problem.get("unknown_devices").is_none(),
            "{case}: {problem}"
        );
    }
    for device_id in [sender.device_id.as_str(), other_device] {
        assert!(
            queued_device_message_ids(&sender, device_id)
                .await
                .is_empty(),
            "the admissible target of a refused batch must not be enqueued in PostgreSQL"
        );
    }

    // The admissible target was never written to either ledger: it is fresh
    // under the refused request's HTTP key and its own device_message_id.
    let body = serde_json::json!({
        "messages": {
            sender.principal_id.as_str(): {
                sender.device_id.as_str(): valid,
            },
        },
    });
    let (status, outcome) = send(&sender, variants[0].0, &body).await;
    assert_eq!(status, StatusCode::OK, "{outcome}");
    assert_eq!(
        outcome["delivered"][sender.principal_id.as_str()][sender.device_id.as_str()]["status"],
        "delivered",
        "{outcome}"
    );
    assert_eq!(
        queued_device_message_ids(&sender, &sender.device_id).await,
        vec![admitted_id]
    );
}

#[test]
fn exact_retry_after_expires_at_returns_the_original_result() {
    run_on_test_runtime(
        "exact_retry_after_expires_at_returns_the_original_result",
        exact_retry_after_expires_at_returns_the_original_result_body,
    );
}

async fn exact_retry_after_expires_at_returns_the_original_result_body() {
    let sender = accepted_sender().await;
    let delivered_id = "ak:device_message:0196419b-0000-7000-8000-0000000e0201";
    let expires_at = chrono::Utc::now() + chrono::Duration::milliseconds(1_500);
    let body = serde_json::json!({
        "messages": {
            sender.principal_id.as_str(): {
                sender.device_id.as_str(): target(delivered_id, expires_at),
            },
        },
    });
    let (status, original) = send(&sender, "original", &body).await;
    assert_eq!(status, StatusCode::OK, "{original}");
    assert_eq!(
        original["delivered"][sender.principal_id.as_str()][sender.device_id.as_str()]["status"],
        "delivered",
        "{original}"
    );

    let wait = (expires_at - chrono::Utc::now()) + chrono::Duration::milliseconds(50);
    tokio::time::sleep(wait.to_std().unwrap_or_default()).await;
    assert!(chrono::Utc::now() > expires_at);

    // The same HTTP request and the same logical message under a new
    // Idempotency-Key both replay the original result without re-judging
    // expiry or enqueueing again.
    for idempotency_key in ["original", "logical-retry"] {
        let (status, replay) = send(&sender, idempotency_key, &body).await;
        assert_eq!(status, StatusCode::OK, "{idempotency_key}: {replay}");
        assert_eq!(replay, original, "{idempotency_key}");
    }
    assert_eq!(
        queued_device_message_ids(&sender, &sender.device_id).await,
        vec![delivered_id]
    );
}

#[test]
fn undeliverable_recipients_are_indistinguishable_unknown_rows() {
    run_on_test_runtime(
        "undeliverable_recipients_are_indistinguishable_unknown_rows",
        undeliverable_recipients_are_indistinguishable_unknown_rows_body,
    );
}

async fn undeliverable_recipients_are_indistinguishable_unknown_rows_body() {
    let sender = accepted_sender().await;
    let now = chrono::Utc::now();
    let unknown_id = "ak:device_message:0196419b-0000-7000-8000-0000000e0301";
    let foreign_id = "ak:device_message:0196419b-0000-7000-8000-0000000e0302";
    let unknown_device = "ak:device:01904100-0000-7000-8000-0000000e0301";
    let foreign_principal = "ak:did_core:web:unknown-recipient.example";
    let foreign_device = "ak:device:01904100-0000-7000-8000-0000000e0302";
    let body = serde_json::json!({
        "messages": {
            sender.principal_id.as_str(): {
                unknown_device: target(unknown_id, now + chrono::Duration::minutes(10)),
            },
            foreign_principal: {
                foreign_device: target(foreign_id, now + chrono::Duration::minutes(10)),
            },
        },
    });
    let (status, outcome) = send(&sender, "unknown-recipients", &body).await;
    assert_eq!(status, StatusCode::OK, "{outcome}");
    assert_eq!(outcome["delivered"], serde_json::json!({}));
    assert_eq!(
        outcome["unknown_devices"],
        serde_json::json!({
            sender.principal_id.as_str(): {
                unknown_device: {"device_message_id": unknown_id, "status": "unknown"},
            },
            foreign_principal: {
                foreign_device: {"device_message_id": foreign_id, "status": "unknown"},
            },
        })
    );
    assert!(
        queued_device_message_ids(&sender, unknown_device)
            .await
            .is_empty()
    );
}
