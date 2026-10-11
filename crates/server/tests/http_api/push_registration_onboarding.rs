//! Integration tests — Station push registration against a Gateway URL the
//! deployment has not onboarded (`push-notifications.md` §3.1–§3.3).
//!
//! A bare `push_gateway_url` never establishes trust: the Station fails closed
//! with the operation's registered `push_gateway_unreachable`, installs no
//! route or handoff intent, and unregistration of the same device stays the
//! idempotent 204.

use coland_test_support::pcr_genesis::PcrGenesisFixture;

use super::common::*;

#[test]
fn register_with_not_onboarded_gateway_fails_closed_without_writes() {
    run_on_test_runtime(
        "register_with_not_onboarded_gateway_fails_closed_without_writes",
        register_with_not_onboarded_gateway_fails_closed_without_writes_body,
    );
}

async fn register_with_not_onboarded_gateway_fails_closed_without_writes_body() {
    let state = coland_test_support::app_state(test_config());
    let fixture = PcrGenesisFixture::new(state.service_did());
    fixture.admit(&state).await.expect("accepted PCR genesis");
    let device_id = fixture.history.founding_device_id.clone();
    let token = dev_token_for_device(
        state.clone(),
        fixture.history.did.as_str(),
        device_id.as_str(),
        "PCR device",
    )
    .await;
    let service = app_from_state(state.clone());

    for attempt in ["first", "retry"] {
        let mut response = TestClient::post("http://server/_arkret/edge/push/register-device")
            .add_header("authorization", format!("Bearer {token}"), true)
            .json(&serde_json::json!({
                "device_id": device_id,
                "push_gateway_url": "https://push.example",
                "push_key": "opaque-provider-token",
                "platform": "desktop",
                "app_id": "inkson",
            }))
            .send(&service)
            .await;
        let status = response.status_code;
        let body: Value = response.take_json().await.expect("problem JSON");
        assert_eq!(
            status,
            Some(StatusCode::SERVICE_UNAVAILABLE),
            "{attempt} registration: {body}"
        );
        assert_eq!(problem_code(&body), "push_gateway_unreachable", "{body}");
        assert!(
            !body.to_string().contains("opaque-provider-token"),
            "a refused registration must not echo the provider route: {body}"
        );
    }

    assert!(
        state
            .test_persistence()
            .push_devices()
            .snapshot_all()
            .await
            .unwrap()
            .is_empty(),
        "a non-onboarded Gateway must not install a local route"
    );

    for attempt in ["first", "repeated"] {
        let unregistered = TestClient::post("http://server/_arkret/edge/push/unregister-device")
            .add_header("authorization", format!("Bearer {token}"), true)
            .json(&serde_json::json!({
                "device_id": device_id,
                "app_id": "inkson",
            }))
            .send(&service)
            .await;
        assert_eq!(
            unregistered.status_code,
            Some(StatusCode::NO_CONTENT),
            "{attempt} unregistration of a never-installed route is idempotent"
        );
    }
}
