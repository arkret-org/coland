//! Development harness route registration.

#![cfg(feature = "conformance-harness")]

use coland_http::config::AppConfig;
use coland_http::service;
use salvo::http::StatusCode;
use salvo::test::{ResponseExt, TestClient};
use serde_json::{Value, json};

#[tokio::test]
async fn development_harness_mounts_the_encode_route() {
    let app = service(coland_test_support::app_state(AppConfig {
        development_mode: true,
        ..coland_test_support::app_config()
    }));
    let mut response = TestClient::post("http://server/_arkret/_conformance/encode")
        .json(&json!({"vector_id": "canonical_object", "input": {"b": 2, "a": 1}}))
        .send(&app)
        .await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    let outcome: Value = response.take_json().await.unwrap();
    assert_eq!(outcome["canonical_json"], r#"{"a":1,"b":2}"#);
}
