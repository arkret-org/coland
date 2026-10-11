//! Accepted-state fixtures use the formal self authority bootstrap operation.
//! Retired Seal and synthetic MLS injection routes never construct acceptance.
//! Known-route metadata is initialized once per process, so the surviving
//! harness positive control uses only the first development configuration.

#![cfg(feature = "conformance-harness")]

use coland_http::config::AppConfig;
use coland_http::service;
use salvo::http::StatusCode;
use salvo::test::{ResponseExt, TestClient};
use serde_json::Value;

#[tokio::test]
async fn retired_injection_routes_are_unknown_even_with_the_development_harness() {
    for development_mode in [true, false] {
        let app = service(coland_test_support::app_state(AppConfig {
            development_mode,
            ..coland_test_support::app_config()
        }));
        for path in ["realm-basis", "signal-mls-basis", "realm-fixture/install"] {
            let mut response =
                TestClient::post(format!("http://server/_arkret/_conformance/{path}"))
                    .send(&app)
                    .await;
            assert_eq!(response.status_code, Some(StatusCode::NOT_FOUND), "{path}");
            let problem: Value = response.take_json().await.unwrap();
            assert_eq!(
                problem["type"],
                "https://arkret.org/problems/unrecognized_endpoint"
            );
        }
        if development_mode {
            // A missing required body reaches extraction, proving the
            // remaining development harness was mounted for this fixture.
            let response = TestClient::post("http://server/_arkret/_conformance/encode")
                .send(&app)
                .await;
            assert_ne!(response.status_code, Some(StatusCode::NOT_FOUND));
        }
    }
}
