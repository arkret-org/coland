use super::common::*;

#[test]
fn retired_seal_mls_read_routes_are_not_registered() {
    run_on_test_runtime("retired_seal_mls_reads", current_body);
}

async fn current_body() {
    let state = coland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    for path in ["mls-accepted-artifact", "mls-welcome-refs"] {
        let response = TestClient::post(format!("http://server/_arkret/self/seals/{path}"))
            .add_header("authorization", format!("Bearer {token}"), true)
            .add_header("content-type", "application/json", true)
            .body(b"{}".to_vec())
            .send(&app_from_state(state.clone()))
            .await;
        assert_eq!(response.status_code, Some(StatusCode::NOT_FOUND), "{path}");
    }
    for path in [
        "/_arkret/self/seals/mls-governance-proof",
        "/_arkret/peer/seals/mls-governance-proof",
    ] {
        let response = TestClient::post(format!("http://server{path}"))
            .add_header("authorization", format!("Bearer {token}"), true)
            .add_header("content-type", "application/json", true)
            .body(b"{}".to_vec())
            .send(&app_from_state(state.clone()))
            .await;
        assert_eq!(response.status_code, Some(StatusCode::NOT_FOUND), "{path}");
    }
}
