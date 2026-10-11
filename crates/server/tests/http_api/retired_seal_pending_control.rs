use super::common::*;

#[test]
fn retired_seal_pending_control_and_command_routes_are_not_registered() {
    run_on_test_runtime("retired_seal_control", current_body);
}

async fn current_body() {
    let state = coland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    let app = app_from_state(state);
    let pending = TestClient::query("http://server/_arkret/self/seals/pending-control")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(b"{}".to_vec())
        .send(&app)
        .await;
    assert_eq!(pending.status_code, Some(StatusCode::NOT_FOUND));
    for path in ["seals/prepare", "seals/prepare-fence-result", "seals"] {
        let response = TestClient::post(format!("http://server/_arkret/self/{path}"))
            .add_header("authorization", format!("Bearer {token}"), true)
            .add_header("content-type", "application/json", true)
            .body(b"{}".to_vec())
            .send(&app)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::NOT_FOUND), "{path}");
    }
}
