use super::common::*;

#[test]
fn retired_seal_history_authority_route_is_not_registered() {
    run_on_test_runtime("retired_seal_history_authority", current_body);
}

async fn current_body() {
    let state = coland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    let response = TestClient::post("http://server/_arkret/self/seals/history-authority")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(b"{}".to_vec())
        .send(&app_from_state(state))
        .await;
    assert_eq!(response.status_code, Some(StatusCode::NOT_FOUND));
}
