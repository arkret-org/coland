use super::common::*;

#[test]
fn retired_self_frontier_routes_are_not_mounted() {
    run_on_test_runtime(
        "retired_self_frontier_routes_are_not_mounted",
        retired_self_frontier_routes_are_not_mounted_body,
    );
}

async fn retired_self_frontier_routes_are_not_mounted_body() {
    let state = coland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    for (path, body) in [
        (
            "http://server/_arkret/self/seals/frontier",
            serde_json::json!({"realm_id": demo_realm_id()}),
        ),
        (
            "http://server/_arkret/self/events/frontier",
            serde_json::json!({"actor_id": fixture_account_actor(&state, "did:web:alice.example")}),
        ),
    ] {
        let response = TestClient::query(path)
            .json(&body)
            .add_header("authorization", format!("Bearer {token}"), true)
            .send(&app_from_state(state.clone()))
            .await;
        assert_eq!(response.status_code, Some(StatusCode::NOT_FOUND), "{path}");
    }
}
