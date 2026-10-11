use super::*;

#[handler]
async fn wait_carrier_goal(res: &mut Response) {
    res.status_code(StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn wait_carriers_are_closed_and_duplicates_are_rejected() {
    use salvo::test::{ResponseExt, TestClient};
    let router = || {
        Router::with_path("{**rest}")
            .hoop(wait_for_sync_token)
            .goal(wait_carrier_goal)
    };
    let response = TestClient::get("http://localhost/_arkret/self/account/subscribe")
        .add_header(
            "Arkret-Operation",
            "ak.self.account.stream.subscribe.v1",
            true,
        )
        .add_header("X-Arkret-Wait-For", "ak:cursor:01", true)
        .send(router())
        .await;
    assert_eq!(response.status_code, Some(StatusCode::NO_CONTENT));
    for url in [
        "http://localhost/path?wait_for=ak%3Acursor%3A01",
        "http://localhost/path?consistency.wait_for=ak%3Acursor%3A01",
    ] {
        assert_eq!(
            TestClient::get(url).send(router()).await.status_code,
            Some(StatusCode::BAD_REQUEST)
        );
    }
    let duplicate = TestClient::get("http://localhost/_arkret/self/account/subscribe")
        .add_header(
            "Arkret-Operation",
            "ak.self.account.stream.subscribe.v1",
            true,
        )
        .add_header("X-Arkret-Wait-For", "ak:cursor:01", true)
        .add_header("X-Arkret-Wait-For", "ak:cursor:01", false)
        .send(router())
        .await;
    assert_eq!(duplicate.status_code, Some(StatusCode::BAD_REQUEST));
    let unregistered = TestClient::post("http://localhost/_arkret/self/events")
        .add_header("Arkret-Operation", "ak.self.events.command.submit.v1", true)
        .add_header("X-Arkret-Wait-For", "ak:cursor:01", true)
        .send(router())
        .await;
    assert_eq!(unregistered.status_code, Some(StatusCode::BAD_REQUEST));
    for (method, operation) in [
        ("GET", "ak.self.blob.resource.get.v1"),
        ("HEAD", "ak.self.blob.resource.head.v1"),
    ] {
        let builder = if method == "GET" {
            TestClient::get("http://localhost/_arkret/self/blob/get")
        } else {
            TestClient::head("http://localhost/_arkret/self/blob/get")
        };
        let response = builder
            .add_header("Arkret-Operation", operation, true)
            .add_header("X-Arkret-Wait-For", "ak:cursor:01", true)
            .send(router())
            .await;
        assert_eq!(response.status_code, Some(StatusCode::NO_CONTENT));
    }
    // A caller cannot grant a different binding HTTP wait support merely by
    // declaring a registered Account operation on its request.
    for path in [
        "/_arkret/ws",
        "/_coland/self/strands/unknown",
        "/unregistered",
    ] {
        let response = TestClient::get(format!("http://localhost{path}"))
            .add_header(
                "Arkret-Operation",
                "ak.self.account.stream.subscribe.v1",
                true,
            )
            .add_header("X-Arkret-Wait-For", "ak:cursor:01", true)
            .send(router())
            .await;
        assert_eq!(response.status_code, Some(StatusCode::BAD_REQUEST));
    }
    let wrong_method = TestClient::post("http://localhost/_arkret/self/account/subscribe")
        .add_header(
            "Arkret-Operation",
            "ak.self.account.stream.subscribe.v1",
            true,
        )
        .add_header("X-Arkret-Wait-For", "ak:cursor:01", true)
        .send(router())
        .await;
    assert_eq!(wrong_method.status_code, Some(StatusCode::BAD_REQUEST));
    let mut malformed = TestClient::get("http://localhost/_arkret/self/account/subscribe")
        .add_header(
            "Arkret-Operation",
            "ak.self.account.stream.subscribe.v1",
            true,
        )
        .add_header("X-Arkret-Wait-For", "ak:cursor:01,ak:cursor:02", true)
        .send(router())
        .await;
    assert_eq!(malformed.status_code, Some(StatusCode::BAD_REQUEST));
    let problem: serde_json::Value = malformed.take_json().await.unwrap();
    assert_eq!(problem["reason_code"], "invalid_cursor");
}

#[test]
fn pattern_matches_concrete_path() {
    assert!(pattern_matches_path(
        "/_arkret/self/events",
        "/_arkret/self/events"
    ));
    assert!(!pattern_matches_path(
        "/_arkret/self/events",
        "/_arkret/self/other"
    ));
}

#[test]
fn pattern_matches_param_segment() {
    assert!(pattern_matches_path(
        "/_coland/self/spaces/{space_id}",
        "/_coland/self/spaces/ak:space:01"
    ));
    // Different segment count → no match.
    assert!(!pattern_matches_path(
        "/_coland/self/spaces/{space_id}",
        "/_coland/self/spaces/ak:space:01/policy"
    ));
    // Param must be non-empty.
    assert!(!pattern_matches_path(
        "/_coland/self/spaces/{space_id}",
        "/_coland/self/spaces/"
    ));
}

#[test]
fn pattern_matches_multi_param_segments() {
    assert!(pattern_matches_path(
        "/_arkret/self/events/{event_id}/refs/{ref_id}",
        "/_arkret/self/events/ak:event:01/refs/ak:event:02"
    ));
}

#[test]
fn pattern_rejects_segment_mismatch() {
    assert!(!pattern_matches_path("/_arkret/self/events", "/_arkret"));
    assert!(!pattern_matches_path("/_arkret", "/_arkret/self/events"));
}

#[test]
fn openapi_32_query_method_is_preserved_for_allow_headers() {
    assert_eq!(method_name_to_method("query"), Some(Method::QUERY));
}

#[test]
fn known_routes_map_resolves_known_path() {
    // Seed the known-routes table with the protocol surface we'd
    // expect the catch-all to disambiguate against. We don't go
    // through the full OpenAPI doc build path because that pulls in
    // the entire service router; the helper logic under test is
    // pattern-matching, not OpenAPI introspection.
    let _ = KNOWN_ROUTES.set(vec![
        (
            "/_arkret/self/events".to_owned(),
            vec![Method::GET, Method::POST],
        ),
        (
            "/_coland/self/spaces/{space_id}".to_owned(),
            vec![Method::GET],
        ),
    ]);

    // Known path → returns the canonical method set (in
    // `METHOD_HEADER_ORDER`) so the `Allow` header is stable.
    let methods = allow_methods_for_path("/_arkret/self/events")
        .expect("/_arkret/self/events is registered with at least one method");
    assert_eq!(methods, vec![Method::GET, Method::POST]);

    let methods = allow_methods_for_path("/_coland/self/spaces/ak:space:abc")
        .expect("/_coland/self/spaces/{id} resolves with a concrete id");
    assert_eq!(methods, vec![Method::GET]);

    // Unknown path → `None`, which is the cue for `api_not_found`
    // to emit `unrecognized_endpoint` instead of `method_not_allowed`.
    assert!(allow_methods_for_path("/_arkret/self/does-not-exist").is_none());
    assert!(allow_methods_for_path("/_coland/peer/does-not-exist").is_none());
}
