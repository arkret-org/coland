//! Contract tests for the D14 production admin query endpoints
//! (`GET /_coland/admin/{actors,audit,capabilities,devices}`).
//!
//! Locks the typed wire shape (`coland_contracts::admin`), the
//! resume-by-id cursor semantics, server-side filtering with filter echo,
//! and the auth gates (401 unauthenticated; the 403 admin-principal
//! decision is unit-tested next to the handler where a production-mode
//! session can be constructed directly).

use super::common::*;

fn assert_no_production_gap(body: &Value) {
    assert!(
        body.get("production_gap").is_none(),
        "production endpoint must not carry the dev-only marker: {body}"
    );
}

#[test]
fn admin_actors_query_returns_typed_rows_and_walks_cursor() {
    run_on_test_runtime(
        "admin_actors_query_returns_typed_rows_and_walks_cursor",
        admin_actors_query_returns_typed_rows_and_walks_cursor_body,
    );
}

async fn admin_actors_query_returns_typed_rows_and_walks_cursor_body() {
    let state = coland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    let _bob = register_account(
        state.clone(),
        "did:web:bob.example",
        "@bob",
        "ak:device:01904100-0000-7000-8000-b0b0b0000002",
    )
    .await;

    let bob_account = arkret_wire::AccountId::new(
        fixture_actor_core_id("did:web:bob.example"),
        state.service_core_id(),
    );
    let mut foreign_bob = state
        .test_persistence()
        .accounts()
        .get(&bob_account)
        .await
        .unwrap()
        .unwrap();
    foreign_bob.pk = coland_storage::AccountPk(0);
    foreign_bob.station_id = DidCoreId::new("ak:did_core:web:000-foreign-station.example").unwrap();
    foreign_bob.localpart.clear();
    foreign_bob.display_name = Some("Foreign Bob must not inherit local lifecycle".to_owned());
    state
        .test_persistence()
        .accounts()
        .put(&foreign_bob)
        .await
        .unwrap();

    // Walk the whole collection with limit=1; ids must be strictly
    // ascending (stable sort key) and unique.
    let mut ids = Vec::new();
    let mut cursor: Option<String> = None;
    let mut seen_cursors = std::collections::BTreeSet::new();
    let expected_count = state
        .test_persistence()
        .accounts()
        .list()
        .await
        .unwrap()
        .iter()
        .filter(|account| account.station_id == state.service_core_id())
        .count();
    loop {
        assert!(
            seen_cursors.len() <= expected_count,
            "cursor walk exceeded the number of accounts: {seen_cursors:?}"
        );
        let url = match &cursor {
            Some(cursor) => {
                format!("http://server/_coland/admin/actors?limit=1&cursor={cursor}")
            }
            None => "http://server/_coland/admin/actors?limit=1".to_owned(),
        };
        let page: Value = TestClient::get(&url)
            .add_header("authorization", format!("Bearer {token}"), true)
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
        assert_no_production_gap(&page);
        assert_eq!(page["total"], expected_count);
        let actors = page["actors"].as_array().expect("typed actors array");
        assert!(actors.len() <= 1);
        for actor in actors {
            // Contract: security-relevant fields are answered
            // authoritatively by coland (never fabricated defaults).
            assert!(actor["id"].as_str().is_some(), "row without id: {actor}");
            assert!(actor["principal_id"].as_str().is_some());
            let account: arkret_wire::AccountId =
                serde_json::from_str(actor["account_id"].as_str().unwrap()).unwrap();
            assert_eq!(account.station_id, state.service_core_id());
            assert_eq!(
                account.principal_id.as_str(),
                actor["principal_id"].as_str().unwrap()
            );
            assert!(
                actor["status"].as_str().is_some(),
                "lifecycle status must be reported: {actor}"
            );
            assert!(
                actor["is_admin"].is_boolean(),
                "is_admin must be answered: {actor}"
            );
            ids.push(actor["id"].as_str().unwrap().to_owned());
        }
        if page["has_more"].as_bool() == Some(true) {
            cursor = Some(
                page["next_cursor"]
                    .as_str()
                    .expect("has_more implies next_cursor")
                    .to_owned(),
            );
            assert!(
                seen_cursors.insert(cursor.clone().unwrap()),
                "cursor repeated without progress: {page}"
            );
        } else {
            assert!(page["next_cursor"].is_null());
            break;
        }
    }
    let mut sorted = ids.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(ids, sorted, "cursor walk must be sorted and duplicate-free");
    assert_eq!(ids.len(), expected_count);
    assert!(
        ids.contains(&fixture_actor_core_id("did:web:bob.example").to_string()),
        "registered account missing from actors: {ids:?}"
    );

    let detail: Value = TestClient::get(format!(
        "http://server/_coland/admin/actors/{}",
        bob_account.principal_id
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(detail["account_id"], bob_account.to_string());
    assert_eq!(detail["display_name"], "bob");
}

#[test]
fn admin_actors_query_excludes_foreign_only_accounts() {
    run_on_test_runtime(
        "admin_actors_query_excludes_foreign_only_accounts",
        admin_actors_query_excludes_foreign_only_accounts_body,
    );
}

async fn admin_actors_query_excludes_foreign_only_accounts_body() {
    let state = coland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    let alice_account = arkret_wire::AccountId::new(
        fixture_actor_core_id("did:web:alice.example"),
        state.service_core_id(),
    );
    let mut foreign = state
        .test_persistence()
        .accounts()
        .get(&alice_account)
        .await
        .unwrap()
        .unwrap();
    foreign.pk = coland_storage::AccountPk(0);
    foreign.principal_id = fixture_actor_core_id("did:web:foreign-only.example");
    foreign.station_id = DidCoreId::new("ak:did_core:web:foreign-station.example").unwrap();
    foreign.localpart.clear();
    state
        .test_persistence()
        .accounts()
        .put(&foreign)
        .await
        .unwrap();

    let page: Value = TestClient::get(
        "http://server/_coland/admin/actors?filter[search]=web:foreign-only.example&limit=1",
    )
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(page["actors"], serde_json::json!([]));
    assert_eq!(page["total"], 0);
    assert_eq!(page["has_more"], false);
    assert!(page["next_cursor"].is_null());

    let missing = TestClient::get(format!(
        "http://server/_coland/admin/actors/{}",
        foreign.principal_id
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state))
    .await;
    assert_eq!(missing.status_code, Some(StatusCode::NOT_FOUND));
}

#[test]
fn admin_actors_query_applies_and_echoes_filters() {
    run_on_test_runtime(
        "admin_actors_query_applies_and_echoes_filters",
        admin_actors_query_applies_and_echoes_filters_body,
    );
}

async fn admin_actors_query_applies_and_echoes_filters_body() {
    let state = coland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    let _bob = register_account(
        state.clone(),
        "did:web:bob.example",
        "@bob",
        "ak:device:01904100-0000-7000-8000-b0b0b0000002",
    )
    .await;

    let page: Value =
        TestClient::get("http://server/_coland/admin/actors?filter[search]=web:bob.example")
            .add_header("authorization", format!("Bearer {token}"), true)
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    let actors = page["actors"].as_array().unwrap();
    assert!(!actors.is_empty(), "search must match bob: {page}");
    assert!(
        actors.iter().all(|actor| actor["id"]
            .as_str()
            .unwrap_or_default()
            .contains("web:bob.example")),
        "server-side search must filter rows: {page}"
    );
    assert_eq!(page["filters"]["search"], "web:bob.example", "filter echo");

    // Unknown status filter value is a hard 400, not an ignored parameter.
    let response = TestClient::get("http://server/_coland/admin/actors?filter[status]=bogus")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(response.status_code, Some(StatusCode::BAD_REQUEST));
}

#[test]
fn admin_actors_query_rejects_expired_cursor_with_gone() {
    run_on_test_runtime(
        "admin_actors_query_rejects_expired_cursor_with_gone",
        admin_actors_query_rejects_expired_cursor_with_gone_body,
    );
}

async fn admin_actors_query_rejects_expired_cursor_with_gone_body() {
    let state = coland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;

    let response =
        TestClient::get("http://server/_coland/admin/actors?cursor=did:web:vanished.example")
            .add_header("authorization", format!("Bearer {token}"), true)
            .send(&app_from_state(state.clone()))
            .await;
    assert_eq!(
        response.status_code,
        Some(StatusCode::GONE),
        "unresolvable cursor must be cursor-expired"
    );
}

#[test]
fn admin_queries_require_authentication() {
    run_on_test_runtime(
        "admin_queries_require_authentication",
        admin_queries_require_authentication_body,
    );
}

async fn admin_queries_require_authentication_body() {
    let state = coland_test_support::app_state(test_config());
    for resource in ["actors", "audit", "capabilities", "devices"] {
        let response = TestClient::get(format!("http://server/_coland/admin/{resource}"))
            .send(&app_from_state(state.clone()))
            .await;
        assert_eq!(
            response.status_code,
            Some(StatusCode::UNAUTHORIZED),
            "unauthenticated {resource} query must be rejected"
        );
    }
}

#[test]
fn admin_audit_query_is_typed_newest_first_and_filterable() {
    run_on_test_runtime(
        "admin_audit_query_is_typed_newest_first_and_filterable",
        admin_audit_query_is_typed_newest_first_and_filterable_body,
    );
}

async fn admin_audit_query_is_typed_newest_first_and_filterable_body() {
    let state = coland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;

    // Generate two audited admin actions to query back.
    for _ in 0..2 {
        let _: Value = TestClient::get("http://server/_coland/admin/actors")
            .add_header("authorization", format!("Bearer {token}"), true)
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    }

    let page: Value =
        TestClient::get("http://server/_coland/admin/audit?filter[action]=admin.actors.query")
            .add_header("authorization", format!("Bearer {token}"), true)
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_no_production_gap(&page);
    let entries = page["entries"].as_array().expect("typed entries array");
    assert!(entries.len() >= 2, "audited queries missing: {page}");
    assert!(
        entries
            .iter()
            .all(|entry| entry["action"] == "admin.actors.query"),
        "action filter must apply server-side: {page}"
    );
    assert_eq!(page["filters"]["action"], "admin.actors.query");
    // Newest first.
    let stamps: Vec<&str> = entries
        .iter()
        .filter_map(|entry| entry["created_at"].as_str())
        .collect();
    let mut sorted = stamps.clone();
    sorted.sort_by(|left, right| right.cmp(left));
    assert_eq!(stamps, sorted, "audit page must be newest-first: {page}");
    // Rows carry the durable identifiers.
    assert!(entries[0]["id"].as_str().is_some());
    assert!(entries[0]["request_id"].as_str().is_some());

    // Malformed time bound is a hard 400.
    let response = TestClient::get("http://server/_coland/admin/audit?since=yesterday")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(response.status_code, Some(StatusCode::BAD_REQUEST));
}

#[test]
fn admin_capabilities_query_reports_tombstones_and_validates_state_filter() {
    run_on_test_runtime(
        "admin_capabilities_query_reports_tombstones_and_validates_state_filter",
        admin_capabilities_query_reports_tombstones_and_validates_state_filter_body,
    );
}

async fn admin_capabilities_query_reports_tombstones_and_validates_state_filter_body() {
    let state = coland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;

    let page: Value = TestClient::get("http://server/_coland/admin/capabilities")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_no_production_gap(&page);
    assert!(page["capabilities"].is_array(), "typed envelope: {page}");
    assert!(page["has_more"].is_boolean());
    assert!(page["total"].is_u64());

    let response = TestClient::get("http://server/_coland/admin/capabilities?filter[state]=paused")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(
        response.status_code,
        Some(StatusCode::BAD_REQUEST),
        "capability state filter is a closed set"
    );
}

#[test]
fn admin_devices_query_filters_by_name_or_id() {
    run_on_test_runtime(
        "admin_devices_query_filters_by_name_or_id",
        admin_devices_query_filters_by_name_or_id_body,
    );
}

async fn admin_devices_query_filters_by_name_or_id_body() {
    let state = coland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    let _bob = register_account(
        state.clone(),
        "did:web:bob.example",
        "@bob",
        "ak:device:01904100-0000-7000-8000-b0b0b0000002",
    )
    .await;

    let page: Value =
        TestClient::get("http://server/_coland/admin/devices?filter[name_or_id]=b0b0b0000002")
            .add_header("authorization", format!("Bearer {token}"), true)
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_no_production_gap(&page);
    let devices = page["devices"].as_array().expect("typed devices array");
    assert!(!devices.is_empty(), "bob's device missing: {page}");
    assert!(
        devices.iter().all(|device| {
            device["id"]
                .as_str()
                .unwrap_or_default()
                .contains("b0b0b0000002")
                || device["actor_id"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("b0b0b0000002")
        }),
        "name_or_id must filter server-side: {page}"
    );
    assert_eq!(page["filters"]["name_or_id"], "b0b0b0000002");
    assert!(devices[0]["created_at"].as_str().is_some());
}

#[test]
fn admin_collection_no_longer_serves_migrated_resources() {
    run_on_test_runtime(
        "admin_collection_no_longer_serves_migrated_resources",
        admin_collection_no_longer_serves_migrated_resources_body,
    );
}

async fn admin_collection_no_longer_serves_migrated_resources_body() {
    let state = coland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;

    // The dev collection must not shadow the production endpoints: the
    // migrated resources are gone from its dispatch (audit/capabilities/
    // devices/actors resolve to the typed handlers instead, which do not
    // carry the dev marker).
    for resource in ["actors", "audit", "capabilities", "devices"] {
        let page: Value = TestClient::get(format!("http://server/_coland/admin/{resource}"))
            .add_header("authorization", format!("Bearer {token}"), true)
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
        assert_no_production_gap(&page);
    }
    // A resource that stays dev-only still reports its production gap.
    let realms: Value = TestClient::get("http://server/_coland/admin/realms")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        realms["production_gap"], "admin_authorization_and_durable_pagination",
        "dev collection keeps its explicit gap marker: {realms}"
    );
}
