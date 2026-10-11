//! Integration tests for codmin-driven admin B-track endpoints.

use coland_storage::BlobRecord;

use super::common::*;

#[test]
fn admin_actor_detail_includes_account_lifecycle_linkage() {
    run_on_test_runtime(
        "admin_actor_detail_includes_account_lifecycle_linkage",
        admin_actor_detail_includes_account_lifecycle_linkage_body,
    );
}

async fn admin_actor_detail_includes_account_lifecycle_linkage_body() {
    let state = coland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;

    let alice = fixture_actor_core_id("did:web:alice.example");
    let expected_account =
        arkret_wire::AccountId::new(alice.clone(), state.service_core_id().clone());
    let actor: Value = TestClient::get(format!(
        "http://server/_coland/admin/actors/{}",
        alice.as_str()
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state))
    .await
    .take_json()
    .await
    .unwrap();

    // D14 — detail row is the typed production `AdminActor` projection.
    assert_eq!(actor["id"], alice.as_str());
    assert_eq!(actor["principal_id"], alice.as_str());
    assert_eq!(
        serde_json::from_str::<arkret_wire::AccountId>(
            actor["account_id"]
                .as_str()
                .expect("admin account identity string")
        )
        .expect("admin account identity contains the complete canonical AccountId"),
        expected_account,
        "actor row must preserve the exact local AccountId: {actor}"
    );
    assert!(
        actor["status"].as_str().is_some(),
        "lifecycle status must be answered authoritatively: {actor}"
    );
    assert!(
        actor["is_admin"].is_boolean(),
        "is_admin must be answered authoritatively: {actor}"
    );
}

#[test]
fn admin_account_status_aliases_keep_protocol_state_closed() {
    run_on_test_runtime(
        "admin_account_status_aliases_keep_protocol_state_closed",
        admin_account_status_aliases_keep_protocol_state_closed_body,
    );
}

async fn admin_account_status_aliases_keep_protocol_state_closed_body() {
    let state = coland_test_support::app_state(test_config());
    let admin = dev_token(state.clone()).await;
    let _bob = register_account(
        state.clone(),
        "did:web:bob.example",
        "@bob",
        "ak:device:01904100-0000-7000-8000-b0b0b0000002",
    )
    .await;
    let bob = fixture_actor_core_id("did:web:bob.example");

    let recovery_locked: Value = TestClient::post(format!(
        "http://server/_coland/admin/accounts/{}/status",
        bob.as_str()
    ))
    .add_header("authorization", format!("Bearer {admin}"), true)
    .json(&serde_json::json!({"status": "recovery_locked"}))
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();

    assert_eq!(recovery_locked["state"], "locked");
    assert_eq!(recovery_locked["protocol_state"], "locked");
    assert_eq!(recovery_locked["status"], "recovery_locked");
    assert_eq!(recovery_locked["management_status"], "recovery_locked");
    assert_eq!(recovery_locked["reason"], "recovery_locked");
    assert_eq!(state.account_lifecycle_state(bob.as_str()), "locked");

    let _carol = register_account(
        state.clone(),
        "did:web:carol.example",
        "@carol",
        "ak:device:01904100-0000-7000-8000-ca2010000003",
    )
    .await;
    let carol = fixture_actor_core_id("did:web:carol.example");
    let disabled: Value = TestClient::post(format!(
        "http://server/_coland/admin/accounts/{}/status",
        carol.as_str()
    ))
    .add_header("authorization", format!("Bearer {admin}"), true)
    .json(&serde_json::json!({"status": "disabled"}))
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();

    assert_eq!(disabled["state"], "deactivated");
    assert_eq!(disabled["protocol_state"], "deactivated");
    assert_eq!(disabled["status"], "disabled");
    assert_eq!(disabled["management_status"], "disabled");
    assert_eq!(disabled["reason"], "disabled");
    assert_eq!(state.account_lifecycle_state(carol.as_str()), "deactivated");

    let pending = TestClient::post(format!(
        "http://server/_coland/admin/accounts/{}/status",
        bob.as_str()
    ))
    .add_header("authorization", format!("Bearer {admin}"), true)
    .json(&serde_json::json!({"status": "pending_deletion"}))
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(pending.status_code.unwrap().as_u16(), 400);
}

#[test]
fn admin_media_statistics_and_by_actor_are_derived_from_blobs() {
    run_on_test_runtime(
        "admin_media_statistics_and_by_actor_are_derived_from_blobs",
        admin_media_statistics_and_by_actor_are_derived_from_blobs_body,
    );
}

async fn admin_media_statistics_and_by_actor_are_derived_from_blobs_body() {
    let state = coland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    let now = chrono::Utc::now();
    state
        .test_persistence()
        .blobs()
        .put(
            "ak:blob:test-1",
            &BlobRecord {
                sha256: "sha256-1".to_owned(),
                size_bytes: 128,
                storage_backend: "memory".to_owned(),
                storage_key: "test-1".to_owned(),
                media_type: "image/png".to_owned(),
                filename: Some("one.png".to_owned()),
                realm_id: Some(demo_realm_id().to_owned()),
                encryption: None,
                legal_hold: false,
                redacted: false,
                visibility: arkret_models_collaboration::objects::blob::BlobVisibility::RealmBound,
                uploaded_by: "ak:did_core:web:alice.example".to_owned(),
                created_at: now,
            },
        )
        .await
        .unwrap();
    state
        .test_persistence()
        .blobs()
        .put(
            "ak:blob:test-2",
            &BlobRecord {
                sha256: "sha256-2".to_owned(),
                size_bytes: 64,
                storage_backend: "memory".to_owned(),
                storage_key: "test-2".to_owned(),
                media_type: "application/octet-stream".to_owned(),
                filename: Some("two.txt".to_owned()),
                realm_id: Some(demo_realm_id().to_owned()),
                encryption: Some(arkret_models_collaboration::objects::blob::BlobStorageEncryption {
                    scheme: arkret_models_collaboration::objects::blob::BlobStorageEncryptionScheme::WholeFileV1,
                }),
                legal_hold: false,
                redacted: false,
                visibility: arkret_models_collaboration::objects::blob::BlobVisibility::RealmBound,
                uploaded_by: "ak:did_core:web:alice.example".to_owned(),
                created_at: now,
            },
        )
        .await
        .unwrap();

    let stats: Value = TestClient::get("http://server/_coland/admin/media/statistics")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(stats["total_blobs"], 2);
    assert_eq!(stats["total_size"], 192);
    assert_eq!(stats["encrypted_count"], 1);
    assert_eq!(stats["by_media_type"]["image/png"]["count"], 1);
    assert_eq!(stats["by_realm"][demo_realm_id()]["total_size"], 192);

    let by_actor: Value = TestClient::get("http://server/_coland/admin/media/by-actor")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    let row = by_actor["data"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["actor_id"] == "ak:did_core:web:alice.example")
        .expect("alice media row");
    assert_eq!(row["blob_count"], 2);
    assert_eq!(row["total_size"], 192);
}
