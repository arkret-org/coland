//! Actual native member material, signed roster and final publication cuts.
use arkret_models_collaboration::mls_group_state_material::{
    MlsGroupStateMaterialOutcome, MlsMemberGroupStateMaterialReadRequestBody,
};
use arkret_models_collaboration::mls_roster_authority::{
    MlsMemberRosterAuthorityReadRequestBody, MlsSelfRosterAuthorityReadOutcome,
};

use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bot_and_ghost_read_real_mls_material_and_signed_roster_without_session() {
    for ghost in [false, true] {
        for circle in [false, true] {
            tokio::spawn(native_phase(|| {
                originate(ghost, Case::MaterialReads, circle)
            }))
            .await
            .unwrap();
        }
    }
}

async fn read(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    scope: &ScopeRef,
    operation: ServiceOperationId,
    body: &Value,
) -> salvo::Response {
    read_in_state(&fixture.state, authority, key, scope, operation, body).await
}

async fn read_in_state(
    state: &AppState,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    scope: &ScopeRef,
    operation: ServiceOperationId,
    body: &Value,
) -> salvo::Response {
    let mut metadata = managed_device_metadata(authority);
    metadata.effective_scope = scope.clone();
    managed_device_http_request_body(
        state,
        authority,
        &metadata,
        operation,
        key,
        Some(arkret_canonical::canonical_json_bytes(body).unwrap()),
    )
    .add_header("content-type", "application/json", true)
    .send(&service(state.clone()))
    .await
}

async fn refused(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    scope: &ScopeRef,
    operation: ServiceOperationId,
    body: &Value,
) {
    let before = native_phase(|| business(fixture)).await;
    let mut response = native_phase(|| read(fixture, authority, key, scope, operation, body)).await;
    assert!(
        !response.status_code.unwrap().is_success(),
        "invalid material selector accepted: {body}"
    );
    let problem: Value = response.take_json().await.unwrap();
    assert!(problem.get("group_info_bytes_b64").is_none());
    assert!(problem.get("roster").is_none());
    assert_eq!(before, native_phase(|| business(fixture)).await);
}

pub(super) async fn exercise(
    fixture: &Fixture,
    install: &Installed,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    scope: &ScopeRef,
    genesis: &Event,
) {
    let payload: MlsGenesisPayload = serde_json::from_value(json!(genesis.payload)).unwrap();
    let material = MlsMemberGroupStateMaterialReadRequestBody {
        realm_id: fixture.realm.clone(),
        effective_scope: scope.clone(),
        mls_group_id: scope.canonical_mls_group_id().unwrap(),
        epoch: Default::default(),
        group_state_event_id: genesis.event_id.clone(),
        caller_actor_id: ActorId::account(authority.account_id.clone()),
        target_commit_event_ref: genesis.event_id.clone(),
        target_epoch: 0,
        group_info_ref: payload.group_info_ref,
        ratchet_tree_ref: payload.ratchet_tree_ref,
        max_response_bytes: None,
    };
    material.validate().unwrap();
    let roster = MlsMemberRosterAuthorityReadRequestBody {
        realm_id: material.realm_id.clone(),
        effective_scope: scope.clone(),
        mls_group_id: material.mls_group_id.clone(),
        target_commit_event_ref: genesis.event_id.clone(),
        target_epoch: 0,
        caller_actor_id: material.caller_actor_id.clone(),
        cursor: None,
    };
    roster.validate().unwrap();
    let selectors = [
        (
            ServiceOperationId::SelfMlsReadGroupStateMaterialV1,
            json!(material),
        ),
        (
            ServiceOperationId::SelfMlsReadRosterAuthorityV1,
            json!(roster),
        ),
    ];
    // Membership and MLS writer grants cannot replace the independent read source.
    for (operation, body) in &selectors {
        native_phase(|| refused(fixture, authority, key, scope, *operation, body)).await;
    }
    let parent = native_phase(|| {
        native_business_parent_in_scope(
            fixture,
            install,
            vec![],
            vec!["ak.event.read".to_owned()],
            None,
            scope.clone(),
        )
    })
    .await;
    let before = native_phase(|| business(fixture)).await;
    let mut response = native_phase(|| {
        read(
            fixture,
            authority,
            key,
            scope,
            selectors[0].0,
            &selectors[0].1,
        )
    })
    .await;
    let status = response.status_code;
    let value: Value = response.take_json().await.unwrap();
    assert_eq!(
        status,
        Some(StatusCode::OK),
        "real native public material: {value}"
    );
    let outcome: MlsGroupStateMaterialOutcome = serde_json::from_value(value).unwrap();
    let bytes = outcome
        .validate_for_request(&material.as_peer_request())
        .unwrap();
    arkret_mls::validate_public_group_state(
        &bytes.group_info_bytes,
        &bytes.ratchet_tree_bytes,
        material.mls_group_id.as_str(),
        0,
    )
    .unwrap();
    let mut response = native_phase(|| {
        read(
            fixture,
            authority,
            key,
            scope,
            selectors[1].0,
            &selectors[1].1,
        )
    })
    .await;
    let status = response.status_code;
    let value: Value = response.take_json().await.unwrap();
    assert_eq!(
        status,
        Some(StatusCode::OK),
        "real native signed roster: {value}"
    );
    let page: MlsSelfRosterAuthorityReadOutcome = serde_json::from_value(value).unwrap();
    assert_eq!(page.roster.records.len(), 1);
    let head = page.roster.manifest.authority_head_commit_event_ref.clone();
    arkret::verify_mls_self_roster_authority_pages(
        &[page],
        &roster.with_accepted_genesis(genesis.event_id.clone()),
        &fixture.state.service_core_id(),
        &head,
    )
    .unwrap();
    // A fresh worker must derive Device and Service authority from accepted
    // storage. Only the test's memory object backend needs its original public
    // bytes copied; no accepted Event, member or authority row is seeded.
    let reopened = native_phase(|| {
        coland_test_support::app_state_with_persistence(
            fixture.state.config().clone(),
            std::sync::Arc::new(coland_storage_postgres::PgPersistenceStore::new(
                fixture.pool.clone(),
            )),
        )
    })
    .await;
    native_phase(|| reopened.hydrate()).await.unwrap();
    for (reference, public_bytes) in [
        (&material.group_info_ref, &bytes.group_info_bytes),
        (&material.ratchet_tree_ref, &bytes.ratchet_tree_bytes),
    ] {
        let digest = reference.as_str().strip_prefix("ak:blob:sha256:").unwrap();
        let storage_key = reopened.test_object_key_for_sha256(digest);
        reopened
            .test_put_object(&storage_key, public_bytes.clone())
            .await
            .unwrap();
    }
    for (operation, body) in &selectors {
        let mut response =
            native_phase(|| read_in_state(&reopened, authority, key, scope, *operation, body))
                .await;
        let status = response.status_code;
        let value: Value = response.take_json().await.unwrap();
        assert_eq!(
            status,
            Some(StatusCode::OK),
            "cold native MLS read: {value}"
        );
        if *operation == ServiceOperationId::SelfMlsReadGroupStateMaterialV1 {
            let restored: MlsGroupStateMaterialOutcome = serde_json::from_value(value).unwrap();
            assert_eq!(restored, outcome);
            restored
                .validate_for_request(&material.as_peer_request())
                .unwrap();
        } else {
            let restored: MlsSelfRosterAuthorityReadOutcome =
                serde_json::from_value(value).unwrap();
            arkret::verify_mls_self_roster_authority_pages(
                &[restored],
                &roster.with_accepted_genesis(genesis.event_id.clone()),
                &reopened.service_core_id(),
                &head,
            )
            .unwrap();
        }
    }
    assert_eq!(before, native_phase(|| business(fixture)).await);
    for (operation, body) in &selectors {
        for field in [
            "caller_actor_id",
            "target_epoch",
            "mls_group_id",
            "unknown_selector",
        ] {
            let mut invalid = body.clone();
            invalid[field] = match field {
                "caller_actor_id" => json!(ActorId::account(fixture.pcr.history.account.clone())),
                "target_epoch" => json!(1),
                "mls_group_id" => json!(
                    ScopeRef::Realm {
                        realm_id: authority.pcr_realm_id.clone()
                    }
                    .canonical_mls_group_id()
                    .unwrap()
                ),
                _ => json!(true),
            };
            native_phase(|| refused(fixture, authority, key, scope, *operation, &invalid)).await;
        }
        if matches!(scope, ScopeRef::Circle { .. }) {
            let realm = ScopeRef::Realm {
                realm_id: fixture.realm.clone(),
            };
            let mut invalid = body.clone();
            invalid["effective_scope"] = json!(realm);
            native_phase(|| refused(fixture, authority, key, &realm, *operation, &invalid)).await;
        }
    }
    let mut invalid = selectors[0].1.clone();
    invalid["group_info_ref"] = invalid["ratchet_tree_ref"].clone();
    native_phase(|| refused(fixture, authority, key, scope, selectors[0].0, &invalid)).await;
    native_phase(|| native_current_revoke(fixture, &parent)).await;
    for (operation, body) in &selectors {
        native_phase(|| refused(fixture, authority, key, scope, *operation, body)).await;
    }
    // A prepared response holds the PCR cut through publication. Exercise
    // each deadline separately: a second nonce writer must not be awaited
    // while the first response still owns that same PCR read lock.
    use arkret_models_collaboration::governance::grant_constraint::{
        GrantConstraintEffect, GrantConstraintKind,
    };
    for (operation, body) in &selectors {
        let deadline = arkret_canonical::normalize_timestamp_canonical(
            chrono::Utc::now() + chrono::Duration::seconds(15),
        );
        let mut temporal =
            GrantConstraint::new(GrantConstraintKind::Temporal, GrantConstraintEffect::Allow);
        temporal.expires_at = Some(deadline);
        let _finite = native_phase(|| {
            native_business_parent_in_scope(
                fixture,
                install,
                vec![temporal],
                vec!["ak.event.read".to_owned()],
                None,
                scope.clone(),
            )
        })
        .await;
        let mut response =
            native_phase(|| read(fixture, authority, key, scope, *operation, body)).await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        let before = native_phase(|| business(fixture)).await;
        tokio::time::sleep(
            (deadline - chrono::Utc::now()).to_std().unwrap_or_default()
                + std::time::Duration::from_millis(100),
        )
        .await;
        assert!(
            response.take_json::<Value>().await.is_err(),
            "expired Service read source published prepared native MLS bytes"
        );
        assert_eq!(before, native_phase(|| business(fixture)).await);
        native_phase(|| refused(fixture, authority, key, scope, *operation, body)).await;
    }
}
