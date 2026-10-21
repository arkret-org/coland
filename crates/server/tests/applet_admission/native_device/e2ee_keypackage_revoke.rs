//! Native own-package cleanup never manufactures an Account session.
use diesel_async::RunQueryDsl;

use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_device_revokes_its_scope_bound_keypackage_without_session() {
    for ghost in [false, true] {
        tokio::spawn(native_phase(|| exercise(ghost)))
            .await
            .unwrap();
    }
}

async fn exercise(ghost: bool) {
    let fixture = native_phase(Fixture::new).await;
    let scope = ScopeRef::Realm {
        realm_id: fixture.realm.clone(),
    };
    let namespace = format!("bridge.{}", uuid::Uuid::now_v7().simple());
    let native = mls_service(&fixture, &namespace);
    let install =
        native_phase(|| fixture.install_package(true, native.package.clone(), &namespace)).await;
    let bundle = if ghost {
        let body = native_phase(|| fixture.ghost_body(&install, &namespace, "revoke-device")).await;
        assert_eq!(
            native_phase(|| fixture.ghost_commit(&install, &body, "revoke-device"))
                .await
                .0,
            StatusCode::OK
        );
        body["event"].clone()
    } else {
        install.bot_body["event"].clone()
    };
    let key = SigningKey::from_bytes(&[173; 32]);
    let device = DeviceId::new(format!("ak:device:{}", uuid::Uuid::now_v7())).unwrap();
    let authority = native_phase(|| {
        authorize(
            &fixture,
            &install,
            &bundle,
            &namespace,
            &key,
            device.clone(),
            true,
        )
    })
    .await;
    let join = join_event(&fixture, &install, &authority, &key, &install.join_grant());
    let (status, outcome) = native_phase(|| post(&fixture, &authority, &key, &join, vec![])).await;
    assert_eq!(status, StatusCode::OK, "real Device membership: {outcome}");
    let identity = arkret_mls::ArkretMlsIdentity::new_realm_device(
        authority.actor_id.clone(),
        device,
        arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(key.clone()),
    )
    .unwrap();
    let fingerprint =
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(key.verifying_key().as_bytes());
    let method = format!("did:key:{fingerprint}#{fingerprint}");
    let old =
        native_phase(|| publish(&fixture, &authority, &key, &identity, &method, &scope)).await;
    // A real replacement adds an independently installed Circle, retaining
    // one exact original authorization for all subsequently published rows.
    let authority = native_phase(|| {
        circle_membership(
            &fixture, &install, &namespace, &bundle, &authority, &key, false,
        )
    })
    .await;
    let circle = authority
        .scopes
        .entries()
        .iter()
        .find(|e| matches!(e.effective_scope, ScopeRef::Circle { .. }))
        .unwrap()
        .effective_scope
        .clone();
    let first =
        native_phase(|| publish(&fixture, &authority, &key, &identity, &method, &scope)).await;
    let second =
        native_phase(|| publish(&fixture, &authority, &key, &identity, &method, &scope)).await;
    let other_scope =
        native_phase(|| publish(&fixture, &authority, &key, &identity, &method, &circle)).await;
    let body = request(
        &authority,
        &key,
        &method,
        vec![first.clone(), second.clone()],
    );
    native_phase(|| {
        negative_guards(
            &fixture,
            &authority,
            &key,
            &method,
            &scope,
            &circle,
            &first,
            &other_scope,
            &body,
        )
    })
    .await;
    let stale = request(&authority, &key, &method, vec![old]);
    let before = native_phase(|| snapshot(&fixture)).await;
    let (status, outcome) =
        native_phase(|| revoke(&fixture, &authority, &key, &scope, &stale)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "opaque old-authorization outcome: {outcome}"
    );
    assert!(outcome["revoked"].as_array().unwrap().is_empty());
    assert_eq!(outcome["failures"][0]["reason_code"], "keypackage_unknown");
    assert_eq!(before, native_phase(|| snapshot(&fixture)).await);
    native_phase(|| rollback(&fixture, &authority, &key, &scope, &body)).await;
    native_phase(|| fixture.revoke(&install)).await;
    let fresh = fresh_upload(&identity, &method, &key, &scope);
    let before = native_phase(|| snapshot(&fixture)).await;
    let (status, error) =
        native_phase(|| upload_in_scope(&fixture, &authority, &key, &fresh, &scope)).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "new material after accepted fence: {error}"
    );
    assert_eq!(before, native_phase(|| snapshot(&fixture)).await);
    let (status, outcome) =
        native_phase(|| revoke(&fixture, &authority, &key, &scope, &body)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "real native cleanup after installation fence: {outcome}"
    );
    let typed: arkret_models_crypto::KeyPackagesRevokeOutcome =
        serde_json::from_value(outcome).unwrap();
    assert_eq!(typed.revoked, body.key_package_refs);
    assert!(typed.failures.is_empty());
    for reference in &body.key_package_refs {
        let row = fixture
            .state
            .test_persistence()
            .mls_key_packages()
            .get_by_ref(reference)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.claimed_by_mls_group_id.as_deref(), Some("revoked"));
        assert_eq!(
            row.device_authorize_event_id.as_deref(),
            Some(authority.authorization_ref.event_id.as_str())
        );
    }
    let before = native_phase(|| snapshot(&fixture)).await;
    let (status, replay) = native_phase(|| revoke(&fixture, &authority, &key, &scope, &body)).await;
    assert_eq!(status, StatusCode::OK, "exact cleanup retry: {replay}");
    assert_eq!(replay["revoked"], json!(body.key_package_refs));
    assert_eq!(before, native_phase(|| snapshot(&fixture)).await);
    let row = fixture
        .state
        .test_persistence()
        .mls_key_packages()
        .get_by_ref(&other_scope)
        .await
        .unwrap()
        .unwrap();
    assert!(
        row.claimed_by_mls_group_id.is_none(),
        "independent scope was not revoked"
    );
    native_phase(|| publish(&fixture, &authority, &key, &identity, &method, &circle)).await;
}

fn request(
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    method: &str,
    refs: Vec<String>,
) -> arkret_models_crypto::KeyPackagesRevokeRequestBody {
    let unsigned = arkret_models_crypto::KeyPackagesRevokeUnsignedRequest {
        key_package_refs: refs,
        device_id: authority.device_id.clone(),
        reason: None,
    };
    let signature = arkret_signatures::keypackages::sign_keypackages_revoke_request(
        &unsigned,
        method,
        &key.to_bytes(),
    )
    .unwrap();
    unsigned.into_signed(signature)
}

async fn publish(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    identity: &arkret_mls::ArkretMlsIdentity,
    method: &str,
    scope: &ScopeRef,
) -> String {
    let body = fresh_upload(identity, method, key, scope);
    let (status, outcome) =
        native_phase(|| upload_in_scope(fixture, authority, key, &body, scope)).await;
    assert_eq!(status, StatusCode::OK, "real own publication: {outcome}");
    assert_eq!(outcome["accepted"], 1, "{outcome}");
    body.keypackages[0].keypackage_ref.clone()
}

async fn negative_guards(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    method: &str,
    scope: &ScopeRef,
    circle: &ScopeRef,
    first: &str,
    other_scope: &str,
    body: &arkret_models_crypto::KeyPackagesRevokeRequestBody,
) {
    let mut wrong_device = body.clone();
    wrong_device.device_id = DeviceId::new(format!("ak:device:{}", uuid::Uuid::now_v7())).unwrap();
    let wrong_key = SigningKey::from_bytes(&[174; 32]);
    let bad_signature = request(authority, &wrong_key, method, body.key_package_refs.clone());
    let crossed = request(
        authority,
        key,
        method,
        vec![first.to_owned(), other_scope.to_owned()],
    );
    for (target, body) in [
        (scope, wrong_device),
        (scope, bad_signature),
        (scope, crossed),
        (circle, body.clone()),
    ] {
        let before = native_phase(|| snapshot(fixture)).await;
        let (status, error) = native_phase(|| revoke(fixture, authority, key, target, &body)).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "native revoke guard: {error}"
        );
        assert_eq!(
            before,
            native_phase(|| snapshot(fixture)).await,
            "refusal has no partial cleanup"
        );
    }
    let unknown = request(
        authority,
        key,
        method,
        vec![format!("sha256:{}", "00".repeat(32))],
    );
    let before = native_phase(|| snapshot(fixture)).await;
    let (status, outcome) = native_phase(|| revoke(fixture, authority, key, scope, &unknown)).await;
    assert_eq!(status, StatusCode::OK, "opaque unknown: {outcome}");
    assert_eq!(outcome["failures"][0]["reason_code"], "keypackage_unknown");
    assert_eq!(before, native_phase(|| snapshot(fixture)).await);
}

async fn rollback(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    scope: &ScopeRef,
    body: &arkret_models_crypto::KeyPackagesRevokeRequestBody,
) {
    let mut conn = fixture.pool.get().await.unwrap();
    let target = &body.key_package_refs[1];
    let sql = format!(
        "CREATE FUNCTION fail_native_keypackage_revoke() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF OLD.keypackage_ref='{target}' THEN RAISE EXCEPTION 'native revoke fault'; END IF; RETURN NEW; END $$"
    );
    diesel::sql_query(sql).execute(&mut conn).await.unwrap();
    diesel::sql_query("CREATE TRIGGER fail_native_keypackage_revoke BEFORE UPDATE ON mls_key_packages FOR EACH ROW EXECUTE FUNCTION fail_native_keypackage_revoke()").execute(&mut conn).await.unwrap();
    drop(conn);
    let before = native_phase(|| snapshot(fixture)).await;
    let (status, error) = native_phase(|| revoke(fixture, authority, key, scope, body)).await;
    let mut conn = fixture.pool.get().await.unwrap();
    diesel::sql_query("DROP TRIGGER fail_native_keypackage_revoke ON mls_key_packages")
        .execute(&mut conn)
        .await
        .unwrap();
    diesel::sql_query("DROP FUNCTION fail_native_keypackage_revoke()")
        .execute(&mut conn)
        .await
        .unwrap();
    drop(conn);
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "real second-row persistence failure: {error}"
    );
    assert_eq!(
        before,
        native_phase(|| snapshot(fixture)).await,
        "whole batch and cache roll back"
    );
}

async fn revoke(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    scope: &ScopeRef,
    body: &arkret_models_crypto::KeyPackagesRevokeRequestBody,
) -> (StatusCode, Value) {
    let mut metadata = managed_device_metadata(authority);
    metadata.effective_scope = scope.clone();
    let mut response = managed_device_http_request_body(
        &fixture.state,
        authority,
        &metadata,
        ServiceOperationId::SelfKeysKeypackagesCommandRevokeV1,
        key,
        Some(arkret_canonical::canonical_json_bytes(body).unwrap()),
    )
    .add_header("content-type", "application/json", true)
    .send(&service(fixture.state.clone()))
    .await;
    (
        response.status_code.unwrap(),
        response.take_json().await.unwrap(),
    )
}
