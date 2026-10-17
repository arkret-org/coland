//! Scope-bound publication by real independent Account Devices.
use ed25519_dalek::Signer as _;

use super::*;

#[path = "e2ee_keypackage_targets.rs"]
mod targets;

#[path = "e2ee_keypackage_input.rs"]
mod input;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bot_and_ghost_upload_scope_bound_keypackages_without_session() {
    tokio::spawn(native_phase(|| async {
        let fixture = native_phase(Fixture::new).await;
        let scope = ScopeRef::Realm {
            realm_id: fixture.realm.clone(),
        };
        native_phase(|| activate_mls(&fixture, scope.clone())).await;
        let namespace = format!("bridge.{}", uuid::Uuid::now_v7().simple());
        let native = mls_service(&fixture, &namespace);
        let install =
            native_phase(|| fixture.install_package(true, native.package.clone(), &namespace))
                .await;
        let ghost =
            native_phase(|| fixture.ghost_body(&install, &namespace, "native-keypackage")).await;
        assert_eq!(
            fixture
                .ghost_commit(&install, &ghost, "native-keypackage-ghost")
                .await
                .0,
            StatusCode::CREATED
        );
        let mut last = None;
        for bundle in [
            &install.bot_body["managed_actor_bundle"],
            &ghost["managed_actor_bundle"],
        ] {
            let key = SigningKey::from_bytes(&[162; 32]);
            let device = DeviceId::new(format!("ak:device:{}", uuid::Uuid::now_v7())).unwrap();
            let authority = native_phase(|| {
                authorize(
                    &fixture,
                    &install,
                    bundle,
                    &namespace,
                    &key,
                    device.clone(),
                    true,
                )
            })
            .await;
            let join = join_event(
                &fixture,
                &install,
                &authority,
                &key,
                &install.bot_outcome.authorization_ref,
            );
            let (status, outcome) =
                native_phase(|| post(&fixture, &authority, &key, &join, vec![])).await;
            assert_eq!(
                status,
                StatusCode::OK,
                "membership before KeyPackage publication: {outcome}"
            );
            let actor = ActorId::account(authority.account_id.clone());
            // The SDK's existing Device representation encodes the real full
            // Account; accepted Station provenance, not this local constructor,
            // distinguishes Human and Applet-managed authorization sources.
            let identity = arkret_mls::ArkretMlsIdentity::new_human_device(
                actor.clone(),
                device,
                arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(key.clone()),
            )
            .unwrap();
            let record = identity.key_package_record().unwrap();
            let fingerprint = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                key.verifying_key().as_bytes(),
            );
            let method = format!("did:key:{fingerprint}#{fingerprint}");
            let mut unsigned = identity
                .signed_key_packages_upload_request(std::slice::from_ref(&record), &method)
                .unwrap()
                .unsigned();
            unsigned.mls_group_id = Some(scope.canonical_mls_group_id().unwrap());
            let bytes = arkret_models_crypto::keypackages_upload_signing_input(&unsigned).unwrap();
            let signature = arkret_signatures::keypackages::keypackage_signature_from_bytes(
                &method,
                &key.sign(&bytes).to_bytes(),
            )
            .unwrap();
            let body = unsigned.into_signed(signature);
            body.validate_shape().unwrap();
            let _: arkret_models_crypto::KeyPackagesUploadRequestBody =
                serde_json::from_slice(&arkret_canonical::canonical_json_bytes(&body).unwrap())
                    .unwrap();
            let (status, outcome) =
                native_phase(|| upload(&fixture, &authority, &key, &body)).await;
            assert_eq!(
                status,
                StatusCode::OK,
                "native KeyPackage upload must accept a real joined independent Device: {outcome}"
            );
            assert_eq!(outcome["accepted"], 1, "{outcome}");
            let typed_outcome: arkret_models_crypto::KeyPackagesUploadOutcome =
                serde_json::from_value(outcome.clone()).unwrap();
            assert!(typed_outcome.rejections.is_empty(), "{outcome}");
            let stored = fixture
                .state
                .test_persistence()
                .mls_key_packages()
                .get_by_ref(record.keypackage_ref.as_str())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(stored.owner_account_id, authority.account_id);
            assert_eq!(stored.effective_scope.as_ref(), Some(&scope));
            assert_eq!(stored.actor_id, authority.account_id.principal_id.as_str());
            assert_eq!(
                stored.device_id.as_deref(),
                Some(authority.device_id.as_str())
            );
            assert_eq!(
                stored.device_authorize_event_id.as_deref(),
                Some(authority.selector.authorization_ref.event_id.as_str())
            );
            assert_eq!(
                stored.key_package_bytes,
                arkret_canonical::base64url_decode(record.keypackage.as_bytes()).unwrap()
            );
            native_phase(|| {
                publication_guards(
                    &fixture, &install, &authority, &key, &identity, &method, &scope, &body,
                )
            })
            .await;
            let authority = native_phase(|| {
                circle_publication(
                    &fixture, &install, &namespace, bundle, &authority, &key, &identity, &method,
                )
            })
            .await;
            last = Some((authority, key, identity, method));
        }
        let (authority, key, identity, method) = last.unwrap();
        native_phase(|| fixture.revoke(&install)).await;
        let body = fresh_upload(&identity, &method, &key, &scope);
        let before = native_phase(|| snapshot(&fixture)).await;
        let (status, error) = native_phase(|| upload(&fixture, &authority, &key, &body)).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "accepted installation fence: {error}"
        );
        assert_eq!(
            error["type"], "https://arkret.org/problems/applet_revoked",
            "{error}"
        );
        assert_eq!(before, native_phase(|| snapshot(&fixture)).await);
        let circle = authority
            .scopes
            .entries()
            .iter()
            .find(|entry| matches!(entry.effective_scope, ScopeRef::Circle { .. }))
            .unwrap()
            .effective_scope
            .clone();
        let body = fresh_upload(&identity, &method, &key, &circle);
        let (status, outcome) = native_phase(|| upload(&fixture, &authority, &key, &body)).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "independent Circle survives Realm installation fence: {outcome}"
        );
        assert_eq!(outcome["accepted"], 1, "{outcome}");
    }))
    .await
    .unwrap();
}

async fn upload(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    body: &arkret_models_crypto::KeyPackagesUploadRequestBody,
) -> (StatusCode, Value) {
    let scope = authority
        .scopes
        .entries()
        .iter()
        .find(|entry| {
            entry.effective_scope.canonical_mls_group_id().ok().as_ref()
                == body.mls_group_id.as_ref()
        })
        .map(|entry| &entry.effective_scope)
        .unwrap_or(&authority.scopes.entries()[0].effective_scope);
    upload_in_scope(fixture, authority, key, body, scope).await
}

async fn upload_in_scope(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    body: &arkret_models_crypto::KeyPackagesUploadRequestBody,
    scope: &ScopeRef,
) -> (StatusCode, Value) {
    let mut metadata = managed_device_metadata(authority);
    metadata.effective_scope = scope.clone();
    let mut response = managed_device_http_request_body(
        &fixture.state,
        authority,
        &metadata,
        ServiceOperationId::SelfKeysKeypackagesUploadCreateV1,
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

fn sign_upload(
    unsigned: arkret_models_crypto::KeyPackagesUploadUnsignedRequest,
    method: &str,
    key: &SigningKey,
) -> arkret_models_crypto::KeyPackagesUploadRequestBody {
    let input = arkret_models_crypto::keypackages_upload_signing_input(&unsigned).unwrap();
    let signature = arkret_signatures::keypackages::keypackage_signature_from_bytes(
        method,
        &key.sign(&input).to_bytes(),
    )
    .unwrap();
    let body = unsigned.into_signed(signature);
    body.validate_shape().unwrap();
    body
}

fn fresh_upload(
    identity: &arkret_mls::ArkretMlsIdentity,
    method: &str,
    key: &SigningKey,
    scope: &ScopeRef,
) -> arkret_models_crypto::KeyPackagesUploadRequestBody {
    let record = identity.key_package_record().unwrap();
    let mut unsigned = identity
        .signed_key_packages_upload_request(&[record], method)
        .unwrap()
        .unsigned();
    unsigned.mls_group_id = Some(scope.canonical_mls_group_id().unwrap());
    sign_upload(unsigned, method, key)
}

async fn snapshot(
    fixture: &Fixture,
) -> (
    Value,
    Vec<coland_storage::MlsKeyPackageRow>,
    Vec<coland_storage::MlsKeyPackageRow>,
) {
    let mut durable = fixture
        .state
        .test_persistence()
        .mls_key_packages()
        .snapshot_all()
        .await
        .unwrap();
    durable.sort_by(|a, b| a.id.cmp(&b.id));
    let mut cache = fixture.state.test_projections().mls_key_package_records();
    cache.sort_by(|a, b| a.id.cmp(&b.id));
    (business(fixture).await, durable, cache)
}

async fn publication_guards(
    fixture: &Fixture,
    install: &Installed,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    identity: &arkret_mls::ArkretMlsIdentity,
    method: &str,
    scope: &ScopeRef,
    original: &arkret_models_crypto::KeyPackagesUploadRequestBody,
) {
    let before = native_phase(|| snapshot(fixture)).await;
    let (status, outcome) = native_phase(|| upload(fixture, authority, key, original)).await;
    assert_eq!(status, StatusCode::OK, "exact publication retry: {outcome}");
    assert_eq!(before, native_phase(|| snapshot(fixture)).await);

    let mut different = original.unsigned();
    different.keypackages[0].expires_at += chrono::Duration::seconds(1);
    let different = sign_upload(different, method, key);
    let (status, error) = native_phase(|| upload(fixture, authority, key, &different)).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "different original under same id: {error}"
    );
    assert_eq!(
        error["type"], "https://arkret.org/problems/duplicate_conflict",
        "{error}"
    );
    assert_eq!(before, native_phase(|| snapshot(fixture)).await);

    let fresh = fresh_upload(identity, method, key, scope);
    let other = native_phase(|| fixture.new_circle_scope()).await;
    native_phase(|| super::circle::join_founder(fixture, &other)).await;
    native_phase(|| activate_mls(fixture, other.clone())).await;
    let mut wrong_scope = fresh.unsigned();
    wrong_scope.mls_group_id = Some(other.canonical_mls_group_id().unwrap());
    let wrong_scope = sign_upload(wrong_scope, method, key);
    let before = native_phase(|| snapshot(fixture)).await;
    let (status, error) = native_phase(|| upload(fixture, authority, key, &wrong_scope)).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "another real MLS group: {error}"
    );
    assert_eq!(before, native_phase(|| snapshot(fixture)).await);

    let foreign = arkret_mls::ArkretMlsIdentity::new_human_device(
        ActorId::account(authority.account_id.clone()),
        authority.device_id.clone(),
        arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(SigningKey::from_bytes(&[163; 32])),
    )
    .unwrap();
    let wrong_leaf = fresh_upload(&foreign, method, key, scope);
    let (status, error) = native_phase(|| upload(fixture, authority, key, &wrong_leaf)).await;
    assert_eq!(status, StatusCode::OK, "per-entry leaf rejection: {error}");
    assert_eq!(error["accepted"], 0, "{error}");
    assert_eq!(error["rejections"].as_array().unwrap().len(), 1, "{error}");
    assert_eq!(before, native_phase(|| snapshot(fixture)).await);

    // Only this fixture's private accepted consent row is perturbed. Restore
    // the exact original before checking the real handler's error and effects.
    let digest = arkret_canonical::canonical_sha256(&install.body).unwrap();
    let mut conn = fixture.pool.get().await.unwrap();
    assert_eq!(diesel::sql_query("UPDATE applet_authoring_units SET request_body=jsonb_set(request_body,'{authoring_request_basis,e2ee_policy,mls_join_allowed}','false'::jsonb) WHERE canonical_request_hash=$1")
        .bind::<diesel::sql_types::Text,_>(&digest).execute(&mut conn).await.unwrap(),1);
    drop(conn);
    let before = native_phase(|| snapshot(fixture)).await;
    let (status, error) = native_phase(|| upload(fixture, authority, key, &fresh)).await;
    let after = native_phase(|| snapshot(fixture)).await;
    let mut conn = fixture.pool.get().await.unwrap();
    diesel::sql_query(
        "UPDATE applet_authoring_units SET request_body=$2 WHERE canonical_request_hash=$1",
    )
    .bind::<diesel::sql_types::Text, _>(&digest)
    .bind::<diesel::sql_types::Jsonb, _>(&install.body)
    .execute(&mut conn)
    .await
    .unwrap();
    drop(conn);
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "missing independent consent: {error}"
    );
    assert_eq!(
        error["type"], "https://arkret.org/problems/applet_e2ee_join_unauthorized",
        "{error}"
    );
    assert_eq!(before, after);

    let policy = native_phase(|| {
        super::circle::deny_policy(fixture, install, scope, scope.clone(), "execute")
    })
    .await;
    let before = native_phase(|| snapshot(fixture)).await;
    let (status, error) = native_phase(|| upload(fixture, authority, key, &fresh)).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "current execution Policy: {error}"
    );
    assert_eq!(
        error["type"], "https://arkret.org/problems/capability_denied",
        "{error}"
    );
    assert_eq!(before, native_phase(|| snapshot(fixture)).await);
    native_phase(|| super::circle::allow_policy(fixture, &policy)).await;

    let before = native_phase(|| snapshot(fixture)).await;
    let mut conn = fixture.pool.get().await.unwrap();
    diesel::sql_query("CREATE FUNCTION fail_native_keypackage_insert() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'native KeyPackage insertion fault'; END $$").execute(&mut conn).await.unwrap();
    diesel::sql_query("CREATE TRIGGER fail_native_keypackage_insert BEFORE INSERT ON mls_key_packages FOR EACH ROW EXECUTE FUNCTION fail_native_keypackage_insert()").execute(&mut conn).await.unwrap();
    drop(conn);
    let (status, error) = native_phase(|| upload(fixture, authority, key, &fresh)).await;
    let mut conn = fixture.pool.get().await.unwrap();
    diesel::sql_query("DROP TRIGGER fail_native_keypackage_insert ON mls_key_packages")
        .execute(&mut conn)
        .await
        .unwrap();
    diesel::sql_query("DROP FUNCTION fail_native_keypackage_insert()")
        .execute(&mut conn)
        .await
        .unwrap();
    drop(conn);
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "durable publication fault: {error}"
    );
    assert_eq!(
        before,
        native_phase(|| snapshot(fixture)).await,
        "failed persistence must not publish an in-memory candidate"
    );
    let (status, accepted) = native_phase(|| upload(fixture, authority, key, &fresh)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "retry original after real persistence fault: {accepted}"
    );
    assert_eq!(accepted["accepted"], 1, "{accepted}");
    #[derive(diesel::QueryableByName)]
    struct Count {
        #[diesel(sql_type=diesel::sql_types::BigInt)]
        value: i64,
    }
    let mut conn = fixture.pool.get().await.unwrap();
    let count = diesel::sql_query(
        "SELECT COUNT(*) AS value FROM accounts WHERE principal_id=$1 AND station_id=$2",
    )
    .bind::<diesel::sql_types::Text, _>(authority.account_id.principal_id.as_str())
    .bind::<diesel::sql_types::Text, _>(authority.account_id.station_id.as_str())
    .get_result::<Count>(&mut conn)
    .await
    .unwrap()
    .value;
    assert_eq!(
        count, 0,
        "native publication must not create a Human Account row"
    );
}

async fn circle_publication(
    fixture: &Fixture,
    install: &Installed,
    namespace: &str,
    bundle: &Value,
    previous: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    identity: &arkret_mls::ArkretMlsIdentity,
    method: &str,
) -> coland_storage::AppletManagedDeviceAuthority {
    let authority = native_phase(|| {
        circle_membership(fixture, install, namespace, bundle, previous, key, true)
    })
    .await;
    let scope = authority
        .scopes
        .entries()
        .iter()
        .find(|entry| matches!(entry.effective_scope, ScopeRef::Circle { .. }))
        .unwrap()
        .effective_scope
        .clone();
    let body = fresh_upload(identity, method, key, &scope);
    let (status, outcome) = native_phase(|| upload(fixture, &authority, key, &body)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "exact Circle KeyPackage publication: {outcome}"
    );
    assert_eq!(outcome["accepted"], 1, "{outcome}");
    let stored = fixture
        .state
        .test_persistence()
        .mls_key_packages()
        .get_by_ref(&body.keypackages[0].keypackage_ref)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.owner_account_id, authority.account_id);
    assert_eq!(stored.effective_scope.as_ref(), Some(&scope));
    assert_eq!(
        stored.device_authorize_event_id.as_deref(),
        Some(authority.selector.authorization_ref.event_id.as_str())
    );
    authority
}

async fn circle_membership(
    fixture: &Fixture,
    install: &Installed,
    namespace: &str,
    bundle: &Value,
    previous: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    activate_group: bool,
) -> coland_storage::AppletManagedDeviceAuthority {
    let scope = native_phase(|| fixture.new_circle_scope()).await;
    native_phase(|| super::circle::join_founder(fixture, &scope)).await;
    if activate_group {
        native_phase(|| activate_mls(fixture, scope.clone())).await;
    }
    native_phase(|| {
        fixture.install_service_with_constraints(
            true,
            install.package.clone(),
            scope.clone(),
            BTreeMap::new(),
        )
    })
    .await;
    let authority=native_phase(||authorize_scopes(fixture,install,bundle,namespace,key,previous.device_id.clone(),json!([
        {"effective_scope":scope,"actions":["ak.applet.join","ak.circle.member.add","ak.event.read"]},
        {"effective_scope":{"kind":"realm","realm_id":fixture.realm},"actions":["ak.applet.join","ak.event.read"]}
    ]))).await;
    let actor = ActorId::account(authority.account_id.clone());
    let parent = native_business_parent_in_scope(
        fixture,
        install,
        vec![],
        vec!["ak.circle.member.add".into()],
        None,
        scope.clone(),
    )
    .await;
    let child = native_phase(|| {
        native_business_child(fixture, install, &actor, std::slice::from_ref(&parent))
    })
    .await;
    let parent_revision =
        ordinary_realm::parent_membership_revision(&fixture.pool, &fixture.realm, &actor).await;
    let event = native_circle_event(
        install,
        &authority,
        key,
        &scope,
        &child,
        "join",
        Some(parent_revision),
        Value::Null,
    );
    let (status, outcome) = native_phase(|| post(fixture, &authority, key, &event, vec![])).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "actual encrypted Circle membership before publication: {outcome}"
    );
    authority
}
