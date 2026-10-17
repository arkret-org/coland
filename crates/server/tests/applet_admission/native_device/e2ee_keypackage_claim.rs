//! Real native requester and target, without a synthesized Session or account row.
use std::collections::BTreeSet;

use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_device_claims_a_genuine_scope_bound_package_without_session() {
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
    native_phase(|| activate_mls(&fixture, scope.clone())).await;
    let namespace = format!("bridge.{}", uuid::Uuid::now_v7().simple());
    let native = mls_service(&fixture, &namespace);
    let install =
        native_phase(|| fixture.install_package(true, native.package.clone(), &namespace)).await;
    let bundle = if ghost {
        let body = native_phase(|| fixture.ghost_body(&install, &namespace, "claim-device")).await;
        assert_eq!(
            native_phase(|| fixture.ghost_commit(&install, &body, "claim-device"))
                .await
                .0,
            StatusCode::CREATED
        );
        body["managed_actor_bundle"].clone()
    } else {
        install.bot_body["managed_actor_bundle"].clone()
    };
    let key = SigningKey::from_bytes(&[177; 32]);
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
    let event = join_event(
        &fixture,
        &install,
        &authority,
        &key,
        &install.bot_outcome.authorization_ref,
    );
    let (status, outcome) = native_phase(|| post(&fixture, &authority, &key, &event, vec![])).await;
    assert_eq!(status, StatusCode::OK, "real native membership: {outcome}");
    let _read_parent = native_phase(|| {
        native_business_parent(
            &fixture,
            &install,
            vec![],
            vec!["ak.event.read".into()],
            None,
        )
    })
    .await;
    let identity = arkret_mls::ArkretMlsIdentity::new_human_device(
        ActorId::account(authority.account_id.clone()),
        device,
        arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(key.clone()),
    )
    .unwrap();
    let fingerprint =
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(key.verifying_key().as_bytes());
    let method = format!("did:key:{fingerprint}#{fingerprint}");
    let upload_body = fresh_upload(&identity, &method, &key, &scope);
    let (status, outcome) =
        native_phase(|| upload_in_scope(&fixture, &authority, &key, &upload_body, &scope)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "actual fresh native package: {outcome}"
    );
    assert_eq!(outcome["accepted"], 1, "{outcome}");
    let body = request(
        &authority,
        &key,
        &scope,
        &upload_body.keypackages[0].keypackage_ref,
    );
    let before = native_phase(|| snapshot(&fixture)).await;
    let bad = request(
        &authority,
        &SigningKey::from_bytes(&[178; 32]),
        &scope,
        &upload_body.keypackages[0].keypackage_ref,
    );
    assert!(
        !native_phase(|| claim(&fixture, &authority, &key, &scope, &bad))
            .await
            .0
            .is_success()
    );
    assert_eq!(
        before,
        native_phase(|| snapshot(&fixture)).await,
        "invalid participant signature must not touch claim state"
    );
    native_phase(|| rollback(&fixture, &authority, &key, &scope, &body)).await;
    let (status, outcome) = native_phase(|| claim(&fixture, &authority, &key, &scope, &body)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "native claim must use its actual requester and target instead of requiring a Session: {outcome}"
    );
    let outcome: arkret_models_crypto::KeyPackagesClaimOutcome =
        serde_json::from_value(outcome).unwrap();
    assert_eq!(outcome.claims.len(), 1);
    assert_eq!(
        outcome.claims[0].actor_id,
        ActorId::account(authority.account_id.clone())
    );
    assert_eq!(
        outcome.claims[0].device_id.as_ref(),
        Some(&authority.device_id)
    );
    assert_eq!(
        outcome.claims[0].keypackage_ref,
        upload_body.keypackages[0].keypackage_ref
    );
    let accepted = serde_json::to_value(&outcome).unwrap();
    let before = native_phase(|| snapshot(&fixture)).await;
    let (status, replay) = native_phase(|| claim(&fixture, &authority, &key, &scope, &body)).await;
    assert_eq!(status, StatusCode::OK, "{replay}");
    assert_eq!(
        accepted, replay,
        "exact retry keeps the original claim id and receipt"
    );
    assert_eq!(before, native_phase(|| snapshot(&fixture)).await);
    let mut changed = body.clone();
    changed.timeout_ms = Some(1);
    resign(&mut changed, &key);
    let (status, error) =
        native_phase(|| claim(&fixture, &authority, &key, &scope, &changed)).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "same request id with another signed body: {error}"
    );
    assert_eq!(before, native_phase(|| snapshot(&fixture)).await);
    native_phase(|| mixed(&fixture, &authority, &key, &scope, &identity, &method)).await;
    native_phase(|| fixture.revoke(&install)).await;
    let fenced = native_phase(|| snapshot(&fixture)).await;
    let (status, error) = native_phase(|| claim(&fixture, &authority, &key, &scope, &body)).await;
    assert!(
        !status.is_success(),
        "immutable original bytes still need current material delivery permission: {error}"
    );
    assert_eq!(fenced, native_phase(|| snapshot(&fixture)).await);
}

fn request(
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    scope: &ScopeRef,
    reference: &str,
) -> arkret_models_crypto::KeyPackagesClaimRequestBody {
    let signed_at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let method = format!("{}#{}", authority.native_did, authority.device_id);
    // Two independent OS-backed UUIDv4 values retain 244 unpredictable bits.
    let random = [
        uuid::Uuid::new_v4().into_bytes(),
        uuid::Uuid::new_v4().into_bytes(),
    ]
    .concat();
    let mut body = arkret_models_crypto::KeyPackagesClaimRequestBody {
        claim_request_id: arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
            random,
        ))
        .unwrap(),
        target_account_id: Some(authority.account_id.clone()),
        requester_account_id: Some(authority.account_id.clone()),
        intended_realm_id: scope.realm_id().clone(),
        mls_group_id: scope.canonical_mls_group_id().unwrap(),
        claim_purpose: arkret_models_crypto::PeerKeyPackageClaimPurpose::RealmMembership,
        required_capabilities: vec![arkret_wire::NonEmptyString::new("ak.content.v1").unwrap()],
        expires_at: signed_at + chrono::Duration::minutes(1),
        target_device_ids: vec![authority.device_id.clone()],
        target_keypackage_ref: Some(arkret_wire::KeyPackageRef::new(reference.to_owned()).unwrap()),
        target_agent_id: None,
        target_agent_verification_method: None,
        target_agent_key_authorize_event_id: None,
        timeout_ms: None,
        strand_id: None,
        pair_key: None,
        last_resort_allowed: None,
        service_binding: arkret_models_crypto::KeyPackagesClaimServiceBinding {
            source_id: authority.account_id.station_id.clone(),
            destination_id: authority.account_id.station_id.clone(),
        },
        requester_authorization:
            arkret_models_crypto::PeerKeyPackageRequesterAuthorization::Device {
                verification_method: arkret_wire::DidUrl::new(method.clone()).unwrap(),
                requester_device_id: authority.device_id.clone(),
                device_authorize_event_id: authority.selector.authorization_ref.event_id.clone(),
                signed_at,
                signature: arkret_signatures::keypackages::keypackage_signature_from_bytes(
                    &method, &[0; 64],
                )
                .unwrap(),
            },
    };
    resign(&mut body, key);
    body.validate_shape().unwrap();
    body
}

fn resign(body: &mut arkret_models_crypto::KeyPackagesClaimRequestBody, key: &SigningKey) {
    let method = match &body.requester_authorization {
        arkret_models_crypto::PeerKeyPackageRequesterAuthorization::Device {
            verification_method,
            ..
        } => verification_method.to_string(),
        _ => unreachable!(),
    };
    let input = arkret_models_crypto::keypackage_claim_authorization_signing_bytes(
        &body.unsigned_request(),
        &body.service_binding,
        &body.requester_authorization,
    )
    .unwrap();
    let arkret_models_crypto::PeerKeyPackageRequesterAuthorization::Device { signature, .. } =
        &mut body.requester_authorization
    else {
        unreachable!()
    };
    *signature = arkret_signatures::keypackages::keypackage_signature_from_bytes(
        &method,
        &key.sign(&input).to_bytes(),
    )
    .unwrap();
}

async fn claim(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    scope: &ScopeRef,
    body: &arkret_models_crypto::KeyPackagesClaimRequestBody,
) -> (StatusCode, Value) {
    let mut metadata = managed_device_metadata(authority);
    metadata.effective_scope = scope.clone();
    let mut response = managed_device_http_request_with_idempotency_at(
        &fixture.state,
        authority,
        &metadata,
        ServiceOperationId::SelfKeysKeypackagesCommandClaimV1,
        key,
        Some(arkret_canonical::canonical_json_bytes(body).unwrap()),
        None,
        body.claim_request_id.as_str(),
    )
    .add_header("content-type", "application/json", true)
    .send(&service(fixture.state.clone()))
    .await;
    (
        response.status_code.unwrap(),
        response.take_json().await.unwrap(),
    )
}

async fn snapshot(fixture: &Fixture) -> Value {
    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type=diesel::sql_types::Jsonb)]
        value: Value,
    }
    let mut conn = fixture.pool.get().await.unwrap();
    let row=diesel::sql_query("SELECT jsonb_build_object('packages',(SELECT jsonb_agg(to_jsonb(k) ORDER BY id) FROM mls_key_packages k),'claims',(SELECT jsonb_agg(to_jsonb(c) ORDER BY source_id,claim_request_id) FROM peer_keypackage_claims c)) AS value").get_result::<Row>(&mut *conn).await.unwrap();
    let projection = fixture
        .state
        .test_projections()
        .mls_key_package_records()
        .iter()
        .map(|row| {
            (
                row.id.clone(),
                row.claimed_by_mls_group_id.clone(),
                row.claimed_at,
                row.claim_expires_at_unix_ms,
                row.last_resort_realm_id.clone(),
                row.consumed_at,
            )
        })
        .collect::<BTreeSet<_>>();
    json!({"durable":row.value,"projection":projection})
}

async fn rollback(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    scope: &ScopeRef,
    body: &arkret_models_crypto::KeyPackagesClaimRequestBody,
) {
    let mut conn = fixture.pool.get().await.unwrap();
    diesel::sql_query(
        "DROP TRIGGER IF EXISTS fail_native_keypackage_claim ON peer_keypackage_claims",
    )
    .execute(&mut *conn)
    .await
    .unwrap();
    diesel::sql_query("DROP FUNCTION IF EXISTS fail_native_keypackage_claim()")
        .execute(&mut *conn)
        .await
        .unwrap();
    let sql = format!(
        "CREATE FUNCTION fail_native_keypackage_claim() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.claim_request_id='{}' THEN RAISE EXCEPTION 'native claim ledger fault'; END IF; RETURN NEW; END $$",
        body.claim_request_id
    );
    diesel::sql_query(sql).execute(&mut *conn).await.unwrap();
    diesel::sql_query("CREATE TRIGGER fail_native_keypackage_claim BEFORE INSERT ON peer_keypackage_claims FOR EACH ROW EXECUTE FUNCTION fail_native_keypackage_claim()").execute(&mut *conn).await.unwrap();
    drop(conn);
    let before = native_phase(|| snapshot(fixture)).await;
    let (status, error) = native_phase(|| claim(fixture, authority, key, scope, body)).await;
    let mut conn = fixture.pool.get().await.unwrap();
    diesel::sql_query("DROP TRIGGER fail_native_keypackage_claim ON peer_keypackage_claims")
        .execute(&mut *conn)
        .await
        .unwrap();
    diesel::sql_query("DROP FUNCTION fail_native_keypackage_claim()")
        .execute(&mut *conn)
        .await
        .unwrap();
    drop(conn);
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "actual ledger write failure: {error}"
    );
    assert_eq!(
        before,
        native_phase(|| snapshot(fixture)).await,
        "package CAS and immutable ledger must roll back together, including projection"
    );
}

async fn mixed(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    scope: &ScopeRef,
    identity: &arkret_mls::ArkretMlsIdentity,
    method: &str,
) {
    let upload = fresh_upload(identity, method, key, scope);
    let (status, outcome) =
        native_phase(|| upload_in_scope(fixture, authority, key, &upload, scope)).await;
    assert_eq!(status, StatusCode::OK, "{outcome}");
    assert_eq!(outcome["accepted"], 1);
    let human_key = SigningKey::from_bytes(&fixture.pcr.history.founding_device_signing_seed);
    let mut body = request(authority, key, scope, &upload.keypackages[0].keypackage_ref);
    body.requester_account_id = Some(fixture.pcr.history.account.clone());
    let authorize = fixture
        .pcr
        .unit
        .transactions
        .iter()
        .find(|tx| tx.event.kind == EventKind::DeviceAuthorize)
        .unwrap()
        .event
        .event_id
        .clone();
    let authorization = &mut body.requester_authorization;
    if let arkret_models_crypto::PeerKeyPackageRequesterAuthorization::Device {
        verification_method,
        requester_device_id,
        device_authorize_event_id,
        signature,
        ..
    } = authorization
    {
        *verification_method = fixture.pcr.history.device_verification_method.clone();
        *requester_device_id = fixture.pcr.history.founding_device_id.clone();
        *device_authorize_event_id = authorize;
        signature.kid = arkret_wire::NonEmptyString::new(verification_method.to_string()).unwrap();
    } else {
        unreachable!()
    }
    resign(&mut body, &human_key);
    let value = serde_json::to_value(&body).unwrap();
    let before = native_phase(|| snapshot(fixture)).await;
    for wrong in [None, Some("another-transport-key")] {
        let (status, error) = native_phase(|| {
            fixture.admin_post(
                "/_arkret/self/keys/keypackages/claim",
                ServiceOperationId::SelfKeysKeypackagesCommandClaimV1.as_str(),
                &value,
                wrong,
            )
        })
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "actual signed Human/native claim must bind one exact HTTP key to its original transaction id: {error}"
        );
        assert_eq!(
            before,
            native_phase(|| snapshot(fixture)).await,
            "a header/body identity mismatch must not consume a publication or ledger"
        );
    }
    let (status, outcome) = native_phase(|| {
        fixture.admin_post(
            "/_arkret/self/keys/keypackages/claim",
            ServiceOperationId::SelfKeysKeypackagesCommandClaimV1.as_str(),
            &value,
            Some(body.claim_request_id.as_str()),
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "real Human requester to native target: {outcome}"
    );
    assert_eq!(
        outcome["claims"][0]["actor_id"],
        serde_json::to_value(ActorId::account(authority.account_id.clone())).unwrap()
    );

    let human = arkret_mls::ArkretMlsIdentity::new_human_device(
        ActorId::account(fixture.pcr.history.account.clone()),
        fixture.pcr.history.founding_device_id.clone(),
        arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(human_key.clone()),
    )
    .unwrap();
    let upload = fresh_upload(
        &human,
        fixture.pcr.history.device_verification_method.as_str(),
        &human_key,
        scope,
    );
    let value = serde_json::to_value(&upload).unwrap();
    let (status, outcome) = native_phase(|| {
        fixture.admin_post(
            "/_arkret/self/keys/keypackages/upload",
            ServiceOperationId::SelfKeysKeypackagesUploadCreateV1.as_str(),
            &value,
            Some(&upload.keypackages[0].keypackage_id),
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "actual Human publication: {outcome}"
    );
    assert_eq!(outcome["accepted"], 1);
    let mut body = request(authority, key, scope, &upload.keypackages[0].keypackage_ref);
    body.target_account_id = Some(fixture.pcr.history.account.clone());
    body.target_device_ids = vec![fixture.pcr.history.founding_device_id.clone()];
    resign(&mut body, key);
    let (status, outcome) = native_phase(|| claim(fixture, authority, key, scope, &body)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "real native requester to Human target: {outcome}"
    );
    assert_eq!(
        outcome["claims"][0]["actor_id"],
        serde_json::to_value(ActorId::account(fixture.pcr.history.account.clone())).unwrap()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn claim_consent_expiry_blocks_already_prepared_key_material_at_handoff() {
    tokio::spawn(native_phase(|| async {
        use arkret_models_collaboration::governance::grant_constraint::{GrantConstraintEffect,GrantConstraintKind};
        let fixture=native_phase(Fixture::new).await;
        let scope=ScopeRef::Realm{realm_id:fixture.realm.clone()};
        native_phase(||activate_mls(&fixture,scope.clone())).await;
        let namespace=format!("bridge.{}",uuid::Uuid::now_v7().simple());
        let native=mls_service(&fixture,&namespace);
        let deadline=arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()+chrono::Duration::seconds(15));
        let mut temporal=GrantConstraint::new(GrantConstraintKind::Temporal,GrantConstraintEffect::Allow);
        temporal.expires_at=Some(deadline);
        let extras=["ak.message.create","ak.applet.bot.provision","ak.applet.ghost.provision"].into_iter().map(|action|(action.to_owned(),vec![temporal.clone()])).collect();
        let (package,outcome,body,install_key)=native_phase(||fixture.install_service_with_constraints(true,native.package.clone(),scope.clone(),extras)).await;
        let (bot_outcome,bot_body)=native_phase(||fixture.provision_bot_in_scope(&package,&namespace,outcome.registration_event_ref.clone(),scope.clone())).await;
        let install=Installed { package, outcome, bot_outcome, bot_body, body, key:install_key };
        let key=SigningKey::from_bytes(&[176;32]);
        let device=DeviceId::new(format!("ak:device:{}",uuid::Uuid::now_v7())).unwrap();
        let authority=native_phase(||authorize(&fixture,&install,&install.bot_body["managed_actor_bundle"],&namespace,&key,device,true)).await;
        let event=join_event(&fixture,&install,&authority,&key,&install.bot_outcome.authorization_ref);
        let (status,outcome)=native_phase(||post(&fixture,&authority,&key,&event,vec![])).await;
        assert_eq!(status,StatusCode::OK,"original finite consent is initially live: {outcome}");
        let _read_parent=native_phase(||native_business_parent(&fixture,&install,vec![],vec!["ak.event.read".into()],None)).await;
        let identity=arkret_mls::ArkretMlsIdentity::new_human_device(ActorId::account(authority.account_id.clone()),authority.device_id.clone(),arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(key.clone())).unwrap();
        let fingerprint=arkret_canonical::ed25519_pubkey_to_did_key_multibase(key.verifying_key().as_bytes());
        let upload=fresh_upload(&identity,&format!("did:key:{fingerprint}#{fingerprint}"),&key,&scope);
        assert_eq!(native_phase(||upload_in_scope(&fixture,&authority,&key,&upload,&scope)).await.0,StatusCode::OK);
        let body=request(&authority,&key,&scope,&upload.keypackages[0].keypackage_ref);
        let mut metadata=managed_device_metadata(&authority);metadata.effective_scope=scope.clone();
        let mut response=native_phase(||async {managed_device_http_request_with_idempotency_at(&fixture.state,&authority,&metadata,ServiceOperationId::SelfKeysKeypackagesCommandClaimV1,&key,Some(arkret_canonical::canonical_json_bytes(&body).unwrap()),None,body.claim_request_id.as_str()).add_header("content-type","application/json",true).send(&service(fixture.state.clone())).await}).await;
        assert_eq!(response.status_code,Some(StatusCode::OK),"claim must prepare actual material before expiry");
        let before=native_phase(||snapshot(&fixture)).await;
        let remaining=(deadline-chrono::Utc::now()).to_std().unwrap_or_default();
        tokio::time::sleep(remaining+std::time::Duration::from_millis(100)).await;
        assert!(response.take_json::<Value>().await.is_err(),"expired original E2EE consent cannot hand off prepared bytes while a separate read parent remains active");
        assert_eq!(before,native_phase(||snapshot(&fixture)).await);
        let (status,error)=native_phase(||claim(&fixture,&authority,&key,&scope,&body)).await;
        assert!(!status.is_success(),"expired current consent cannot expose original claim: {error}");
        assert_eq!(before,native_phase(||snapshot(&fixture)).await);
    })).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_circle_claim_matches_its_real_group_and_survives_independent_realm_fence() {
    for ghost in [false, true] {
        tokio::spawn(native_phase(|| circle(ghost))).await.unwrap();
    }
}
async fn circle(ghost: bool) {
    let fixture = native_phase(Fixture::new).await;
    let realm = ScopeRef::Realm {
        realm_id: fixture.realm.clone(),
    };
    native_phase(|| activate_mls(&fixture, realm.clone())).await;
    let namespace = format!("bridge.{}", uuid::Uuid::now_v7().simple());
    let native = mls_service(&fixture, &namespace);
    let install =
        native_phase(|| fixture.install_package(true, native.package.clone(), &namespace)).await;
    let bundle = if ghost {
        let body =
            native_phase(|| fixture.ghost_body(&install, &namespace, "circle-claim-device")).await;
        assert_eq!(
            native_phase(|| fixture.ghost_commit(&install, &body, "circle-claim-device"))
                .await
                .0,
            StatusCode::CREATED
        );
        body["managed_actor_bundle"].clone()
    } else {
        install.bot_body["managed_actor_bundle"].clone()
    };
    let key = SigningKey::from_bytes(&[179; 32]);
    let device = DeviceId::new(format!("ak:device:{}", uuid::Uuid::now_v7())).unwrap();
    let original =
        native_phase(|| authorize(&fixture, &install, &bundle, &namespace, &key, device, true))
            .await;
    let event = join_event(
        &fixture,
        &install,
        &original,
        &key,
        &install.bot_outcome.authorization_ref,
    );
    assert_eq!(
        native_phase(|| post(&fixture, &original, &key, &event, vec![]))
            .await
            .0,
        StatusCode::OK
    );
    let authority = native_phase(|| {
        circle_membership(
            &fixture, &install, &namespace, &bundle, &original, &key, true,
        )
    })
    .await;
    let scope = authority
        .scopes
        .entries()
        .iter()
        .find(|pair| matches!(pair.effective_scope, ScopeRef::Circle { .. }))
        .unwrap()
        .effective_scope
        .clone();
    let _read = native_phase(|| {
        native_business_parent_in_scope(
            &fixture,
            &install,
            vec![],
            vec!["ak.event.read".into()],
            None,
            scope.clone(),
        )
    })
    .await;
    let identity = arkret_mls::ArkretMlsIdentity::new_human_device(
        ActorId::account(authority.account_id.clone()),
        authority.device_id.clone(),
        arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(key.clone()),
    )
    .unwrap();
    let fingerprint =
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(key.verifying_key().as_bytes());
    let upload = fresh_upload(
        &identity,
        &format!("did:key:{fingerprint}#{fingerprint}"),
        &key,
        &scope,
    );
    let (status, outcome) =
        native_phase(|| upload_in_scope(&fixture, &authority, &key, &upload, &scope)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "actual independently installed Circle publication: {outcome}"
    );
    assert_eq!(outcome["accepted"], 1);
    let body = request(
        &authority,
        &key,
        &scope,
        &upload.keypackages[0].keypackage_ref,
    );
    let before = native_phase(|| snapshot(&fixture)).await;
    let (status, error) = native_phase(|| claim(&fixture, &authority, &key, &realm, &body)).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "signed actual Circle differs from metadata Realm: {error}"
    );
    assert_eq!(before, native_phase(|| snapshot(&fixture)).await);
    let mut bad = body.clone();
    if let arkret_models_crypto::PeerKeyPackageRequesterAuthorization::Device {
        device_authorize_event_id,
        ..
    } = &mut bad.requester_authorization
    {
        *device_authorize_event_id = original.selector.authorization_ref.event_id.clone();
    } else {
        unreachable!()
    }
    resign(&mut bad, &key);
    assert!(
        !native_phase(|| claim(&fixture, &authority, &key, &scope, &bad))
            .await
            .0
            .is_success()
    );
    assert_eq!(
        before,
        native_phase(|| snapshot(&fixture)).await,
        "old original Device authority cannot select material"
    );
    let (status, outcome) = native_phase(|| claim(&fixture, &authority, &key, &scope, &body)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "actual Circle native claim: {outcome}"
    );
    native_phase(|| fixture.revoke(&install)).await;
    let before = native_phase(|| snapshot(&fixture)).await;
    let (status, replay) = native_phase(|| claim(&fixture, &authority, &key, &scope, &body)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "Realm A fence must preserve exact Circle B original material read: {replay}"
    );
    assert_eq!(outcome, replay);
    assert_eq!(before, native_phase(|| snapshot(&fixture)).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_claim_holds_real_human_counterpart_pcr_until_body_handoff() {
    tokio::spawn(native_phase(||async {
        let fixture=native_phase(Fixture::new_with_second_device).await;
        let scope=ScopeRef::Realm {realm_id:fixture.realm.clone()};
        native_phase(||activate_mls(&fixture,scope.clone())).await;
        let namespace=format!("bridge.{}",uuid::Uuid::now_v7().simple());
        let native=mls_service(&fixture,&namespace);
        let install=native_phase(||fixture.install_package(true,native.package.clone(),&namespace)).await;
        let key=SigningKey::from_bytes(&[180;32]);
        let device=DeviceId::new(format!("ak:device:{}",uuid::Uuid::now_v7())).unwrap();
        let authority=native_phase(||authorize(&fixture,&install,&install.bot_body["managed_actor_bundle"],&namespace,&key,device,true)).await;
        let event=join_event(&fixture,&install,&authority,&key,&install.bot_outcome.authorization_ref);
        assert_eq!(native_phase(||post(&fixture,&authority,&key,&event,vec![])).await.0,StatusCode::OK);
        let _read=native_phase(||native_business_parent(&fixture,&install,vec![],vec!["ak.event.read".into()],None)).await;
        let human_key=SigningKey::from_bytes(&fixture.pcr.history.founding_device_signing_seed);
        let human=arkret_mls::ArkretMlsIdentity::new_human_device(ActorId::account(fixture.pcr.history.account.clone()),fixture.pcr.history.founding_device_id.clone(),arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(human_key.clone())).unwrap();
        let upload=fresh_upload(&human,fixture.pcr.history.device_verification_method.as_str(),&human_key,&scope);
        let value=serde_json::to_value(&upload).unwrap();
        let (status,outcome)=native_phase(||fixture.admin_post("/_arkret/self/keys/keypackages/upload",ServiceOperationId::SelfKeysKeypackagesUploadCreateV1.as_str(),&value,Some(&upload.keypackages[0].keypackage_id))).await;
        assert_eq!(status,StatusCode::OK,"{outcome}");assert_eq!(outcome["accepted"],1);
        let mut body=request(&authority,&key,&scope,&upload.keypackages[0].keypackage_ref);
        body.target_account_id=Some(fixture.pcr.history.account.clone());body.target_device_ids=vec![fixture.pcr.history.founding_device_id.clone()];resign(&mut body,&key);
        let mut metadata=managed_device_metadata(&authority);metadata.effective_scope=scope.clone();
        let mut response=native_phase(||async {managed_device_http_request_with_idempotency_at(&fixture.state,&authority,&metadata,ServiceOperationId::SelfKeysKeypackagesCommandClaimV1,&key,Some(arkret_canonical::canonical_json_bytes(&body).unwrap()),None,body.claim_request_id.as_str()).add_header("content-type","application/json",true).send(&service(fixture.state.clone())).await}).await;
        assert_eq!(response.status_code,Some(StatusCode::OK));
        let revocation=native_phase(||revoke_original_admin_device(&fixture));tokio::pin!(revocation);
        let deadline=tokio::time::Instant::now()+std::time::Duration::from_secs(3);
        loop {
            tokio::select! {
                _=&mut revocation=>panic!("counterpart revocation completed before material handoff"),
                _=tokio::time::sleep(std::time::Duration::from_millis(20))=>{}
            }
            #[derive(diesel::QueryableByName)]
            struct Waiting {#[diesel(sql_type=diesel::sql_types::Bool)] present:bool}
            let mut conn=fixture.pool.get().await.unwrap();
            let waiting=diesel::sql_query("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid<>pg_backend_pid() AND datname=current_database() AND usename=current_user AND wait_event_type='Lock' AND query ILIKE '%realm_authorities%' AND query ILIKE '%FOR UPDATE%') AS present").get_result::<Waiting>(&mut *conn).await.unwrap();drop(conn);
            if waiting.present {break;}
            assert!(tokio::time::Instant::now()<deadline,"actual Human PCR revocation must reach a blocked authoritative writer");
        }
        let received:arkret_models_crypto::KeyPackagesClaimOutcome=response.take_json().await.unwrap();assert_eq!(received.claims.len(),1);
        revocation.await;
        let before=native_phase(||snapshot(&fixture)).await;
        let (status,error)=native_phase(||claim(&fixture,&authority,&key,&scope,&body)).await;
        assert!(!status.is_success(),"old original target must not redeliver after actual revoke: {error}");
        assert_eq!(before,native_phase(||snapshot(&fixture)).await);
    })).await.unwrap();
}
