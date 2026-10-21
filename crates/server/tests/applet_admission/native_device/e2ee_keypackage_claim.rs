//! Real native requester and target, without a synthesized Session or account row.
use std::collections::BTreeSet;

use coland_storage::MlsKeyPackageStore as _;

use super::*;
#[path = "e2ee_keypackage_consume.rs"]
mod consume;

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
            StatusCode::OK
        );
        body["event"].clone()
    } else {
        install.bot_body["event"].clone()
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
    let event = join_event(&fixture, &install, &authority, &key, &install.join_grant());
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
    let identity = arkret_mls::ArkretMlsIdentity::new_realm_device(
        authority.actor_id.clone(),
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
    let (status, original_bytes) =
        native_phase(|| claim_wire(&fixture.state, &authority, &key, &scope, &body)).await;
    let outcome: Value = serde_json::from_slice(&original_bytes).unwrap();
    assert_eq!(
        status,
        StatusCode::OK,
        "native claim must use its actual requester and target instead of requiring a Session: {outcome}"
    );
    let outcome: arkret_models_crypto::KeyPackagesClaimOutcome =
        serde_json::from_value(outcome).unwrap();
    assert_eq!(outcome.claims.len(), 1);
    assert_eq!(outcome.claims[0].actor_id, authority.actor_id.clone());
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
    let (status, replay_bytes) =
        native_phase(|| claim_wire(&fixture.state, &authority, &key, &scope, &body)).await;
    let replay: Value = serde_json::from_slice(&replay_bytes).unwrap();
    assert_eq!(
        original_bytes, replay_bytes,
        "exact retry preserves the actual complete HTTP response bytes"
    );
    assert_eq!(status, StatusCode::OK, "{replay}");
    assert_eq!(
        accepted, replay,
        "exact retry keeps the original claim id and receipt"
    );
    assert_eq!(before, native_phase(|| snapshot(&fixture)).await);
    let mut changed = body.clone();
    changed.timeout_ms = Some(30000);
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

pub(in crate::native_device::e2ee) fn request(
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
        target_account_id: None,
        target_actor_id: Some(authority.actor_id.clone()),
        requester_account_id: None,
        requester_actor_id: Some(authority.actor_id.clone()),
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
            source_id: authority.governance_service_id.clone(),
            destination_id: authority.governance_service_id.clone(),
        },
        requester_authorization:
            arkret_models_crypto::PeerKeyPackageRequesterAuthorization::RealmDevice {
                verification_method: arkret_wire::DidUrl::new(method.clone()).unwrap(),
                requester_device_id: authority.device_id.clone(),
                device_authorize_event_id: authority.authorization_ref.event_id.clone(),
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

pub(in crate::native_device::e2ee) fn account_requester(
    fixture: &Fixture,
    body: &mut arkret_models_crypto::KeyPackagesClaimRequestBody,
) {
    let method = fixture.pcr.history.device_verification_method.clone();
    body.requester_actor_id = None;
    body.requester_account_id = Some(fixture.pcr.history.account.clone());
    body.requester_authorization =
        arkret_models_crypto::PeerKeyPackageRequesterAuthorization::Device {
            verification_method: method.clone(),
            requester_device_id: fixture.pcr.history.founding_device_id.clone(),
            device_authorize_event_id: fixture.pcr.history.events[1].event_id.clone(),
            signed_at: arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
            signature: arkret_signatures::keypackages::keypackage_signature_from_bytes(
                method.as_str(),
                &[0; 64],
            )
            .unwrap(),
        };
}

pub(in crate::native_device::e2ee) fn resign(
    body: &mut arkret_models_crypto::KeyPackagesClaimRequestBody,
    key: &SigningKey,
) {
    let method = match &body.requester_authorization {
        arkret_models_crypto::PeerKeyPackageRequesterAuthorization::Device {
            verification_method,
            ..
        }
        | arkret_models_crypto::PeerKeyPackageRequesterAuthorization::RealmDevice {
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
    let (arkret_models_crypto::PeerKeyPackageRequesterAuthorization::Device { signature, .. }
    | arkret_models_crypto::PeerKeyPackageRequesterAuthorization::RealmDevice {
        signature, ..
    }) = &mut body.requester_authorization
    else {
        unreachable!()
    };
    *signature = arkret_signatures::keypackages::keypackage_signature_from_bytes(
        &method,
        &key.sign(&input).to_bytes(),
    )
    .unwrap();
}

pub(in crate::native_device::e2ee) async fn claim(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    scope: &ScopeRef,
    body: &arkret_models_crypto::KeyPackagesClaimRequestBody,
) -> (StatusCode, Value) {
    claim_at(&fixture.state, authority, key, scope, body).await
}

async fn claim_at(
    state: &AppState,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    scope: &ScopeRef,
    body: &arkret_models_crypto::KeyPackagesClaimRequestBody,
) -> (StatusCode, Value) {
    let (status, bytes) = claim_wire(state, authority, key, scope, body).await;
    (status, serde_json::from_slice(&bytes).unwrap())
}

async fn claim_wire(
    state: &AppState,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    scope: &ScopeRef,
    body: &arkret_models_crypto::KeyPackagesClaimRequestBody,
) -> (StatusCode, Vec<u8>) {
    let mut metadata = managed_device_metadata(authority);
    metadata.effective_scope = scope.clone();
    let mut response = managed_device_http_request_with_idempotency_at(
        state,
        authority,
        &metadata,
        ServiceOperationId::SelfKeysKeypackagesCommandClaimV1,
        key,
        Some(arkret_canonical::canonical_json_bytes(body).unwrap()),
        None,
        body.claim_request_id.as_str(),
    )
    .add_header("content-type", "application/json", true)
    .send(&service(state.clone()))
    .await;
    (
        response.status_code.unwrap(),
        response.take_bytes(None).await.unwrap().to_vec(),
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
    body.requester_actor_id = None;
    body.requester_account_id = Some(fixture.pcr.history.account.clone());
    account_requester(&fixture, &mut body);
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
        serde_json::to_value(authority.actor_id.clone()).unwrap()
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
    body.target_actor_id = None;
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
        let extras=["ak.applet.join","ak.applet.publish","ak.message.create","ak.applet.bot.provision","ak.applet.ghost.provision"].into_iter().map(|action|(action.to_owned(),vec![temporal.clone()])).collect();
        let (package,outcome,body,install_key)=native_phase(||fixture.install_service_with_constraints(true,native.package.clone(),scope.clone(),extras)).await;
        let (bot_outcome, bot_body)=native_phase(||fixture.provision_bot_in_scope(&package,&namespace,outcome.registration_event_ref.clone(),scope.clone())).await;
        let install=Installed { package, outcome, bot: bot_outcome, join_grant: installation_grant(&body,"ak.applet.join"), bot_body, body, key:install_key };
        let key=SigningKey::from_bytes(&[176;32]);
        let device=DeviceId::new(format!("ak:device:{}",uuid::Uuid::now_v7())).unwrap();
        let authority=native_phase(||authorize(&fixture,&install,&install.bot_body["event"],&namespace,&key,device,true)).await;
        let event=join_event(&fixture,&install,&authority,&key,&install.join_grant());
        let (status,outcome)=native_phase(||post(&fixture,&authority,&key,&event,vec![])).await;
        assert_eq!(status,StatusCode::OK,"original finite consent is initially live: {outcome}");
        let _read_parent=native_phase(||native_business_parent(&fixture,&install,vec![],vec!["ak.event.read".into()],None)).await;
        let identity=arkret_mls::ArkretMlsIdentity::new_realm_device(authority.actor_id.clone(),authority.device_id.clone(),arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(key.clone())).unwrap();
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
            StatusCode::OK
        );
        body["event"].clone()
    } else {
        install.bot_body["event"].clone()
    };
    let key = SigningKey::from_bytes(&[179; 32]);
    let device = DeviceId::new(format!("ak:device:{}", uuid::Uuid::now_v7())).unwrap();
    let original =
        native_phase(|| authorize(&fixture, &install, &bundle, &namespace, &key, device, true))
            .await;
    let event = join_event(&fixture, &install, &original, &key, &install.join_grant());
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
    let identity = arkret_mls::ArkretMlsIdentity::new_realm_device(
        authority.actor_id.clone(),
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
    if let arkret_models_crypto::PeerKeyPackageRequesterAuthorization::RealmDevice {
        device_authorize_event_id,
        ..
    } = &mut bad.requester_authorization
    {
        *device_authorize_event_id = original.authorization_ref.event_id.clone();
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
    let query = arkret_models_crypto::KeyPackagesClaimQueryRequestBody {
        claim_id: arkret_wire::KeypackageClaimId::new(
            outcome["claims"][0]["claim_id"]
                .as_str()
                .unwrap()
                .to_owned(),
        )
        .unwrap(),
    };
    let before = native_phase(|| snapshot(&fixture)).await;
    let (status, bytes) =
        native_phase(|| query_wire(&fixture.state, &authority, &key, &scope, &query)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        arkret_canonical::canonical_json_bytes(&outcome).unwrap(),
        bytes
    );
    let (status, bytes) =
        native_phase(|| query_wire(&fixture.state, &authority, &key, &realm, &query)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let error: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        error["type"],
        "https://arkret.org/problems/keypackage_unknown"
    );
    assert_eq!(before, native_phase(|| snapshot(&fixture)).await);
    native_phase(|| fixture.revoke(&install)).await;
    let before = native_phase(|| snapshot(&fixture)).await;
    let (status, bytes) =
        native_phase(|| query_wire(&fixture.state, &authority, &key, &scope, &query)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "Realm A fence must preserve Circle B owner read"
    );
    assert_eq!(
        arkret_canonical::canonical_json_bytes(&outcome).unwrap(),
        bytes
    );
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
        let authority=native_phase(||authorize(&fixture,&install,&install.bot_body["event"],&namespace,&key,device,true)).await;
        let event=join_event(&fixture,&install,&authority,&key,&install.join_grant());
        assert_eq!(native_phase(||post(&fixture,&authority,&key,&event,vec![])).await.0,StatusCode::OK);
        let _read=native_phase(||native_business_parent(&fixture,&install,vec![],vec!["ak.event.read".into()],None)).await;
        let human_key=SigningKey::from_bytes(&fixture.pcr.history.founding_device_signing_seed);
        let human=arkret_mls::ArkretMlsIdentity::new_human_device(ActorId::account(fixture.pcr.history.account.clone()),fixture.pcr.history.founding_device_id.clone(),arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(human_key.clone())).unwrap();
        let upload=fresh_upload(&human,fixture.pcr.history.device_verification_method.as_str(),&human_key,&scope);
        let value=serde_json::to_value(&upload).unwrap();
        let (status,outcome)=native_phase(||fixture.admin_post("/_arkret/self/keys/keypackages/upload",ServiceOperationId::SelfKeysKeypackagesUploadCreateV1.as_str(),&value,Some(&upload.keypackages[0].keypackage_id))).await;
        assert_eq!(status,StatusCode::OK,"{outcome}");assert_eq!(outcome["accepted"],1);
        let mut body=request(&authority,&key,&scope,&upload.keypackages[0].keypackage_ref);
        body.target_actor_id = None;
    body.target_account_id = Some(fixture.pcr.history.account.clone());body.target_device_ids=vec![fixture.pcr.history.founding_device_id.clone()];resign(&mut body,&key);
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_claim_budget_is_shared_by_independent_station_workers() {
    for ghost in [false, true] {
        tokio::spawn(native_phase(|| exercise_worker_budget(ghost)))
            .await
            .unwrap();
    }
}

async fn exercise_worker_budget(ghost: bool) {
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
            StatusCode::OK
        );
        body["event"].clone()
    } else {
        install.bot_body["event"].clone()
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
    let event = join_event(&fixture, &install, &authority, &key, &install.join_grant());
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
    let identity = arkret_mls::ArkretMlsIdentity::new_realm_device(
        authority.actor_id.clone(),
        device,
        arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(key.clone()),
    )
    .unwrap();
    let fingerprint =
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(key.verifying_key().as_bytes());
    let method = format!("did:key:{fingerprint}#{fingerprint}");

    let mut uploads = Vec::new();
    for _ in 0..6 {
        let body = fresh_upload(&identity, &method, &key, &scope);
        let (status, outcome) =
            native_phase(|| upload_in_scope(&fixture, &authority, &key, &body, &scope)).await;
        assert_eq!(status, StatusCode::OK, "fresh actual package: {outcome}");
        assert_eq!(outcome["accepted"], 1);
        uploads.push(body);
    }
    // Both workers use the same durable identity and ordinary startup hydration.
    // No package cache is cleared or populated by a test-only back door.
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
    assert_eq!(fixture.state.service_core_id(), reopened.service_core_id());
    let source_id = fixture.state.service_core_id();
    let store = coland_storage_postgres::PgMlsKeyPackageStore {
        pool: fixture.pool.clone(),
    };
    let mut accepted = Vec::new();
    let mut bodies = Vec::new();
    for (index, upload) in uploads.iter().enumerate() {
        let body = request(
            &authority,
            &key,
            &scope,
            upload.keypackages[0].keypackage_ref.as_str(),
        );
        let state = if index % 2 == 0 {
            &fixture.state
        } else {
            &reopened
        };
        let (status, outcome) =
            native_phase(|| claim_at(state, &authority, &key, &scope, &body)).await;
        if index < 5 {
            assert_eq!(status, StatusCode::OK, "attempt {index}: {outcome}");
            accepted.push(outcome);
        } else {
            assert!(
                !status.is_success(),
                "six real native claims across two independent workers must share the five-attempt Station budget, got {status}: {outcome}"
            );
            let package =
                native_phase(|| store.get_by_ref(upload.keypackages[0].keypackage_ref.as_str()))
                    .await
                    .unwrap()
                    .unwrap();
            assert!(
                package.claimed_by_mls_group_id.is_none(),
                "quota rejection cannot claim the sixth package"
            );
            let ledger = native_phase(|| {
                store.get_peer_claim(source_id.as_str(), body.claim_request_id.as_str())
            })
            .await
            .unwrap()
            .unwrap();
            assert_eq!(ledger.state, "claim_failed");
            assert!(ledger.keypackage_id.is_none() && ledger.outcome.is_none());
        }
        bodies.push(body);
    }
    let before = native_phase(|| snapshot(&fixture)).await;
    let (status, replay) =
        native_phase(|| claim_at(&reopened, &authority, &key, &scope, &bodies[0])).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "accepted retry after quota: {replay}"
    );
    assert_eq!(
        replay, accepted[0],
        "retry preserves the first original receipt"
    );
    let (status, error) =
        native_phase(|| claim_at(&fixture.state, &authority, &key, &scope, &bodies[5])).await;
    assert!(
        !status.is_success(),
        "denied original attempt cannot get a second decision: {error}"
    );
    assert_eq!(
        before,
        native_phase(|| snapshot(&fixture)).await,
        "both exact retries leave all business rows and projections unchanged"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_worker_started_before_publication_claims_the_actual_durable_package() {
    for ghost in [false, true] {
        tokio::spawn(native_phase(|| exercise_fresh_publication(ghost)))
            .await
            .unwrap();
    }
}
async fn exercise_fresh_publication(ghost: bool) {
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
            StatusCode::OK
        );
        body["event"].clone()
    } else {
        install.bot_body["event"].clone()
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
    let event = join_event(&fixture, &install, &authority, &key, &install.join_grant());
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
    let identity = arkret_mls::ArkretMlsIdentity::new_realm_device(
        authority.actor_id.clone(),
        device,
        arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(key.clone()),
    )
    .unwrap();
    let fingerprint =
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(key.verifying_key().as_bytes());
    let method = format!("did:key:{fingerprint}#{fingerprint}");

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
    assert_eq!(fixture.state.service_core_id(), reopened.service_core_id());
    // Publication happens strictly after this independent worker's ordinary
    // startup. No cache is cleared, copied, refreshed or seeded for the test.
    let upload = fresh_upload(&identity, &method, &key, &scope);
    let (status, outcome) =
        native_phase(|| upload_in_scope(&fixture, &authority, &key, &upload, &scope)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "actual later publication: {outcome}"
    );
    assert_eq!(outcome["accepted"], 1);
    let store = coland_storage_postgres::PgMlsKeyPackageStore {
        pool: fixture.pool.clone(),
    };
    let reference = upload.keypackages[0].keypackage_ref.as_str();
    let row = native_phase(|| store.get_by_ref(reference))
        .await
        .unwrap()
        .unwrap();
    assert!(row.claimed_by_mls_group_id.is_none());
    let body = request(&authority, &key, &scope, reference);
    let (status, original) =
        native_phase(|| claim_wire(&reopened, &authority, &key, &scope, &body)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an already-running independent worker must claim the actual fresh durable publication without cache injection: {}",
        String::from_utf8_lossy(&original)
    );
    let outcome: arkret_models_crypto::KeyPackagesClaimOutcome =
        serde_json::from_slice(&original).unwrap();
    assert_eq!(outcome.claims.len(), 1);
    assert_eq!(outcome.claims[0].keypackage_ref.as_str(), reference);
    let (status, replay) =
        native_phase(|| claim_wire(&fixture.state, &authority, &key, &scope, &body)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        original, replay,
        "the publisher worker recovers the same accepted bytes"
    );
    native_phase(|| {
        fresh_unqualified_claim(
            &fixture, &reopened, &authority, &key, &scope, &identity, &method,
        )
    })
    .await;
}

async fn fresh_unqualified_claim(
    fixture: &Fixture,
    reopened: &AppState,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    scope: &ScopeRef,
    identity: &arkret_mls::ArkretMlsIdentity,
    method: &str,
) {
    let upload = fresh_upload(identity, method, key, scope);
    let (status, outcome) =
        native_phase(|| upload_in_scope(fixture, authority, key, &upload, scope)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "second actual publication: {outcome}"
    );
    let reference = upload.keypackages[0].keypackage_ref.as_str();
    let store = coland_storage_postgres::PgMlsKeyPackageStore {
        pool: fixture.pool.clone(),
    };
    let mut body = request(authority, key, scope, reference);
    // Selection isolation is checked on the real published row. These reads
    // do not assert that the altered target has accepted any authority.
    let mut wrong = body.clone();
    let target = wrong
        .target_actor_id
        .as_ref()
        .unwrap()
        .as_realm_actor_id()
        .unwrap();
    wrong.target_actor_id = Some(ActorId::realm(arkret_wire::RealmActorId {
        realm_id: RealmId::from_event_id(&fixture.pcr.unit.transactions[1].event.event_id),
        principal_id: target.principal_id.clone(),
    }));
    resign(&mut wrong, key);
    let peer = arkret_models_crypto::PeerKeyPackagesClaimRequestBody::from(&wrong);
    assert!(peer.validate_shape().is_err());
    assert!(
        native_phase(|| store.peer_claim_candidates(&peer))
            .await
            .is_err()
    );
    // A well-formed, distinct Realm principal still cannot select this row.
    wrong.target_actor_id = Some(ActorId::realm(arkret_wire::RealmActorId {
        realm_id: authority.realm_id.clone(),
        principal_id: fixture.state.service_core_id(),
    }));
    resign(&mut wrong, key);
    let peer = arkret_models_crypto::PeerKeyPackagesClaimRequestBody::from(&wrong);
    peer.validate_shape().unwrap();
    assert!(
        native_phase(|| store.peer_claim_candidates(&peer))
            .await
            .unwrap()
            .is_empty()
    );
    let missing = fresh_upload(identity, method, key, scope);
    let missing_body = request(
        authority,
        key,
        scope,
        &missing.keypackages[0].keypackage_ref,
    );
    let (status, _) =
        native_phase(|| claim_wire(reopened, authority, key, scope, &missing_body)).await;
    assert!(
        !status.is_success(),
        "an unknown exact reference cannot select another package"
    );
    assert!(
        native_phase(|| store.get_by_ref(reference))
            .await
            .unwrap()
            .unwrap()
            .claimed_by_mls_group_id
            .is_none()
    );
    body.target_keypackage_ref = None;
    resign(&mut body, key);
    let (status, original) =
        native_phase(|| claim_wire(reopened, authority, key, scope, &body)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "unqualified fresh publication: {}",
        String::from_utf8_lossy(&original)
    );
    let outcome: arkret_models_crypto::KeyPackagesClaimOutcome =
        serde_json::from_slice(&original).unwrap();
    assert_eq!(outcome.claims.len(), 1);
    assert_eq!(outcome.claims[0].keypackage_ref.as_str(), reference);
    let (status, replay) =
        native_phase(|| claim_wire(&fixture.state, authority, key, scope, &body)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(original, replay);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_claim_owner_reads_original_outcome_without_session() {
    for ghost in [false, true] {
        tokio::spawn(native_phase(|| own_claim_read(ghost)))
            .await
            .unwrap();
    }
}
async fn own_claim_read(ghost: bool) {
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
            StatusCode::OK
        );
        body["event"].clone()
    } else {
        install.bot_body["event"].clone()
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
    let event = join_event(&fixture, &install, &authority, &key, &install.join_grant());
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
    let identity = arkret_mls::ArkretMlsIdentity::new_realm_device(
        authority.actor_id.clone(),
        device,
        arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(key.clone()),
    )
    .unwrap();
    let fingerprint =
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(key.verifying_key().as_bytes());
    let method = format!("did:key:{fingerprint}#{fingerprint}");

    let upload = fresh_upload(&identity, &method, &key, &scope);
    assert_eq!(
        native_phase(|| upload_in_scope(&fixture, &authority, &key, &upload, &scope))
            .await
            .0,
        StatusCode::OK
    );
    let body = request(
        &authority,
        &key,
        &scope,
        &upload.keypackages[0].keypackage_ref,
    );
    let (status, original) =
        native_phase(|| claim_wire(&fixture.state, &authority, &key, &scope, &body)).await;
    assert_eq!(status, StatusCode::OK);
    let outcome: arkret_models_crypto::KeyPackagesClaimOutcome =
        serde_json::from_slice(&original).unwrap();
    let query = arkret_models_crypto::KeyPackagesClaimQueryRequestBody {
        claim_id: arkret_wire::KeypackageClaimId::new(outcome.claims[0].claim_id.clone()).unwrap(),
    };
    let before = native_phase(|| snapshot(&fixture)).await;
    let (status, bytes) =
        native_phase(|| query_wire(&fixture.state, &authority, &key, &scope, &query)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "true native owner must read its original claim without a Session: {}",
        String::from_utf8_lossy(&bytes)
    );
    assert_eq!(
        original, bytes,
        "claim read must retain the original complete response bytes"
    );
    assert_eq!(
        before,
        native_phase(|| snapshot(&fixture)).await,
        "read does not mutate package or ledger"
    );
    let unknown = arkret_models_crypto::KeyPackagesClaimQueryRequestBody {
        claim_id: arkret_wire::KeypackageClaimId::new(format!(
            "ak:keypackage_claim:{}",
            uuid::Uuid::now_v7()
        ))
        .unwrap(),
    };
    let (status, error) =
        native_phase(|| query_wire(&fixture.state, &authority, &key, &scope, &unknown)).await;
    let error: Value = serde_json::from_slice(&error).unwrap();
    assert!(!status.is_success());
    assert_eq!(
        error["type"],
        "https://arkret.org/problems/keypackage_unknown"
    );
    assert_eq!(before, native_phase(|| snapshot(&fixture)).await);
    let other_key = SigningKey::from_bytes(&[182; 32]);
    let other = native_phase(|| {
        authorize(
            &fixture,
            &install,
            &bundle,
            &namespace,
            &other_key,
            DeviceId::new(format!("ak:device:{}", uuid::Uuid::now_v7())).unwrap(),
            true,
        )
    })
    .await;
    let before = native_phase(|| snapshot(&fixture)).await;
    let (status, bytes) =
        native_phase(|| query_wire(&fixture.state, &other, &other_key, &scope, &query)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let error: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        error["type"],
        "https://arkret.org/problems/keypackage_unknown"
    );
    assert_eq!(before, native_phase(|| snapshot(&fixture)).await);
    let (status, bytes) =
        native_phase(|| query_wire(&fixture.state, &authority, &key, &scope, &query)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        original, bytes,
        "adding another genuine Device does not replace the original Device"
    );
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
    let (status, bytes) =
        native_phase(|| query_wire(&reopened, &authority, &key, &scope, &query)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        original, bytes,
        "cold owner read uses genuine durable authority"
    );
    native_phase(|| {
        revoked_package_read(
            &fixture,
            &install.package,
            &authority,
            &key,
            &scope,
            &identity,
            &method,
        )
    })
    .await;
    let (status, bytes) =
        native_phase(|| query_wire(&fixture.state, &authority, &key, &scope, &query)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        original, bytes,
        "revoking a separate package does not revoke this original claim"
    );
    native_phase(|| fixture.revoke(&install)).await;
    let before = native_phase(|| snapshot(&fixture)).await;
    let (status, error) =
        native_phase(|| query_wire(&fixture.state, &authority, &key, &scope, &query)).await;
    let error: Value = serde_json::from_slice(&error).unwrap();
    assert!(!status.is_success());
    assert_eq!(
        error["type"],
        "https://arkret.org/problems/keypackage_unknown"
    );
    assert_eq!(before, native_phase(|| snapshot(&fixture)).await);
}
async fn query_wire(
    state: &AppState,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    scope: &ScopeRef,
    body: &arkret_models_crypto::KeyPackagesClaimQueryRequestBody,
) -> (StatusCode, Vec<u8>) {
    let mut metadata = managed_device_metadata(authority);
    metadata.effective_scope = scope.clone();
    let mut response = managed_device_http_request_with_idempotency_at(
        state,
        authority,
        &metadata,
        ServiceOperationId::SelfKeysKeypackagesReadClaimV1,
        key,
        Some(arkret_canonical::canonical_json_bytes(body).unwrap()),
        None,
        &format!("native-claim-read-{}", uuid::Uuid::now_v7()),
    )
    .add_header("content-type", "application/json", true)
    .send(&service(state.clone()))
    .await;
    (
        response.status_code.unwrap(),
        response.take_bytes(None).await.unwrap().to_vec(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn query_consent_expiry_blocks_already_prepared_original_outcome_at_handoff() {
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
        let extras=["ak.applet.join","ak.applet.publish","ak.message.create","ak.applet.bot.provision","ak.applet.ghost.provision"].into_iter().map(|action|(action.to_owned(),vec![temporal.clone()])).collect();
        let (package,outcome,body,install_key)=native_phase(||fixture.install_service_with_constraints(true,native.package.clone(),scope.clone(),extras)).await;
        let (bot_outcome, bot_body)=native_phase(||fixture.provision_bot_in_scope(&package,&namespace,outcome.registration_event_ref.clone(),scope.clone())).await;
        let install=Installed { package, outcome, bot: bot_outcome, join_grant: installation_grant(&body,"ak.applet.join"), bot_body, body, key:install_key };
        let key=SigningKey::from_bytes(&[176;32]);
        let device=DeviceId::new(format!("ak:device:{}",uuid::Uuid::now_v7())).unwrap();
        let authority=native_phase(||authorize(&fixture,&install,&install.bot_body["event"],&namespace,&key,device,true)).await;
        let event=join_event(&fixture,&install,&authority,&key,&install.join_grant());
        let (status,outcome)=native_phase(||post(&fixture,&authority,&key,&event,vec![])).await;
        assert_eq!(status,StatusCode::OK,"original finite consent is initially live: {outcome}");
        let _read_parent=native_phase(||native_business_parent(&fixture,&install,vec![],vec!["ak.event.read".into()],None)).await;
        let identity=arkret_mls::ArkretMlsIdentity::new_realm_device(authority.actor_id.clone(),authority.device_id.clone(),arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(key.clone())).unwrap();
        let fingerprint=arkret_canonical::ed25519_pubkey_to_did_key_multibase(key.verifying_key().as_bytes());
        let upload=fresh_upload(&identity,&format!("did:key:{fingerprint}#{fingerprint}"),&key,&scope);
        assert_eq!(native_phase(||upload_in_scope(&fixture,&authority,&key,&upload,&scope)).await.0,StatusCode::OK);
        let command=request(&authority,&key,&scope,&upload.keypackages[0].keypackage_ref);
        let (status,bytes)=native_phase(||claim_wire(&fixture.state,&authority,&key,&scope,&command)).await;
        assert_eq!(status,StatusCode::OK);
        let original:arkret_models_crypto::KeyPackagesClaimOutcome=serde_json::from_slice(&bytes).unwrap();
        let body=arkret_models_crypto::KeyPackagesClaimQueryRequestBody {claim_id:arkret_wire::KeypackageClaimId::new(original.claims[0].claim_id.clone()).unwrap()};
        let mut metadata=managed_device_metadata(&authority);metadata.effective_scope=scope.clone();
        let mut response=native_phase(||async {managed_device_http_request_with_idempotency_at(&fixture.state,&authority,&metadata,ServiceOperationId::SelfKeysKeypackagesReadClaimV1,&key,Some(arkret_canonical::canonical_json_bytes(&body).unwrap()),None,command.claim_request_id.as_str()).add_header("content-type","application/json",true).send(&service(fixture.state.clone())).await}).await;
        assert_eq!(response.status_code,Some(StatusCode::OK),"query must prepare original material before expiry");
        let before=native_phase(||snapshot(&fixture)).await;
        let remaining=(deadline-chrono::Utc::now()).to_std().unwrap_or_default();
        tokio::time::sleep(remaining+std::time::Duration::from_millis(100)).await;
        assert!(response.take_json::<Value>().await.is_err(),"expired original E2EE consent cannot hand off prepared bytes while a separate read parent remains active");
        assert_eq!(before,native_phase(||snapshot(&fixture)).await);
        let (status,error)=native_phase(||query_wire(&fixture.state,&authority,&key,&scope,&body)).await;
        assert!(!status.is_success(),"expired current consent cannot expose original claim: {error:?}");
        assert_eq!(before,native_phase(||snapshot(&fixture)).await);
    })).await.unwrap();
}

async fn revoked_package_read(
    fixture: &Fixture,
    package: &AppletPackage,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    scope: &ScopeRef,
    identity: &arkret_mls::ArkretMlsIdentity,
    method: &str,
) {
    let upload = fresh_upload(identity, method, key, scope);
    assert_eq!(
        native_phase(|| upload_in_scope(fixture, authority, key, &upload, scope))
            .await
            .0,
        StatusCode::OK
    );
    let command = request(authority, key, scope, &upload.keypackages[0].keypackage_ref);
    let (status, bytes) =
        native_phase(|| claim_wire(&fixture.state, authority, key, scope, &command)).await;
    assert_eq!(status, StatusCode::OK);
    let outcome: arkret_models_crypto::KeyPackagesClaimOutcome =
        serde_json::from_slice(&bytes).unwrap();
    let original_outcome = outcome.clone();
    let query = arkret_models_crypto::KeyPackagesClaimQueryRequestBody {
        claim_id: arkret_wire::KeypackageClaimId::new(outcome.claims[0].claim_id.clone()).unwrap(),
    };
    let unsigned = arkret_models_crypto::KeyPackagesRevokeUnsignedRequest {
        key_package_refs: vec![upload.keypackages[0].keypackage_ref.clone()],
        device_id: authority.device_id.clone(),
        reason: None,
    };
    let signature = arkret_signatures::keypackages::sign_keypackages_revoke_request(
        &unsigned,
        method,
        &key.to_bytes(),
    )
    .unwrap();
    let revoke = unsigned.into_signed(signature);
    let mut metadata = managed_device_metadata(authority);
    metadata.effective_scope = scope.clone();
    let mut response = native_phase(|| async {
        managed_device_http_request_body(
            &fixture.state,
            authority,
            &metadata,
            ServiceOperationId::SelfKeysKeypackagesCommandRevokeV1,
            key,
            Some(arkret_canonical::canonical_json_bytes(&revoke).unwrap()),
        )
        .add_header("content-type", "application/json", true)
        .send(&service(fixture.state.clone()))
        .await
    })
    .await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    let outcome: arkret_models_crypto::KeyPackagesRevokeOutcome =
        response.take_json().await.unwrap();
    assert_eq!(outcome.revoked, revoke.key_package_refs);
    let before = native_phase(|| snapshot(fixture)).await;
    let (status, bytes) =
        native_phase(|| query_wire(&fixture.state, authority, key, scope, &query)).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "an actually revoked package must not be returned from its old immutable outcome: {}",
        String::from_utf8_lossy(&bytes)
    );
    let error: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        error["type"],
        "https://arkret.org/problems/keypackage_unknown"
    );
    assert_eq!(before, native_phase(|| snapshot(fixture)).await);
    native_phase(|| {
        stored_recovery_delivery(
            fixture,
            package,
            authority,
            scope,
            &original_outcome,
            &command,
        )
    })
    .await;
    assert_eq!(before, native_phase(|| snapshot(fixture)).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn query_claim_deadline_blocks_original_outcome_before_background_cleanup() {
    tokio::spawn(native_phase(|| async {
        use arkret_models_collaboration::governance::grant_constraint::{
            GrantConstraintEffect, GrantConstraintKind,
        };
        let fixture = native_phase(Fixture::new).await;
        let scope = ScopeRef::Realm {
            realm_id: fixture.realm.clone(),
        };
        native_phase(|| activate_mls(&fixture, scope.clone())).await;
        let namespace = format!("bridge.{}", uuid::Uuid::now_v7().simple());
        let native = mls_service(&fixture, &namespace);
        let deadline = arkret_canonical::normalize_timestamp_canonical(
            chrono::Utc::now() + chrono::Duration::seconds(30),
        );
        let mut temporal =
            GrantConstraint::new(GrantConstraintKind::Temporal, GrantConstraintEffect::Allow);
        temporal.expires_at = Some(deadline);
        let extras = [
            "ak.message.create",
            "ak.applet.bot.provision",
            "ak.applet.ghost.provision",
        ]
        .into_iter()
        .map(|action| (action.to_owned(), vec![temporal.clone()]))
        .collect();
        let (package, outcome, body, install_key) = native_phase(|| {
            fixture.install_service_with_constraints(
                true,
                native.package.clone(),
                scope.clone(),
                extras,
            )
        })
        .await;
        let (bot_outcome, bot_body) = native_phase(|| {
            fixture.provision_bot_in_scope(
                &package,
                &namespace,
                outcome.registration_event_ref.clone(),
                scope.clone(),
            )
        })
        .await;
        let install = Installed {
            package,
            outcome,
            bot: bot_outcome,
            join_grant: installation_grant(&body, "ak.applet.join"),
            bot_body,
            body,
            key: install_key,
        };
        let key = SigningKey::from_bytes(&[176; 32]);
        let device = DeviceId::new(format!("ak:device:{}", uuid::Uuid::now_v7())).unwrap();
        let authority = native_phase(|| {
            authorize(
                &fixture,
                &install,
                &install.bot_body["event"],
                &namespace,
                &key,
                device,
                true,
            )
        })
        .await;
        let event = join_event(&fixture, &install, &authority, &key, &install.join_grant());
        let (status, outcome) =
            native_phase(|| post(&fixture, &authority, &key, &event, vec![])).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "original finite consent is initially live: {outcome}"
        );
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
        let identity = arkret_mls::ArkretMlsIdentity::new_realm_device(
            authority.actor_id.clone(),
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
        assert_eq!(
            native_phase(|| upload_in_scope(&fixture, &authority, &key, &upload, &scope))
                .await
                .0,
            StatusCode::OK
        );
        let mut command = request(
            &authority,
            &key,
            &scope,
            &upload.keypackages[0].keypackage_ref,
        );
        command.expires_at = arkret_canonical::normalize_timestamp_canonical(
            chrono::Utc::now() + chrono::Duration::seconds(5),
        );
        resign(&mut command, &key);
        let (status, bytes) =
            native_phase(|| claim_wire(&fixture.state, &authority, &key, &scope, &command)).await;
        assert_eq!(status, StatusCode::OK);
        let original: arkret_models_crypto::KeyPackagesClaimOutcome =
            serde_json::from_slice(&bytes).unwrap();
        let body = arkret_models_crypto::KeyPackagesClaimQueryRequestBody {
            claim_id: arkret_wire::KeypackageClaimId::new(original.claims[0].claim_id.clone())
                .unwrap(),
        };
        let mut metadata = managed_device_metadata(&authority);
        metadata.effective_scope = scope.clone();
        let mut response = native_phase(|| async {
            managed_device_http_request_with_idempotency_at(
                &fixture.state,
                &authority,
                &metadata,
                ServiceOperationId::SelfKeysKeypackagesReadClaimV1,
                &key,
                Some(arkret_canonical::canonical_json_bytes(&body).unwrap()),
                None,
                command.claim_request_id.as_str(),
            )
            .add_header("content-type", "application/json", true)
            .send(&service(fixture.state.clone()))
            .await
        })
        .await;
        assert_eq!(
            response.status_code,
            Some(StatusCode::OK),
            "query must prepare original material before expiry"
        );
        let before = native_phase(|| snapshot(&fixture)).await;
        let remaining = (command.expires_at - chrono::Utc::now())
            .to_std()
            .unwrap_or_default();
        tokio::time::sleep(remaining + std::time::Duration::from_millis(100)).await;
        assert!(
            response.take_json::<Value>().await.is_err(),
            "expired original claim cannot hand off prepared material before background cleanup"
        );
        assert_eq!(before, native_phase(|| snapshot(&fixture)).await);
        let (status, error) =
            native_phase(|| query_wire(&fixture.state, &authority, &key, &scope, &body)).await;
        assert!(
            !status.is_success(),
            "expired original claim cannot expose material: {error:?}"
        );
        assert_eq!(before, native_phase(|| snapshot(&fixture)).await);
        assert!(
            chrono::Utc::now() < deadline,
            "independent original E2EE consent must still be live"
        );
        let store = coland_storage_postgres::PgMlsKeyPackageStore {
            pool: fixture.pool.clone(),
        };
        let expired = native_phase(|| {
            store.revoke_expired_peer_claims(chrono::Utc::now().timestamp_millis())
        })
        .await
        .unwrap();
        assert_eq!(expired, vec![upload.keypackages[0].keypackage_id.clone()]);
        let ledger = native_phase(|| {
            store.get_peer_claim(
                fixture.state.service_id(),
                command.claim_request_id.as_str(),
            )
        })
        .await
        .unwrap()
        .unwrap();
        assert_eq!(ledger.state, "revoked");
        native_phase(|| {
            stored_recovery_delivery(
                &fixture,
                &install.package,
                &authority,
                &scope,
                &original,
                &command,
            )
        })
        .await;
    }))
    .await
    .unwrap();
}

// This exercises the accepting delivery consumer with actual native authority,
// signed outcome, package and ledger. It does not claim that a local self claim
// can be queried through the cross-Station peer HTTP transport.
async fn stored_recovery_delivery(
    fixture: &Fixture,
    package: &AppletPackage,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    scope: &ScopeRef,
    outcome: &arkret_models_crypto::KeyPackagesClaimOutcome,
    command: &arkret_models_crypto::KeyPackagesClaimRequestBody,
) {
    let endpoint = coland_storage::AppletManagedDeviceScopeGuard {
        authority: authority.clone(),
        effective_scope: scope.clone(),
        service_did_document: applet_service_id_document(package),
    };
    let outcome = arkret_models_crypto::PeerKeyPackagesClaimOutcome {
        claim_request_id: outcome.claim_request_id.clone(),
        claims: outcome.claims.clone(),
        claim_receipt: outcome.claim_receipt.clone(),
    };
    for operation in [
        ServiceOperationId::PeerKeysKeypackagesReadClaimV1,
        ServiceOperationId::PeerKeysKeypackagesCommandClaimV1,
    ] {
        let input = coland_storage::AccountContentDeliveryInput {
            realms: vec![scope.realm_id().clone()],
            keypackage_claims: vec![coland_storage::MlsKeyPackageClaimDelivery {
                operation,
                outcome: outcome.clone(),
                endpoints: vec![endpoint.clone()],
                remote_devices: Vec::new(),
                command: (operation == ServiceOperationId::PeerKeysKeypackagesCommandClaimV1)
                    .then(|| arkret_models_crypto::PeerKeyPackagesClaimRequestBody::from(command)),
            }],
            applet_endpoint: Some(endpoint.clone()),
            credential_expires_at: Some(chrono::Utc::now() + chrono::Duration::seconds(10)),
            ..Default::default()
        };
        let store = PgAuthorityCommitStore {
            pool: fixture.pool.clone(),
        };
        let station = fixture.state.service_core_id();
        let guard = native_phase(|| {
            store.acquire_realm_actor_content_delivery(&authority.actor_id, &station, &input)
        })
        .await
        .unwrap()
        .expect("stored result retains its original signed outcome after claim expiry or revoke");
        assert!(guard.permits_handoff());
        native_phase(|| guard.finish()).await.unwrap();
    }
}
