include!("realm_actor_mls_handoff_fixture.rs");

// Included inside realm_actor_mls_fixture. Reuse real accepted native setup.
fn admission_upload(
    identity: &arkret_mls::ArkretMlsIdentity,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    seed: &[u8; 32],
    last_resort: bool,
) -> KeyPackagesUploadRequestBody {
    let method = DidUrl::new(format!("{}#{}", authority.native_did, authority.device_id)).unwrap();
    let record = if last_resort {
        identity.last_resort_key_package_record().unwrap()
    } else {
        identity.key_package_record().unwrap()
    };
    let mut unsigned = identity
        .signed_key_packages_upload_request(&[record], method.as_str())
        .unwrap()
        .unsigned();
    unsigned.mls_group_id = Some(
        authority.scopes.entries()[0]
            .effective_scope
            .canonical_mls_group_id()
            .unwrap(),
    );
    unsigned.keypackages[0].last_resort = last_resort.then_some(true);
    let signature = arkret_signatures::keypackages::sign_keypackage_signing_input(
        seed,
        method.as_str(),
        &keypackages_upload_signing_input(&unsigned).unwrap(),
    )
    .unwrap();
    unsigned.into_signed(signature)
}

fn admission_revoke(
    authority: &coland_storage::AppletManagedDeviceAuthority,
    seed: &[u8; 32],
    refs: Vec<String>,
) -> KeyPackagesRevokeRequestBody {
    let method = format!("{}#{}", authority.native_did, authority.device_id);
    let body = KeyPackagesRevokeUnsignedRequest {
        key_package_refs: refs,
        device_id: authority.device_id.clone(),
        reason: None,
    };
    let signature =
        arkret_signatures::keypackages::sign_keypackages_revoke_request(&body, &method, seed)
            .unwrap();
    body.into_signed(signature)
}

async fn admission_native_upload(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    seed: &[u8; 32],
    body: &KeyPackagesUploadRequestBody,
) -> String {
    let (status, value) = boxed_step(|| {
        obligation_recipient_post(
            fixture,
            authority,
            seed,
            "/_arkret/self/keys/keypackages/upload",
            ServiceOperationId::SelfKeysKeypackagesUploadCreateV1,
            json!(body),
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "actual native scoped publication: {value}"
    );
    assert_eq!(value["accepted"], 1);
    let before = boxed_step(|| obligation_mls_footprint(fixture)).await;
    let (status, replay) = boxed_step(|| {
        obligation_recipient_post(
            fixture,
            authority,
            seed,
            "/_arkret/self/keys/keypackages/upload",
            ServiceOperationId::SelfKeysKeypackagesUploadCreateV1,
            json!(body),
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "exact native publication replay: {replay}"
    );
    assert_eq!(replay, value);
    assert_eq!(
        boxed_step(|| obligation_mls_footprint(fixture)).await,
        before
    );
    body.keypackages[0].keypackage_ref.clone()
}

pub(super) async fn keypackage_admission(
    fixture: &Fixture,
    package: &AppletPackage,
    candidate: &RealmActorCreatePayload,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    child: &GrantId,
    group: &mut arkret_mls::ArkretMlsGroup,
) {
    use diesel_async::{RunQueryDsl as _, SimpleAsyncConnection as _};
    let original = fixture
        .state
        .test_persistence()
        .authority_commits()
        .applet_realm_actor_creations(&fixture.realm, &candidate.applet_id, None)
        .await
        .unwrap()
        .into_iter()
        .find(|p| p.event.payload.get("actor_id") == Some(&json!(candidate.actor_id)))
        .unwrap();
    let seed = [90; 32];
    let device = boxed_step(|| {
        super::realm_native_fixture::authorize_obligation_device(
            fixture,
            candidate,
            &original.commit,
            90,
            arkret_canonical::normalize_timestamp_canonical(
                chrono::Utc::now() + chrono::Duration::minutes(15),
            ),
        )
    })
    .await;
    let recipient = fixture
        .state
        .test_persistence()
        .device_revocations()
        .applet_managed_device_authority(&candidate.actor_id, &device, chrono::Utc::now())
        .await
        .unwrap()
        .unwrap();
    assert_ne!(recipient.device_id, authority.device_id);
    let identity = arkret_mls::ArkretMlsIdentity::new_realm_device(
        recipient.actor_id.clone(),
        device.clone(),
        arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(SigningKey::from_bytes(&seed)),
    )
    .unwrap();
    let method = format!("{}#{}", recipient.native_did, device);
    let mut wrong_device = admission_upload(&identity, &recipient, &seed, false).unsigned();
    wrong_device.device_id = Some(authority.device_id.clone());
    let signature = arkret_signatures::keypackages::sign_keypackage_signing_input(
        &seed,
        &method,
        &keypackages_upload_signing_input(&wrong_device).unwrap(),
    )
    .unwrap();
    let wrong_device = wrong_device.into_signed(signature);
    let before = boxed_step(|| obligation_mls_footprint(fixture)).await;
    let (status, problem) = boxed_step(|| {
        obligation_recipient_post(
            fixture,
            &recipient,
            &seed,
            "/_arkret/self/keys/keypackages/upload",
            ServiceOperationId::SelfKeysKeypackagesUploadCreateV1,
            json!(wrong_device),
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "original native transport cannot upload under another Device: {problem}"
    );
    assert_eq!(
        problem["type"],
        "https://arkret.org/problems/capability_denied"
    );
    assert_eq!(
        boxed_step(|| obligation_mls_footprint(fixture)).await,
        before
    );
    let unsigned = admission_upload(&identity, &recipient, &seed, false).unsigned();
    let signature = arkret_signatures::keypackages::sign_keypackage_signing_input(
        &[91; 32],
        &method,
        &keypackages_upload_signing_input(&unsigned).unwrap(),
    )
    .unwrap();
    let wrong_signature = unsigned.into_signed(signature);
    let before = boxed_step(|| obligation_mls_footprint(fixture)).await;
    let (status, problem) = boxed_step(|| {
        obligation_recipient_post(
            fixture,
            &recipient,
            &seed,
            "/_arkret/self/keys/keypackages/upload",
            ServiceOperationId::SelfKeysKeypackagesUploadCreateV1,
            json!(wrong_signature),
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "valid transport cannot substitute the independent upload signature: {problem}"
    );
    assert_eq!(problem["type"], "https://arkret.org/problems/param_invalid");
    assert_eq!(problem["detail"], "device_signature_invalid");
    assert_eq!(
        boxed_step(|| obligation_mls_footprint(fixture)).await,
        before
    );
    for invalid in [
        "opaque-package",
        "ak:mls:kp:01964137-0000-4000-8000-000000000001",
        "ak:mls:kp:01964137-0000-7000-7000-000000000001",
        "ak:mls:kp:01964137-0000-7000-8000-00000000000A",
    ] {
        let mut unsigned = admission_upload(&identity, &recipient, &seed, false).unsigned();
        // A valid earlier entry cannot escape a whole-request shape refusal.
        let mut malformed = unsigned.keypackages[0].clone();
        malformed.keypackage_id = invalid.into();
        unsigned.keypackages.push(malformed);
        assert!(keypackages_upload_signing_input(&unsigned).is_err());
        let mut input = arkret_models_crypto::http_bodies::KEYPACKAGES_UPLOAD_SIGNATURE_DOMAIN
            .as_bytes()
            .to_vec();
        input.extend(arkret_canonical::canonical_json_bytes(&unsigned).unwrap());
        let signature =
            arkret_signatures::keypackages::sign_keypackage_signing_input(&seed, &method, &input)
                .unwrap();
        arkret_signatures::keypackages::verify_keypackage_signing_input(
            &recipient.public_key,
            &method,
            &input,
            &signature,
        )
        .unwrap();
        let body = unsigned.into_signed(signature);
        let before = boxed_step(|| obligation_mls_footprint(fixture)).await;
        let (status, problem) = boxed_step(|| {
            obligation_recipient_post(
                fixture,
                &recipient,
                &seed,
                "/_arkret/self/keys/keypackages/upload",
                ServiceOperationId::SelfKeysKeypackagesUploadCreateV1,
                json!(body),
            )
        })
        .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "typed registered identity required: {problem}"
        );
        assert_eq!(
            problem["type"],
            "https://arkret.org/problems/schema_violation"
        );
        assert_eq!(
            boxed_step(|| obligation_mls_footprint(fixture)).await,
            before
        );
    }
    let first = admission_upload(&identity, &recipient, &seed, false);
    let first_ref =
        boxed_step(|| admission_native_upload(fixture, &recipient, &seed, &first)).await;
    let second = admission_upload(&identity, &recipient, &seed, false);
    let second_ref =
        boxed_step(|| admission_native_upload(fixture, &recipient, &seed, &second)).await;
    let revoke = admission_revoke(
        &recipient,
        &seed,
        vec![first_ref.clone(), second_ref.clone()],
    );
    let mut wrong = revoke.unsigned();
    wrong.device_id = authority.device_id.clone();
    let signature =
        arkret_signatures::keypackages::sign_keypackages_revoke_request(&wrong, &method, &seed)
            .unwrap();
    let wrong = wrong.into_signed(signature);
    let bad_signature = admission_revoke(&recipient, &[91; 32], revoke.key_package_refs.clone());
    for invalid in [wrong, bad_signature] {
        let before = boxed_step(|| obligation_mls_footprint(fixture)).await;
        let (status, problem) = boxed_step(|| {
            obligation_recipient_post(
                fixture,
                &recipient,
                &seed,
                "/_arkret/self/keys/keypackages/revoke",
                ServiceOperationId::SelfKeysKeypackagesCommandRevokeV1,
                json!(invalid),
            )
        })
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "valid native transport cannot bypass original package Device/inner signature: {problem}"
        );
        assert_eq!(
            problem["type"],
            "https://arkret.org/problems/capability_denied"
        );
        assert_eq!(
            boxed_step(|| obligation_mls_footprint(fixture)).await,
            before
        );
    }
    let unknown = admission_revoke(
        &recipient,
        &seed,
        vec![format!("sha256:{}", "00".repeat(32))],
    );
    let before = boxed_step(|| obligation_mls_footprint(fixture)).await;
    let (status, value) = boxed_step(|| {
        obligation_recipient_post(
            fixture,
            &recipient,
            &seed,
            "/_arkret/self/keys/keypackages/revoke",
            ServiceOperationId::SelfKeysKeypackagesCommandRevokeV1,
            json!(unknown),
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "unknown exact package is opaque: {value}"
    );
    assert_eq!(value["failures"][0]["reason_code"], "keypackage_unknown");
    assert_eq!(
        boxed_step(|| obligation_mls_footprint(fixture)).await,
        before
    );
    let mut connection = fixture.pool.get().await.unwrap();
    connection.batch_execute(&format!("CREATE FUNCTION test_native_admission_revoke_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF OLD.keypackage_ref='{}' THEN RAISE EXCEPTION 'native second package writer failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER test_native_admission_revoke_failure BEFORE UPDATE ON mls_key_packages FOR EACH ROW EXECUTE FUNCTION test_native_admission_revoke_failure();",second_ref.replace('\'',"''"))).await.unwrap();
    drop(connection);
    let before = boxed_step(|| obligation_mls_footprint(fixture)).await;
    let reply = boxed_step(|| {
        obligation_recipient_post(
            fixture,
            &recipient,
            &seed,
            "/_arkret/self/keys/keypackages/revoke",
            ServiceOperationId::SelfKeysKeypackagesCommandRevokeV1,
            json!(revoke),
        )
    })
    .await;
    let mut connection = fixture.pool.get().await.unwrap();
    connection.batch_execute("DROP TRIGGER test_native_admission_revoke_failure ON mls_key_packages; DROP FUNCTION test_native_admission_revoke_failure();").await.unwrap();
    drop(connection);
    assert_eq!(
        reply.0,
        StatusCode::SERVICE_UNAVAILABLE,
        "second package failure rolls back whole batch: {}",
        reply.1
    );
    assert_eq!(
        reply.1["type"],
        "https://arkret.org/problems/temporarily_unavailable"
    );
    assert_eq!(
        boxed_step(|| obligation_mls_footprint(fixture)).await,
        before
    );
    let (status, value) = boxed_step(|| {
        obligation_recipient_post(
            fixture,
            &recipient,
            &seed,
            "/_arkret/self/keys/keypackages/revoke",
            ServiceOperationId::SelfKeysKeypackagesCommandRevokeV1,
            json!(revoke),
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "real native own-package cleanup: {value}"
    );
    let result: KeyPackagesRevokeOutcome = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(result.revoked, revoke.key_package_refs);
    assert!(result.failures.is_empty());
    let before = boxed_step(|| obligation_mls_footprint(fixture)).await;
    let (status, replay) = boxed_step(|| {
        obligation_recipient_post(
            fixture,
            &recipient,
            &seed,
            "/_arkret/self/keys/keypackages/revoke",
            ServiceOperationId::SelfKeysKeypackagesCommandRevokeV1,
            json!(revoke),
        )
    })
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(replay, value);
    assert_eq!(
        boxed_step(|| obligation_mls_footprint(fixture)).await,
        before
    );
    for reference in [&first_ref, &second_ref] {
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
            Some(recipient.authorization_ref.event_id.as_str())
        );
    }
    boxed_step(|| {
        admission_native_last_resort(
            fixture, package, candidate, authority, child, group, recipient, identity, &seed,
        )
    })
    .await;
    boxed_step(|| {
        admission_prepared_queue_boundaries(fixture, package, candidate, authority, child, group)
    })
    .await;
    boxed_step(|| {
        admission_native_mls_writer_expiry(fixture, package, candidate, authority, child, group)
    })
    .await;
    boxed_step(|| {
        admission_claimed_target_fence(fixture, package, candidate, authority, child, group)
    })
    .await;
    boxed_step(|| {
        admission_accepted_self_update(fixture, package, candidate, authority, child, group)
    })
    .await;
    let restored_child = boxed_step(|| {
        admission_read_material_and_snapshot_guards(fixture, package, candidate, authority, group)
    })
    .await;
    boxed_step(|| super::realm_native_fixture::policy_blocks_fresh_native_join(fixture, package))
        .await;
    boxed_step(|| {
        admission_current_mls_policy(
            fixture,
            package,
            candidate,
            authority,
            &restored_child,
            group,
        )
    })
    .await;
}

fn admission_last_resort_claim(
    source: &coland_storage::AppletManagedDeviceAuthority,
    recipient: &coland_storage::AppletManagedDeviceAuthority,
    scope: &ScopeRef,
    reference: &str,
) -> KeyPackagesClaimRequestBody {
    admission_signed_claim(source, recipient, scope, reference, true)
}

fn admission_signed_claim(
    source: &coland_storage::AppletManagedDeviceAuthority,
    recipient: &coland_storage::AppletManagedDeviceAuthority,
    scope: &ScopeRef,
    reference: &str,
    last_resort: bool,
) -> KeyPackagesClaimRequestBody {
    assert_eq!(source.realm_id, recipient.realm_id);
    assert!(
        source
            .scopes
            .entries()
            .iter()
            .any(|entry| &entry.effective_scope == scope)
    );
    let method = DidUrl::new(format!("{}#{}", source.native_did, source.device_id)).unwrap();
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let mut body = KeyPackagesClaimRequestBody {
        claim_request_id: arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
            rand::random::<[u8; 32]>(),
        ))
        .unwrap(),
        target_account_id: None,
        target_actor_id: Some(recipient.actor_id.clone()),
        requester_account_id: None,
        requester_actor_id: Some(source.actor_id.clone()),
        intended_realm_id: source.realm_id.clone(),
        mls_group_id: scope.canonical_mls_group_id().unwrap(),
        claim_purpose: PeerKeyPackageClaimPurpose::RealmMembership,
        required_capabilities: vec![arkret_wire::NonEmptyString::new("ak.content.v1").unwrap()],
        expires_at: at + chrono::Duration::minutes(4),
        target_device_ids: vec![recipient.device_id.clone()],
        // Exact references select ordinary single-use packages only. A
        // negotiated last-resort claim selects this Device's available pool.
        target_keypackage_ref: (!last_resort)
            .then(|| arkret_wire::KeyPackageRef::new(reference).unwrap()),
        target_agent_id: None,
        target_agent_verification_method: None,
        target_agent_key_authorize_event_id: None,
        timeout_ms: None,
        strand_id: None,
        pair_key: None,
        last_resort_allowed: last_resort.then_some(true),
        service_binding: KeyPackagesClaimServiceBinding {
            source_id: source.governance_service_id.clone(),
            destination_id: recipient.governance_service_id.clone(),
        },
        requester_authorization: PeerKeyPackageRequesterAuthorization::RealmDevice {
            verification_method: method.clone(),
            requester_device_id: source.device_id.clone(),
            device_authorize_event_id: source.authorization_ref.event_id.clone(),
            signed_at: at,
            signature: arkret_signatures::keypackages::keypackage_signature_from_bytes(
                method.as_str(),
                &[0; 64],
            )
            .unwrap(),
        },
    };
    let input = keypackage_claim_authorization_signing_bytes(
        &body.unsigned_request(),
        &body.service_binding,
        &body.requester_authorization,
    )
    .unwrap();
    let PeerKeyPackageRequesterAuthorization::RealmDevice { signature, .. } =
        &mut body.requester_authorization
    else {
        unreachable!()
    };
    *signature = arkret_signatures::keypackages::sign_keypackage_signing_input(
        &[79; 32],
        method.as_str(),
        &input,
    )
    .unwrap();
    body.validate_shape().unwrap();
    body
}

async fn admission_native_last_resort(
    fixture: &Fixture,
    package: &AppletPackage,
    candidate: &RealmActorCreatePayload,
    source: &coland_storage::AppletManagedDeviceAuthority,
    child: &GrantId,
    group: &mut arkret_mls::ArkretMlsGroup,
    recipient: coland_storage::AppletManagedDeviceAuthority,
    identity: arkret_mls::ArkretMlsIdentity,
    seed: &[u8; 32],
) {
    // Both participants use this actual same Station. Its public description
    // advertises the optional feature before either signed claim is authored.
    let (status, description) = boxed_step(|| {
        account_request(
            fixture,
            reqwest::Method::GET,
            "/_arkret/describe",
            ServiceOperationId::ServerReadDescribeV1,
            None,
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "actual feature negotiation material: {description}"
    );
    assert!(
        description["supported_features"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f == arkret_wire::FeatureDescriptor::MLS_LAST_RESORT_KEYPACKAGE_V1)
    );
    let upload = admission_upload(&identity, &recipient, seed, true);
    let reference =
        boxed_step(|| admission_native_upload(fixture, &recipient, seed, &upload)).await;
    let request =
        admission_last_resort_claim(source, &recipient, &candidate.creation_scope, &reference);
    assert!(request.target_keypackage_ref.is_none());
    assert_eq!(request.last_resort_allowed, Some(true));
    // A real Device signature cannot make the closed exact-reference /
    // last-resort combination legal. Reject it before accepting the same
    // correctly authored pool-selection request below.
    let mut exact_last_resort = request.clone();
    exact_last_resort.target_keypackage_ref =
        Some(arkret_wire::KeyPackageRef::new(reference.as_str()).unwrap());
    let signing_input = keypackage_claim_authorization_signing_bytes(
        &exact_last_resort.unsigned_request(),
        &exact_last_resort.service_binding,
        &exact_last_resort.requester_authorization,
    )
    .unwrap();
    let PeerKeyPackageRequesterAuthorization::RealmDevice {
        verification_method,
        signature,
        ..
    } = &mut exact_last_resort.requester_authorization
    else {
        unreachable!()
    };
    *signature = arkret_signatures::keypackages::sign_keypackage_signing_input(
        &[79; 32],
        verification_method.as_str(),
        &signing_input,
    )
    .unwrap();
    assert!(exact_last_resort.validate_shape().is_err());
    let before = boxed_step(|| obligation_mls_footprint(fixture)).await;
    let (status, problem) = boxed_step(|| {
        device_post(
            fixture,
            source,
            "/_arkret/self/keys/keypackages/claim",
            ServiceOperationId::SelfKeysKeypackagesCommandClaimV1,
            json!(exact_last_resort),
        )
    })
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{problem}");
    assert_eq!(
        problem["type"],
        "https://arkret.org/problems/schema_violation"
    );
    assert_eq!(
        boxed_step(|| obligation_mls_footprint(fixture)).await,
        before
    );
    let (status, value) = boxed_step(|| {
        device_post(
            fixture,
            source,
            "/_arkret/self/keys/keypackages/claim",
            ServiceOperationId::SelfKeysKeypackagesCommandClaimV1,
            json!(request),
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "negotiated actual native last-resort claim: {value}"
    );
    let claim: KeyPackagesClaimOutcome = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(claim.claim_receipt.request, request.unsigned_request());
    assert_eq!(claim.claims.len(), 1);
    assert_eq!(claim.claims[0].keypackage_ref, reference);
    assert_eq!(claim.claims[0].last_resort, Some(true));
    assert_eq!(claim.claims[0].actor_id, recipient.actor_id);
    assert_eq!(
        claim.claims[0].device_id.as_ref(),
        Some(&recipient.device_id)
    );
    let current = coland_storage_postgres::PgMlsGroupCurrentStore {
        pool: fixture.pool.clone(),
    }
    .current(&candidate.creation_scope)
    .await
    .unwrap()
    .unwrap()
    .value;
    let binding = MlsGovernanceBindingPayload::new(
        candidate.creation_scope.clone(),
        Some(current.current_mls_commit_event_ref.clone()),
        current.epoch,
        current.epoch + 1,
        current.current_key_access_revision,
    )
    .unwrap();
    let added = group
        .add_member_with_governance_binding(
            &arkret_mls::mls_key_package_record_from_claim(&claim.claims[0]).unwrap(),
            &binding,
        )
        .unwrap();
    let payload = MlsCommitPayload::new(
        current.current_mls_commit_event_ref.clone(),
        current.current_key_access_revision,
        &added.commit,
        binding,
    )
    .unwrap();
    let signer = Ed25519PayloadSigner::new(
        SigningKey::from_bytes(&[79; 32]),
        source.native_did.clone(),
        DidUrl::new(format!("{}#{}", source.native_did, source.device_id)).unwrap(),
    );
    let event = signed_event(
        package,
        candidate.actor_id.clone(),
        candidate.creation_scope.clone(),
        EventKind::MlsCommit,
        json!(payload),
        Some(child),
        &signer,
    );
    let at = event.created_at;
    let method = DidUrl::new(format!("{}#{}", source.native_did, source.device_id)).unwrap();
    let mut welcome = arkret_wire::MlsWelcomeDelivery {
        welcome_id: arkret_wire::MlsWelcomeDeliveryId::new(format!(
            "ak:mls_welcome_delivery:{}",
            uuid::Uuid::now_v7()
        ))
        .unwrap(),
        realm_id: fixture.realm.clone(),
        effective_scope: candidate.creation_scope.clone(),
        commit_event_ref: event.event_id.clone(),
        recipient_actor_id: recipient.actor_id.clone(),
        recipient_endpoint: arkret_wire::MlsWelcomeRecipientEndpoint::Device {
            device_id: recipient.device_id.clone(),
        },
        keypackage_claim_ref: added.welcome.keypackage_claim_ref,
        ciphertext_b64: added.welcome.ciphertext_b64,
        producer_proof: arkret_signatures::detached_object::sign_detached_object(
            &Value::Null,
            arkret_wire::DetachedSignatureContext::MlsWelcomeDelivery,
            method.clone(),
            at,
            &SigningKey::from_bytes(&[79; 32]),
        )
        .unwrap(),
    };
    welcome.producer_proof = arkret_signatures::detached_object::sign_detached_object(
        &arkret_canonical::unsigned_value(&welcome, &["producer_proof"]).unwrap(),
        arkret_wire::DetachedSignatureContext::MlsWelcomeDelivery,
        method,
        at,
        &SigningKey::from_bytes(&[79; 32]),
    )
    .unwrap();
    let submission = SelfAuthoritySubmitRequest::MlsCommit(arkret_wire::MlsCommitSubmission {
        commit_event: event.clone(),
        welcomes: vec![welcome.clone()],
        idempotency_key: arkret_wire::UuidV7::new(uuid::Uuid::now_v7()).unwrap(),
    });
    let (status, accepted) = boxed_step(|| {
        device_post(
            fixture,
            source,
            "/_arkret/self/events",
            ServiceOperationId::SelfEventsCommandSubmitV1,
            json!(submission),
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "actual valid native Add with last-resort claim: {accepted}"
    );
    let original = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&event.event_id)
        .await
        .unwrap()
        .unwrap();
    let original = arkret_wire::CommittedEventFullView {
        event: original.event,
        commit: original.commit,
    };
    group.install_accepted_commit(&original, &current).unwrap();
    boxed_step(|| obligation_install_native_roster(fixture, source, &[79; 32], &original, group))
        .await;
    let mut joined = Box::new(
        arkret_mls::ArkretMlsGroup::join_from_verified_welcome_delivery(
            identity, &welcome, &original,
        )
        .unwrap(),
    );
    boxed_step(|| {
        obligation_install_native_roster(fixture, &recipient, seed, &original, &mut joined)
    })
    .await;
    let saved = joined.export_state_record().unwrap();
    let path = std::env::temp_dir().join(format!(
        "native-last-resort-recipient-{}.json",
        uuid::Uuid::now_v7()
    ));
    {
        use std::io::Write as _;
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.write_all(&serde_json::to_vec(&saved).unwrap())
            .unwrap();
        file.sync_all().unwrap();
    }
    drop(joined);
    let restored = arkret_mls::ArkretMlsGroup::restore_from_state_record(
        &serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap(),
    )
    .unwrap();
    std::fs::remove_file(&path).unwrap();
    let recipient_method =
        DidUrl::new(format!("{}#{}", recipient.native_did, recipient.device_id)).unwrap();
    let durable = RecipientMlsDurableReceipt {
        domain: arkret_wire::NonEmptyString::new(
            arkret_wire::DomainSeparationId::MLS_RECIPIENT_DURABLE_RECEIPT_V1.to_owned(),
        )
        .unwrap(),
        claim_request_id: claim.claim_request_id.clone(),
        key_package_ref: arkret_wire::NonEmptyString::new(reference.clone()).unwrap(),
        recipient: RecipientMlsDurableSigner::RealmDevice {
            recipient_actor_id: recipient.actor_id.clone(),
            recipient_device_id: recipient.device_id.clone(),
            device_verification_method: recipient_method.clone(),
        },
        recipient_id: fixture.state.service_core_id(),
        realm_id: fixture.realm.clone(),
        mls_group_id: candidate.creation_scope.canonical_mls_group_id().unwrap(),
        mls_epoch: restored.epoch(),
        welcome_ref: welcome.welcome_id.clone(),
        welcome_digest: welcome.durable_receipt_digest().unwrap(),
        durable_at: arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
        signature: KeyOperationSignature {
            kid: arkret_wire::NonEmptyString::new(recipient_method.to_string()).unwrap(),
            signature_algorithm: None,
            sig: arkret_wire::Base64UrlString::new("AA").unwrap(),
        },
    };
    let command = restored
        .identity()
        .signed_key_packages_consume_request(
            welcome.keypackage_claim_ref.clone(),
            restored
                .identity()
                .sign_recipient_mls_durable_receipt(durable)
                .unwrap(),
        )
        .unwrap();
    for (signature, input) in [
        (
            &command.signature,
            keypackages_consume_signing_input(&command.unsigned()).unwrap(),
        ),
        (
            &command.recipient_durable_receipt.signature,
            command
                .recipient_durable_receipt
                .canonical_signing_bytes()
                .unwrap(),
        ),
    ] {
        arkret_signatures::keypackages::verify_keypackage_signing_input(
            &recipient.public_key,
            recipient_method.as_str(),
            &input,
            signature,
        )
        .unwrap();
    }
    let (status, value) = boxed_step(|| {
        obligation_recipient_post(
            fixture,
            &recipient,
            seed,
            "/_arkret/self/keys/keypackages/consume",
            ServiceOperationId::SelfKeysKeypackagesCommandConsumeV1,
            json!(command),
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "real native last-resort durable consume: {value}"
    );
    let outcome: KeyPackagesConsumeOutcome = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(outcome.consume_receipt.claim_id, command.claim_id);
    assert_eq!(
        arkret_canonical::canonical_json_bytes(&outcome.consume_receipt.recipient_durable_receipt)
            .unwrap(),
        arkret_canonical::canonical_json_bytes(&command.recipient_durable_receipt).unwrap()
    );
    let store = fixture.state.test_persistence();
    let ledger = store
        .mls_key_packages()
        .get_peer_claim_by_claim_id(command.claim_id.as_str())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ledger.state, "consumed");
    assert_eq!(
        ledger.consume_receipt,
        Some(json!(&outcome.consume_receipt))
    );
    let row = store
        .mls_key_packages()
        .get_by_ref(&reference)
        .await
        .unwrap()
        .unwrap();
    assert!(row.last_resort);
    assert!(row.consumed_at.is_none());
    assert!(row.claimed_by_mls_group_id.is_none());
    let before = boxed_step(|| obligation_mls_footprint(fixture)).await;
    let (status, replay) = boxed_step(|| {
        obligation_recipient_post(
            fixture,
            &recipient,
            seed,
            "/_arkret/self/keys/keypackages/consume",
            ServiceOperationId::SelfKeysKeypackagesCommandConsumeV1,
            json!(command),
        )
    })
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(replay, value);
    assert_eq!(
        boxed_step(|| obligation_mls_footprint(fixture)).await,
        before
    );
    let another =
        admission_last_resort_claim(source, &recipient, &candidate.creation_scope, &reference);
    let (status, value) = boxed_step(|| {
        device_post(
            fixture,
            source,
            "/_arkret/self/keys/keypackages/claim",
            ServiceOperationId::SelfKeysKeypackagesCommandClaimV1,
            json!(another),
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "same published last-resort package has independent second audit: {value}"
    );
    let second: KeyPackagesClaimOutcome = serde_json::from_value(value).unwrap();
    assert_eq!(second.claim_receipt.request, another.unsigned_request());
    assert_eq!(second.claims[0].keypackage_ref, reference);
    assert_ne!(second.claims[0].claim_id, command.claim_id.as_str());
    let prior = store
        .mls_key_packages()
        .get_peer_claim_by_claim_id(command.claim_id.as_str())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(prior.state, "consumed");
    assert_eq!(prior.consume_receipt, Some(json!(&outcome.consume_receipt)));
    let next = store
        .mls_key_packages()
        .get_peer_claim_by_claim_id(&second.claims[0].claim_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(next.state, "last_resort_claimed");
    assert!(next.consume_receipt.is_none());
}

pub(super) async fn keypackage_before_genesis(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
) {
    let scope = ScopeRef::Realm {
        realm_id: fixture.realm.clone(),
    };
    let store = coland_storage_postgres::PgMlsGroupCurrentStore {
        pool: fixture.pool.clone(),
    };
    assert!(
        store.current(&scope).await.unwrap().is_none(),
        "this target exists before any accepted MLS Genesis"
    );
    let identity = arkret_mls::ArkretMlsIdentity::new_realm_device(
        authority.actor_id.clone(),
        authority.device_id.clone(),
        arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(SigningKey::from_bytes(&[79; 32])),
    )
    .unwrap();
    let valid = admission_upload(&identity, authority, &[79; 32], false);
    let reference =
        boxed_step(|| admission_native_upload(fixture, authority, &[79; 32], &valid)).await;
    assert!(
        store.current(&scope).await.unwrap().is_none(),
        "valid scoped publication is not an implicit Genesis"
    );
    let mut wrong = admission_upload(&identity, authority, &[79; 32], false).unsigned();
    let foreign = ScopeRef::Realm {
        realm_id: arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x46; 32],
        )),
    };
    wrong.mls_group_id = Some(foreign.canonical_mls_group_id().unwrap());
    let method = format!("{}#{}", authority.native_did, authority.device_id);
    let signature = arkret_signatures::keypackages::sign_keypackage_signing_input(
        &[79; 32],
        &method,
        &keypackages_upload_signing_input(&wrong).unwrap(),
    )
    .unwrap();
    let wrong = wrong.into_signed(signature);
    let before = boxed_step(|| obligation_mls_footprint(fixture)).await;
    let (status, problem) = boxed_step(|| {
        device_post(
            fixture,
            authority,
            "/_arkret/self/keys/keypackages/upload",
            ServiceOperationId::SelfKeysKeypackagesUploadCreateV1,
            json!(wrong),
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "valid signed foreign group target cannot escape its exact scope: {problem}"
    );
    assert_eq!(
        problem["type"],
        "https://arkret.org/problems/capability_denied"
    );
    assert_eq!(
        boxed_step(|| obligation_mls_footprint(fixture)).await,
        before
    );
    assert!(store.current(&scope).await.unwrap().is_none());
    let row = fixture
        .state
        .test_persistence()
        .mls_key_packages()
        .get_by_ref(&reference)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.owner_actor_id, authority.actor_id);
    assert_eq!(row.effective_scope.as_ref(), Some(&scope));
    assert_eq!(
        row.device_authorize_event_id.as_deref(),
        Some(authority.authorization_ref.event_id.as_str())
    );
}

async fn admission_current_mls_policy(
    fixture: &Fixture,
    package: &AppletPackage,
    candidate: &RealmActorCreatePayload,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    child: &GrantId,
    group: &arkret_mls::ArkretMlsGroup,
) {
    let state = coland_storage_postgres::PgMlsGroupCurrentStore {
        pool: fixture.pool.clone(),
    }
    .current(&candidate.creation_scope)
    .await
    .unwrap()
    .unwrap()
    .value;
    let binding = MlsGovernanceBindingPayload::new(
        candidate.creation_scope.clone(),
        Some(state.current_mls_commit_event_ref.clone()),
        state.epoch,
        state.epoch + 1,
        state.current_key_access_revision,
    )
    .unwrap();
    let mut prepared = arkret_mls::ArkretMlsGroup::restore_from_state_record(
        &group.export_state_record().unwrap(),
    )
    .unwrap();
    let update = prepared
        .self_update_commit_with_governance_binding(&binding)
        .unwrap();
    let payload = MlsCommitPayload::new(
        state.current_mls_commit_event_ref.clone(),
        state.current_key_access_revision,
        &update,
        binding,
    )
    .unwrap();
    let signer = Ed25519PayloadSigner::new(
        SigningKey::from_bytes(&[79; 32]),
        authority.native_did.clone(),
        DidUrl::new(format!("{}#{}", authority.native_did, authority.device_id)).unwrap(),
    );
    let event = signed_event(
        package,
        candidate.actor_id.clone(),
        candidate.creation_scope.clone(),
        EventKind::MlsCommit,
        json!(payload),
        Some(child),
        &signer,
    );
    let request = SelfAuthoritySubmitRequest::MlsCommit(arkret_wire::MlsCommitSubmission {
        commit_event: event.clone(),
        welcomes: vec![],
        idempotency_key: arkret_wire::UuidV7::new(uuid::Uuid::now_v7()).unwrap(),
    });
    request.validate().unwrap();
    boxed_step(|| {
        super::realm_native_fixture::install_admission_policy(
            fixture,
            &package.applet_id,
            &package.service_id,
            "execute",
        )
    })
    .await;
    let before = boxed_step(|| obligation_mls_footprint(fixture)).await;
    let (status, problem) = boxed_step(|| {
        device_post(
            fixture,
            authority,
            "/_arkret/self/events",
            ServiceOperationId::SelfEventsCommandSubmitV1,
            json!(request),
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "fully authored MLS self-update must still observe changed current execution policy: {problem}"
    );
    assert_eq!(
        problem["type"],
        "https://arkret.org/problems/capability_denied"
    );
    assert_eq!(
        boxed_step(|| obligation_mls_footprint(fixture)).await,
        before
    );
    assert!(
        fixture
            .state
            .test_persistence()
            .authority_commits()
            .committed_event(&event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(group.epoch(), state.epoch);
}

async fn admission_accepted_self_update(
    fixture: &Fixture,
    package: &AppletPackage,
    candidate: &RealmActorCreatePayload,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    child: &GrantId,
    group: &mut arkret_mls::ArkretMlsGroup,
) {
    let groups = coland_storage_postgres::PgMlsGroupCurrentStore {
        pool: fixture.pool.clone(),
    };
    let current = groups
        .current(&candidate.creation_scope)
        .await
        .unwrap()
        .unwrap()
        .value;
    let binding = MlsGovernanceBindingPayload::new(
        candidate.creation_scope.clone(),
        Some(current.current_mls_commit_event_ref.clone()),
        current.epoch,
        current.epoch + 1,
        current.current_key_access_revision,
    )
    .unwrap();
    let update = group
        .self_update_commit_with_governance_binding(&binding)
        .unwrap();
    let payload = MlsCommitPayload::new(
        current.current_mls_commit_event_ref.clone(),
        current.current_key_access_revision,
        &update,
        binding,
    )
    .unwrap();
    let signer = Ed25519PayloadSigner::new(
        SigningKey::from_bytes(&[79; 32]),
        authority.native_did.clone(),
        DidUrl::new(format!("{}#{}", authority.native_did, authority.device_id)).unwrap(),
    );
    let event = signed_event(
        package,
        candidate.actor_id.clone(),
        candidate.creation_scope.clone(),
        EventKind::MlsCommit,
        json!(payload),
        Some(child),
        &signer,
    );
    let request = SelfAuthoritySubmitRequest::MlsCommit(arkret_wire::MlsCommitSubmission {
        commit_event: event.clone(),
        welcomes: vec![],
        idempotency_key: arkret_wire::UuidV7::new(uuid::Uuid::now_v7()).unwrap(),
    });
    request.validate().unwrap();
    let (status, value) = boxed_step(|| {
        device_post(
            fixture,
            authority,
            "/_arkret/self/events",
            ServiceOperationId::SelfEventsCommandSubmitV1,
            json!(request),
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "actual native typed self-update accepted: {value}"
    );
    let accepted = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&event.event_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(accepted.event, event);
    let original = arkret_wire::CommittedEventFullView {
        event: accepted.event,
        commit: accepted.commit,
    };
    group.install_accepted_commit(&original, &current).unwrap();
    boxed_step(|| {
        obligation_install_native_roster(fixture, authority, &[79; 32], &original, group)
    })
    .await;
    assert_eq!(group.epoch(), current.epoch + 1);
    let next = groups
        .current(&candidate.creation_scope)
        .await
        .unwrap()
        .unwrap()
        .value;
    assert_eq!(next.epoch, group.epoch());
    assert_eq!(next.current_mls_commit_event_ref, event.event_id);
    let before = boxed_step(|| obligation_mls_footprint(fixture)).await;
    let (status, replay) = boxed_step(|| {
        device_post(
            fixture,
            authority,
            "/_arkret/self/events",
            ServiceOperationId::SelfEventsCommandSubmitV1,
            json!(request),
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "exact native self-update recovers original Commit: {replay}"
    );
    let outcome: arkret_models_collaboration::authority_commit::SelfAuthoritySubmitOutcome =
        serde_json::from_value(replay).unwrap();
    outcome.validate_for_request(&request).unwrap();
    let arkret_models_collaboration::authority_commit::SelfAuthoritySubmitOutcome::Ordinary(
        arkret_wire::AuthoritySubmitOutcome::Accepted { commit, .. },
    ) = outcome
    else {
        panic!("exact native self-update must recover its accepted original")
    };
    assert_eq!(commit, original.commit);
    assert_eq!(
        boxed_step(|| obligation_mls_footprint(fixture)).await,
        before
    );
    assert_eq!(group.epoch(), next.epoch);
}

async fn admission_read_parent(
    fixture: &Fixture,
    package: &AppletPackage,
    actor: &ActorId,
    template: &CapabilityGrantCreateBody,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
) -> GrantId {
    let mut body = template.clone();
    body.constraints
        .retain(|c| c.constraint_kind != GrantConstraintKind::Temporal);
    if let Some(deadline) = expires_at {
        body.actions = vec!["ak.event.read".into()];
        let mut window =
            GrantConstraint::new(GrantConstraintKind::Temporal, GrantConstraintEffect::Allow);
        window.expires_at = Some(deadline);
        body.constraints.push(window);
    }
    body.issued_at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let parent = boxed_step(|| obligation_admin_grant(fixture, body.clone())).await;
    let sources = [(parent, body)];
    boxed_step(|| obligation_terminal_child(fixture, package, actor, &sources)).await
}

async fn admission_claimed_target_fence(
    fixture: &Fixture,
    package: &AppletPackage,
    candidate: &RealmActorCreatePayload,
    source: &coland_storage::AppletManagedDeviceAuthority,
    child: &GrantId,
    group: &arkret_mls::ArkretMlsGroup,
) {
    let seed = [95; 32];
    let (target, recipient) = boxed_step(|| {
        super::realm_native_fixture::admission_native_endpoint(fixture, package, 95, false)
    })
    .await;
    assert_ne!(target.actor_id, source.actor_id);
    let identity = arkret_mls::ArkretMlsIdentity::new_realm_device(
        recipient.actor_id.clone(),
        recipient.device_id.clone(),
        arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(SigningKey::from_bytes(&seed)),
    )
    .unwrap();
    let upload = admission_upload(&identity, &recipient, &seed, false);
    let reference =
        boxed_step(|| admission_native_upload(fixture, &recipient, &seed, &upload)).await;
    let request = admission_signed_claim(
        source,
        &recipient,
        &candidate.creation_scope,
        &reference,
        false,
    );
    let (status, value) = boxed_step(|| {
        device_post(
            fixture,
            source,
            "/_arkret/self/keys/keypackages/claim",
            ServiceOperationId::SelfKeysKeypackagesCommandClaimV1,
            json!(request),
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "genuine claim before independent target fence: {value}"
    );
    let claim: KeyPackagesClaimOutcome = serde_json::from_value(value).unwrap();
    assert_eq!(claim.claim_receipt.request, request.unsigned_request());
    assert_eq!(claim.claims.len(), 1);
    assert_eq!(claim.claims[0].actor_id, target.actor_id);
    assert_eq!(claim.claims[0].keypackage_ref, reference);
    assert_eq!(
        claim.claims[0].device_id.as_ref(),
        Some(&recipient.device_id)
    );
    let current = coland_storage_postgres::PgMlsGroupCurrentStore {
        pool: fixture.pool.clone(),
    }
    .current(&candidate.creation_scope)
    .await
    .unwrap()
    .unwrap()
    .value;
    let binding = MlsGovernanceBindingPayload::new(
        candidate.creation_scope.clone(),
        Some(current.current_mls_commit_event_ref.clone()),
        current.epoch,
        current.epoch + 1,
        current.current_key_access_revision,
    )
    .unwrap();
    let mut prepared = arkret_mls::ArkretMlsGroup::restore_from_state_record(
        &group.export_state_record().unwrap(),
    )
    .unwrap();
    let added = prepared
        .add_member_with_governance_binding(
            &arkret_mls::mls_key_package_record_from_claim(&claim.claims[0]).unwrap(),
            &binding,
        )
        .unwrap();
    let payload = MlsCommitPayload::new(
        current.current_mls_commit_event_ref.clone(),
        current.current_key_access_revision,
        &added.commit,
        binding,
    )
    .unwrap();
    let source_method = DidUrl::new(format!("{}#{}", source.native_did, source.device_id)).unwrap();
    let event = signed_event(
        package,
        candidate.actor_id.clone(),
        candidate.creation_scope.clone(),
        EventKind::MlsCommit,
        json!(payload),
        Some(child),
        &Ed25519PayloadSigner::new(
            SigningKey::from_bytes(&[79; 32]),
            source.native_did.clone(),
            source_method.clone(),
        ),
    );
    let mut welcome = arkret_wire::MlsWelcomeDelivery {
        welcome_id: arkret_wire::MlsWelcomeDeliveryId::new(format!(
            "ak:mls_welcome_delivery:{}",
            uuid::Uuid::now_v7()
        ))
        .unwrap(),
        realm_id: fixture.realm.clone(),
        effective_scope: candidate.creation_scope.clone(),
        commit_event_ref: event.event_id.clone(),
        recipient_actor_id: recipient.actor_id.clone(),
        recipient_endpoint: arkret_wire::MlsWelcomeRecipientEndpoint::Device {
            device_id: recipient.device_id.clone(),
        },
        keypackage_claim_ref: added.welcome.keypackage_claim_ref,
        ciphertext_b64: added.welcome.ciphertext_b64,
        producer_proof: arkret_signatures::detached_object::sign_detached_object(
            &Value::Null,
            arkret_wire::DetachedSignatureContext::MlsWelcomeDelivery,
            source_method.clone(),
            event.created_at,
            &SigningKey::from_bytes(&[79; 32]),
        )
        .unwrap(),
    };
    welcome.producer_proof = arkret_signatures::detached_object::sign_detached_object(
        &arkret_canonical::unsigned_value(&welcome, &["producer_proof"]).unwrap(),
        arkret_wire::DetachedSignatureContext::MlsWelcomeDelivery,
        source_method,
        event.created_at,
        &SigningKey::from_bytes(&[79; 32]),
    )
    .unwrap();
    let submission = SelfAuthoritySubmitRequest::MlsCommit(arkret_wire::MlsCommitSubmission {
        commit_event: event.clone(),
        welcomes: vec![welcome],
        idempotency_key: arkret_wire::UuidV7::new(uuid::Uuid::now_v7()).unwrap(),
    });
    submission.validate().unwrap();
    // Only the destination changes. The producer remains current and authorized.
    boxed_step(|| super::realm_native_fixture::admission_pause_target(fixture, &target)).await;
    let current_source = fixture
        .state
        .test_persistence()
        .device_revocations()
        .applet_managed_device_authority(&source.actor_id, &source.device_id, chrono::Utc::now())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(current_source.authorization_ref, source.authorization_ref);
    assert_eq!(current_source.public_key, source.public_key);
    let before = boxed_step(|| obligation_mls_footprint(fixture)).await;
    let (status, problem) = boxed_step(|| {
        device_post(
            fixture,
            source,
            "/_arkret/self/events",
            ServiceOperationId::SelfEventsCommandSubmitV1,
            json!(submission),
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "claimed package must not bypass current target actor fence: {problem}"
    );
    assert_eq!(
        problem["type"],
        "https://arkret.org/problems/device_unauthorized"
    );
    assert_eq!(problem["detail"], "Realm actor status gate is not active");
    assert_eq!(
        boxed_step(|| obligation_mls_footprint(fixture)).await,
        before
    );
    assert!(
        fixture
            .state
            .test_persistence()
            .authority_commits()
            .committed_event(&event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(group.epoch(), current.epoch);
    let retained = fixture
        .state
        .test_persistence()
        .mls_key_packages()
        .get_by_ref(&reference)
        .await
        .unwrap()
        .unwrap();
    assert!(retained.consumed_at.is_none());
}

fn admission_verify_snapshot(fixture: &Fixture, snapshot: &arkret_wire::RealmStateSnapshot) {
    snapshot.require_full_recovery().unwrap();
    let key = arkret_signatures::PublicKeyMaterial::Ed25519Multibase {
        value: arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            fixture
                .state
                .notary_signing_key()
                .verifying_key()
                .as_bytes(),
        ),
    };
    arkret_signatures::detached_object::verify_detached_object_signature(
        &snapshot.signature,
        &arkret_canonical::unsigned_value(snapshot, &["signature"]).unwrap(),
        arkret_wire::DetachedSignatureContext::RealmSnapshot,
        &key,
    )
    .unwrap();
    let stream = arkret_wire::CommitStreamRef::from_scope(
        &ScopeRef::Realm {
            realm_id: fixture.realm.clone(),
        },
        None,
    )
    .unwrap();
    assert_eq!(snapshot.visible_stream_heads.len(), 1);
    assert_eq!(snapshot.visible_stream_heads[0].stream_ref, stream);
    assert_eq!(snapshot.retention_and_history_floor.stream_floors.len(), 1);
    assert_eq!(
        snapshot.retention_and_history_floor.stream_floors[0].stream_ref,
        stream
    );
    assert!(snapshot.current_state_entries.iter().all(|row| match row {
        arkret_wire::TypedCurrentRow::Value {
            source_stream_ref, ..
        } => source_stream_ref == &stream,
    }));
}

async fn admission_read_footprint(fixture: &Fixture) -> Value {
    use diesel_async::RunQueryDsl as _;
    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type = diesel::sql_types::Jsonb)]
        value: Value,
    }
    let mut value = boxed_step(|| obligation_mls_footprint(fixture)).await;
    let mut connection = fixture.pool.get().await.unwrap();
    for table in [
        "realm_state_snapshot_issuances",
        "realm_state_snapshot_window_reservations",
        "sync_cursor_handles",
    ] {
        let row = diesel::sql_query(format!("SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb) AS value FROM {table} r"))
            .get_result::<Row>(&mut connection).await.unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert(table.into(), row.value);
    }
    value
}

async fn admission_snapshot_response(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    reference: Option<&arkret_wire::RealmSnapshotId>,
) -> salvo::Response {
    let operation = if reference.is_some() {
        ServiceOperationId::SelfRealmStateSnapshotReadByRefV1
    } else {
        ServiceOperationId::SelfRealmStateSnapshotReadManifestHeadV1
    };
    let path = operation.descriptor().http_path.replace(
        "{snapshot_id}",
        reference.map(|id| id.as_str()).unwrap_or(""),
    );
    let path = format!("{path}?realm_id={}", fixture.realm);
    boxed_step(|| {
        boundary_native_response(fixture, &fixture.state, authority, &path, operation, None)
    })
    .await
}

async fn admission_read_material_and_snapshot_guards(
    fixture: &Fixture,
    package: &AppletPackage,
    candidate: &RealmActorCreatePayload,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    group: &mut arkret_mls::ArkretMlsGroup,
) -> GrantId {
    use arkret_models_collaboration::mls_roster_authority::{
        MlsMemberRosterAuthorityReadRequestBody, MlsSelfRosterAuthorityReadOutcome,
    };
    let rows = fixture
        .state
        .test_persistence()
        .capability_grant_current_results()
        .snapshot_for_realm(&fixture.realm)
        .await
        .unwrap();
    let parents:Vec<_>=rows.iter().filter(|r|matches!(&r.value.subject,CapabilitySubject::Actor(a) if a==&ActorId::service(package.service_id.clone()))
        && r.value.status==arkret_models_collaboration::governance::grant_constraint::CapabilityGrantStatus::Active
        && r.value.actions.iter().any(|a|a=="ak.event.read")
        && r.value.constraints.iter().any(|c|c.applet_id.as_ref()==Some(&package.applet_id))).collect();
    let original = parents
        .iter()
        .find(|r| {
            r.value
                .constraints
                .iter()
                .any(|c| !c.allowed_managed_actor_roles.is_empty())
        })
        .expect("actual Service business regrant source")
        .value
        .clone();
    let template = CapabilityGrantCreateBody {
        schema: original.schema,
        realm_id: original.realm_id,
        issuer_id: original.issuer_id,
        subject: original.subject,
        actions: original.actions,
        resources: original.resources,
        constraints: original.constraints,
        issuer_authority_refs: original.issuer_authority_refs,
        issued_at: original.issued_at,
    };
    for parent in parents {
        boxed_step(|| obligation_close_grant(fixture, &parent.grant_id)).await;
    }
    let deadline = arkret_canonical::normalize_timestamp_canonical(
        chrono::Utc::now() + chrono::Duration::seconds(30),
    );
    let _read_child = boxed_step(|| {
        admission_read_parent(
            fixture,
            package,
            &candidate.actor_id,
            &template,
            Some(deadline),
        )
    })
    .await;
    let state = coland_storage_postgres::PgMlsGroupCurrentStore {
        pool: fixture.pool.clone(),
    }
    .current(&candidate.creation_scope)
    .await
    .unwrap()
    .unwrap()
    .value;
    let request = MlsMemberRosterAuthorityReadRequestBody {
        realm_id: fixture.realm.clone(),
        effective_scope: candidate.creation_scope.clone(),
        mls_group_id: candidate.creation_scope.canonical_mls_group_id().unwrap(),
        target_commit_event_ref: state.current_mls_commit_event_ref.clone(),
        target_epoch: state.epoch,
        caller_actor_id: candidate.actor_id.clone(),
        cursor: None,
    };
    let mut response = boxed_step(|| {
        boundary_native_response(
            fixture,
            &fixture.state,
            authority,
            arkret_wire::peer_operation_paths::PATH_SELF_MLS_ROSTER_AUTHORITY,
            ServiceOperationId::SelfMlsReadRosterAuthorityV1,
            Some(json!(request)),
        )
    })
    .await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    let page: MlsSelfRosterAuthorityReadOutcome = response.take_json().await.unwrap();
    assert!(page.roster.next_cursor.is_none());
    let pages = vec![page];
    let peer = arkret::verify_mls_member_roster_authority_pages(&pages, &request).unwrap();
    let material_request =
        arkret::mls_roster_genesis_material_request(&peer, &pages[0].roster.manifest);
    let mut response = boxed_step(|| {
        boundary_native_response(
            fixture,
            &fixture.state,
            authority,
            arkret_wire::peer_operation_paths::PATH_SELF_MLS_GROUP_STATE_MATERIAL,
            ServiceOperationId::SelfMlsReadGroupStateMaterialV1,
            Some(json!(material_request)),
        )
    })
    .await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    let material = response.take_json().await.unwrap();
    arkret::install_verified_mls_self_roster_bindings(group, &pages, &request, &material).unwrap();
    let before = boxed_step(|| admission_read_footprint(fixture)).await;
    let mut prepared = boxed_step(|| {
        boundary_native_response(
            fixture,
            &fixture.state,
            authority,
            arkret_wire::peer_operation_paths::PATH_SELF_MLS_GROUP_STATE_MATERIAL,
            ServiceOperationId::SelfMlsReadGroupStateMaterialV1,
            Some(json!(material_request)),
        )
    })
    .await;
    assert_eq!(
        prepared.status_code,
        Some(StatusCode::OK),
        "finite real read source must first authorize actual Genesis material"
    );
    assert!(chrono::Utc::now() < deadline);
    tokio::time::sleep(
        (deadline - chrono::Utc::now()).to_std().unwrap() + std::time::Duration::from_millis(80),
    )
    .await;
    let refused = prepared.take_json::<Value>().await;
    drop(prepared);
    assert!(
        refused.is_err(),
        "prepared native MLS material must not disclose after its independent Service read source expires"
    );
    assert_eq!(
        boxed_step(|| admission_read_footprint(fixture)).await,
        before
    );
    let mut expired = boxed_step(|| {
        boundary_native_response(
            fixture,
            &fixture.state,
            authority,
            arkret_wire::peer_operation_paths::PATH_SELF_MLS_GROUP_STATE_MATERIAL,
            ServiceOperationId::SelfMlsReadGroupStateMaterialV1,
            Some(json!(material_request)),
        )
    })
    .await;
    assert_eq!(expired.status_code, Some(StatusCode::NOT_FOUND));
    let problem: Value = expired.take_json().await.unwrap();
    assert_eq!(problem["status"], 404);
    assert_eq!(problem["type"], "https://arkret.org/problems/not_found");
    assert!(problem.get("group_info_bytes_b64").is_none());
    assert!(problem.get("ratchet_tree_bytes_b64").is_none());
    assert_eq!(
        boxed_step(|| admission_read_footprint(fixture)).await,
        before
    );
    let deadline = arkret_canonical::normalize_timestamp_canonical(
        chrono::Utc::now() + chrono::Duration::seconds(30),
    );
    let _read_child = boxed_step(|| {
        admission_read_parent(
            fixture,
            package,
            &candidate.actor_id,
            &template,
            Some(deadline),
        )
    })
    .await;
    let mut head = boxed_step(|| admission_snapshot_response(fixture, authority, None)).await;
    assert_eq!(head.status_code, Some(StatusCode::OK));
    let snapshot: arkret_wire::RealmStateSnapshot = head.take_json().await.unwrap();
    admission_verify_snapshot(fixture, &snapshot);
    let mut by_ref =
        boxed_step(|| admission_snapshot_response(fixture, authority, Some(&snapshot.snapshot_id)))
            .await;
    assert_eq!(by_ref.status_code, Some(StatusCode::OK));
    assert_eq!(
        by_ref
            .take_json::<arkret_wire::RealmStateSnapshot>()
            .await
            .unwrap(),
        snapshot
    );
    let before = boxed_step(|| admission_read_footprint(fixture)).await;
    let mut prepared =
        boxed_step(|| admission_snapshot_response(fixture, authority, Some(&snapshot.snapshot_id)))
            .await;
    assert_eq!(prepared.status_code, Some(StatusCode::OK));
    assert!(chrono::Utc::now() < deadline);
    tokio::time::sleep(
        (deadline - chrono::Utc::now()).to_std().unwrap() + std::time::Duration::from_millis(80),
    )
    .await;
    let refused = prepared.take_json::<Value>().await;
    drop(prepared);
    assert!(
        refused.is_err(),
        "prepared original snapshot must lose its exact current read-source window, not return cached old bytes"
    );
    assert_eq!(
        boxed_step(|| admission_read_footprint(fixture)).await,
        before
    );
    for (reference, expected_status, expected_type) in [
        (
            None,
            StatusCode::NOT_FOUND,
            "https://arkret.org/problems/not_found",
        ),
        (
            Some(&snapshot.snapshot_id),
            StatusCode::FORBIDDEN,
            "https://arkret.org/problems/capability_denied",
        ),
    ] {
        let mut response =
            boxed_step(|| admission_snapshot_response(fixture, authority, reference)).await;
        assert_eq!(response.status_code, Some(expected_status));
        let problem: Value = response.take_json().await.unwrap();
        assert_eq!(problem["type"], expected_type);
        for field in [
            "snapshot_id",
            "realm_id",
            "governance_generation",
            "purpose",
            "history_basis",
            "visible_stream_heads",
            "current_state_entries",
            "retention_and_history_floor",
            "created_at",
            "signature",
        ] {
            assert!(
                problem.get(field).is_none(),
                "refused snapshot exposed {field}"
            );
        }
    }
    assert_eq!(
        boxed_step(|| admission_read_footprint(fixture)).await,
        before
    );
    let restored = boxed_step(|| {
        admission_read_parent(fixture, package, &candidate.actor_id, &template, None)
    })
    .await;
    let mut response =
        boxed_step(|| admission_snapshot_response(fixture, authority, Some(&snapshot.snapshot_id)))
            .await;
    assert_eq!(
        response.status_code,
        Some(StatusCode::OK),
        "a new legitimate read source restores eligibility for the same archived snapshot"
    );
    let same: arkret_wire::RealmStateSnapshot = response.take_json().await.unwrap();
    assert_eq!(same, snapshot);
    admission_verify_snapshot(fixture, &same);
    restored
}
