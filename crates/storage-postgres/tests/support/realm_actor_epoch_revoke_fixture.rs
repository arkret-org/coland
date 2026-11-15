// Included in realm_native_fixture. Real Gov TCP/TLS, native Service WebVH
// rotation, PG and original signatures. AA remains the existing fixture mock.
async fn epoch_transaction(
    fixture: &Fixture,
    package: &AppletPackage,
    body: &Value,
    identity: &str,
) -> (StatusCode, Value) {
    let bytes = arkret_canonical::canonical_json_bytes(body).unwrap();
    let digest = content_digest_header(&bytes);
    let path = "/_arkret/edge/applet/transactions";
    let url = format!(
        "{}{path}",
        fixture.state.config().public_base_url.trim_end_matches('/')
    );
    let parsed = Url::parse(&url).unwrap();
    let operation = arkret_wire::ServiceOperationId::EDGE_APPLET_COMMAND_TRANSACTION_V1;
    let parts = SignedRequestParts {
        method: "POST".into(),
        target_uri: url.clone(),
        authority: parsed[url::Position::BeforeHost..url::Position::AfterPort].into(),
        path: path.into(),
        headers: vec![
            ("arkret-operation".into(), operation.into()),
            ("content-type".into(), "application/json".into()),
            ("content-digest".into(), digest.clone()),
            ("source-service-id".into(), package.service_id.to_string()),
            (
                "destination-service-id".into(),
                fixture.state.service_id().to_owned(),
            ),
            ("idempotency-key".into(), identity.into()),
        ],
        body_digest: Some(digest.clone()),
    };
    let signed = sign_http_message_for_scenario(
        &parts,
        HttpSignatureScenario::AppletTransactionV1,
        &[],
        "sig1",
        package.webhook_signature_policy.key_ref.as_str(),
        chrono::Utc::now().timestamp(),
        &applet_service_signing_key(&package.webhook_signature_policy.key_ref),
    )
    .unwrap();
    let response = native_http_client(std::time::Duration::from_secs(90))
        .post(url)
        .header("arkret-operation", operation)
        .header("content-type", "application/json")
        .header("content-digest", digest)
        .header("source-service-id", package.service_id.as_str())
        .header("destination-service-id", fixture.state.service_id())
        .header("idempotency-key", identity)
        .header("signature-input", signed.signature_input_header)
        .header("signature", signed.signature_header)
        .body(bytes)
        .send()
        .await
        .unwrap();
    (response.status(), response.json().await.unwrap())
}

/// Same existing SDK-native rotation as the material fixture, but anchored
/// strictly after the accepted A Commit, never backdated to now-minus-one.
async fn epoch_b_package(
    fixture: &Fixture,
    native: &NativeService,
    accepted_a_at: chrono::DateTime<chrono::Utc>,
) -> (AppletPackage, AppletRegistrationEpochEvidence) {
    let old = native.service_resolution.lock().unwrap().clone();
    let ResolutionMethodHistoryEvidence::WebvhLog {
        mut log_entries,
        witness_records,
        ..
    } = old.method_history_evidence
    else {
        panic!("actual Service WebVH history required");
    };
    assert_eq!(
        log_entries.len(),
        1,
        "this fixture performs one real A-to-B rotation"
    );
    let previous_at: chrono::DateTime<chrono::Utc> = log_entries.last().unwrap()["versionTime"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let earliest = accepted_a_at.max(previous_at) + chrono::Duration::seconds(1);
    let at = loop {
        let now = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        if now >= earliest {
            break now;
        }
        tokio::time::sleep((earliest - now).to_std().unwrap()).await;
    };
    let did = applet_service_did(&native.package);
    let method = DidUrl::new(format!("{did}#applet-native-key-new")).unwrap();
    let mut document = log_entries.last().unwrap()["state"].clone();
    document["verificationMethod"]
        .as_array_mut()
        .unwrap()
        .retain(|entry| entry["id"] != native.package.webhook_signature_policy.key_ref.as_str());
    document["verificationMethod"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":method,"type":"Multikey","controller":did,
            "publicKeyMultibase":arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                SigningKey::from_bytes(&[44;32]).verifying_key().as_bytes()),
        }));
    document["assertionMethod"] = json!([method]);
    document["authentication"] = json!([method]);
    let authority = Url::parse(&native.package.base_url)
        .unwrap()
        .authority()
        .to_owned();
    let inception = fixture_applet_service_inception(&authority);
    assert_eq!(inception.did, did.as_str());
    let next = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        SigningKey::from_bytes(&[45; 32]).verifying_key().as_bytes(),
    );
    let rotation = arkret_signatures::webvh::prepare_service_rotation(
        &arkret_signatures::webvh::ServiceRotationInput {
            did: did.as_str(),
            previous_entries: &log_entries,
            state: &document,
            current_update_seed: &inception.next_update_key_seed,
            next_update_public_key_multibase: &next,
            version_created_at: at,
        },
    )
    .unwrap();
    log_entries.push(rotation.log_entry);
    let source = arkret_identity::build_authenticated_webvh_service_resolution(
        native.package.service_id.clone(),
        "applet_service".into(),
        serde_json::from_value(log_entries.last().unwrap()["state"].clone()).unwrap(),
        log_entries,
        witness_records,
        chrono::Utc::now(),
    )
    .unwrap();
    let actual =
        arkret_identity::authenticated_service_document_at(&source, &native.package.service_id, at)
            .unwrap();
    assert!(
        arkret_identity::public_key_material_from_document(
            &actual,
            &native.package.webhook_signature_policy.key_ref
        )
        .is_err(),
        "A method really is absent from B current document"
    );
    let epoch = AppletRegistrationEpochEvidence::from_did_document(
        &actual,
        AppletDidMethodVersionEvidence::versioned(
            "did:webvh",
            Some(
                source
                    .method_history_evidence
                    .boundary()
                    .to_version_id
                    .clone(),
            ),
            None,
        )
        .unwrap(),
    )
    .unwrap();
    let record = coland_storage::WebvhDocumentRecord {
        did: did.to_string(),
        did_document: json!(source.normalized_did_document),
        key_log_head: Some(
            source
                .method_history_evidence
                .boundary()
                .to_method_history_head
                .clone(),
        ),
        sequence: 2,
        method_evidence: json!(source.method_history_evidence),
        fetched_at: at,
        expires_at: at + chrono::Duration::minutes(15),
        updated_at: at,
    };
    *native.service_resolution.lock().unwrap() = source;
    let resolution_url = format!(
        "{}{}",
        native.package.base_url.trim_end_matches('/'),
        arkret_models_identity::canonical_service_resolution_path(&native.package.service_id)
    );
    let response = native_http_client(std::time::Duration::from_secs(30))
        .get(resolution_url)
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the actual Service endpoint serves its native B history"
    );
    let served: arkret_models_identity::AuthenticatedServiceResolution =
        response.json().await.unwrap();
    let expected = native.service_resolution.lock().unwrap().clone();
    assert_eq!(
        arkret_canonical::canonical_json_bytes(&served).unwrap(),
        arkret_canonical::canonical_json_bytes(&expected).unwrap()
    );
    let served_document =
        arkret_identity::authenticated_service_document_at(&served, &native.package.service_id, at)
            .unwrap();
    assert_eq!(
        arkret_canonical::canonical_json_bytes(&served_document).unwrap(),
        arkret_canonical::canonical_json_bytes(&actual).unwrap()
    );
    let ResolutionMethodHistoryEvidence::WebvhLog { log_entries, .. } =
        &served.method_history_evidence
    else {
        panic!("the actual remote resolution must retain both WebVH epochs");
    };
    assert_eq!(log_entries.len(), 2);
    fixture
        .state
        .test_persistence()
        .webvh()
        .put_document(record.clone())
        .await
        .unwrap();
    fixture
        .state
        .test_cache_resolved_webvh_record(coland_services::identity::DidDocumentState {
            did: record.did,
            did_document: record.did_document,
            key_log_head: record.key_log_head,
            sequence: record.sequence,
            method_evidence: record.method_evidence,
            fetched_at: record.fetched_at,
            expires_at: record.expires_at,
            updated_at: record.updated_at,
        })
        .unwrap();
    let mut package = native.package.clone();
    let publisher = package.proof.as_ref().unwrap().verification_method.clone();
    package.webhook_signature_policy.key_ref = method;
    package.created_at = at;
    package.stamp_registration_epoch(&epoch).unwrap();
    package.stamp_package_digest().unwrap();
    let controller = arkret_identity::verification_method_did(publisher.as_str()).unwrap();
    package
        .sign(
            &Ed25519PayloadSigner::from_did_key_seed([13; 32], controller, publisher.clone()),
            &publisher,
        )
        .unwrap();
    package.validate_with_epoch_evidence(&epoch).unwrap();
    assert_eq!(package.service_id, native.package.service_id);
    assert_ne!(
        package.registration_epoch,
        native.package.registration_epoch
    );
    (package, epoch)
}

pub(super) async fn service_epoch_revoke_and_original_recovery(pool: PgPool) {
    use arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact;
    use arkret_models_collaboration::events_payloads::CapabilityRevokePayload;
    use arkret_models_collaboration::governance::grant_constraint::{
        GrantConstraintKind, GrantConstraintSubkind,
    };
    let (fixture, _governor) = boxed_step(|| network_fixture(pool.clone())).await;
    let factory = AppletAuthoringFactory {
        fixture,
        packages: Default::default(),
        scopes: Default::default(),
    };
    let applet = AppletId::new(format!("ak:applet:{}", uuid::Uuid::now_v7())).unwrap();
    let mut native = NativeService::new(&applet, &factory.fixture.state.service_core_id());
    realm_actor_mls_fixture::enable(&mut native.package);
    factory
        .packages
        .lock()
        .await
        .insert(applet.to_string(), native.package.clone());
    let install = boxed_step(|| factory.prepare_install(&applet, "epoch-revoke")).await;
    let fixture = &factory.fixture;
    let coland_storage::AppletAdmissionRequest::Install(a_body) = &install.input.candidate.request;
    let (status, value) = boxed_step(|| async {
        fixture
            .admin_post_network(
                "/_arkret/self/applets/install",
                arkret_wire::ServiceOperationId::SELF_APPLET_COMMAND_INSTALL_V1,
                &json!(a_body),
                "epoch-initial-install",
            )
            .await
    })
    .await;
    assert_eq!(status, StatusCode::CREATED, "real A install: {value}");
    let a_install: AppletInstallResponseBody = serde_json::from_value(value).unwrap();
    let provision = a_body
        .authoring_request_basis
        .capability_grant_events
        .iter()
        .find(|event| {
            event.payload["grant"]["actions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|action| action == "ak.applet.bot.provision")
        })
        .unwrap();
    let provision = arkret_wire::GrantId::from_event_id(&provision.event_id);
    let (actor, actor_signer) = authority_admission_candidate(
        &native.package,
        fixture,
        &a_install.registration_event_ref,
        &provision,
        true,
        &native.archive,
    );
    let create = authority_admission_create(&actor, &actor_signer);
    let (status, value) =
        boxed_step(|| authority_admission_send(fixture, &native.package, &create)).await;
    assert_eq!(status, StatusCode::OK, "genuine A Bot: {value}");
    let scope = install.effective_scope.clone();
    let parent = boxed_step(|| {
        realm_actor_mls_fixture::business_parent(fixture, &native.package, &actor.actor_id, &scope)
    })
    .await;
    let original = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&EventId::from_token_bytes(parent.token_bytes()).unwrap())
        .await
        .unwrap()
        .unwrap();
    let mut child: CapabilityGrantCreateBody =
        serde_json::from_value(original.event.payload["grant"].clone()).unwrap();
    let service = ActorId::service(native.package.service_id.clone());
    child.issuer_id = service.clone();
    child.subject = CapabilitySubject::Actor(actor.actor_id.clone());
    child.issuer_authority_refs = vec![IssuerAuthorityRef::Grant {
        grant_id: parent.clone(),
    }];
    child.issued_at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    for c in &mut child.constraints {
        if c.constraint_subkind == Some(GrantConstraintSubkind::AppletAuthority) {
            c.executed_by = Some(actor.actor_id.clone());
        } else if c.constraint_kind == GrantConstraintKind::AuthorityControl
            && c.constraint_subkind.is_none()
        {
            c.allowed_managed_actor_roles.clear();
            c.max_authority_depth = Some(0);
            c.authority_regrant_allowed = Some(false);
        }
    }
    let signer_a = Ed25519PayloadSigner::new(
        applet_service_signing_key(&native.package.webhook_signature_policy.key_ref),
        applet_service_did(&native.package),
        native.package.webhook_signature_policy.key_ref.clone(),
    );
    let event_a = realm_actor_mls_fixture::signed_event(
        &native.package,
        service.clone(),
        scope.clone(),
        EventKind::CapabilityGrant,
        json!(CapabilityGrantPayload { grant: child }),
        Some(&parent),
        &signer_a,
    );
    let child_id = arkret_wire::GrantId::from_event_id(&event_a.event_id);
    let a_request = json!(AppletEventTransactionRequestBody {
        applet_id: applet.clone(),
        source_id: native.package.service_id.clone(),
        events: vec![event_a.clone()],
        committed_events: vec![],
        signals: vec![]
    });
    let a_identity = format!("epoch-original-A-{}", uuid::Uuid::now_v7());
    let (status, value) =
        boxed_step(|| epoch_transaction(fixture, &native.package, &a_request, &a_identity)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "A producer and HTTP really accepted: {value}"
    );
    let a_outcome = boxed_step(|| {
        realm_actor_mls_fixture::grant_boundary_assert_accepted(fixture, &event_a, value)
    })
    .await;
    let a_record = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&event_a.event_id)
        .await
        .unwrap()
        .unwrap();
    let a_full = arkret_wire::CommittedEventFullView {
        event: a_record.event,
        commit: a_record.commit,
    };
    let a_fact = fixture
        .state
        .test_persistence()
        .authority_commits()
        .producer_signer_fact(&event_a, &a_full.commit)
        .await
        .unwrap()
        .unwrap();
    let suite = event_a.realm_id.digest_suite_code().digest_suite();
    a_fact.validate_commit_binding(&a_full, suite).unwrap();
    arkret_identity::account_device_signer_evidence::verify_historical_producer_event_signature(
        &event_a, &a_fact, suite,
    )
    .unwrap();
    let rows = fixture
        .state
        .test_persistence()
        .capability_grant_current_states()
        .snapshot_for_realm(&fixture.realm)
        .await
        .unwrap();
    let parent_row = rows.iter().find(|row| row.grant_id == parent).unwrap();
    let close = fixture.admin_event(
        EventKind::CapabilityRevoke,
        scope.clone(),
        json!(CapabilityRevokePayload {
            grant_id: parent.clone(),
            expected_commit_id: parent_row.revision.commit_id.clone(),
            reason: Some("business parent closed before key rotation".into()),
        }),
    );
    let close =
        arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequestBody::Event(
            arkret_wire::EventAdmissionSubmission::new(close),
        );
    let (status, value) = boxed_step(|| async {
        fixture
            .admin_post_network(
                "/_arkret/self/events",
                arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
                &json!(close),
                "epoch-close-A-parent",
            )
            .await
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "real A business-parent revocation: {value}"
    );
    let closed: arkret_models_collaboration::authority_commit::SelfAuthoritySubmitResponseBody =
        serde_json::from_value(value).unwrap();
    closed.validate_for_request(&close).unwrap();

    // Prepare a legitimate A template now. Calling the generic factory after
    // rotation would reconstruct/cache inception A, so B is derived below only
    // from the actually served native B resolution and typed closed models.
    let template = boxed_step(|| factory.prepare_install(&applet, "epoch-revoke")).await;
    let coland_storage::AppletAdmissionRequest::Install(template) =
        &template.input.candidate.request;
    let mut b_body = (**template).clone();
    let previous: AppletRegistrationPayload = serde_json::from_value(json!(
        b_body.authoring_request_basis.registration_event.payload
    ))
    .unwrap();
    let (package_b, epoch_b) =
        boxed_step(|| epoch_b_package(fixture, &native, a_full.commit.committed_at)).await;
    b_body.applet_package = package_b.clone();
    b_body.authoring_request_basis.package_digest = package_b.package_digest.clone().unwrap();
    b_body.authoring_request_basis.registration_event = fixture.admin_event(
        EventKind::AppletRegistration,
        ScopeRef::realm(fixture.realm.clone()),
        json!(
            package_b
                .to_registration(&epoch_b, previous.expected_commit_id)
                .unwrap()
        ),
    );
    for event in &mut b_body.authoring_request_basis.capability_grant_events {
        let mut payload: CapabilityGrantPayload =
            serde_json::from_value(json!(event.payload)).unwrap();
        for c in &mut payload.grant.constraints {
            if c.constraint_subkind == Some(GrantConstraintSubkind::AppletAuthority) {
                c.registration_epoch = Some(package_b.registration_epoch.clone());
            }
        }
        *event = fixture.admin_event(
            EventKind::CapabilityGrant,
            ScopeRef::realm(fixture.realm.clone()),
            json!(payload),
        );
    }
    boxed_step(|| install_admission_repreview(fixture, &mut b_body)).await;
    let (status, value) = boxed_step(|| async {
        fixture
            .admin_post_network(
                "/_arkret/self/applets/install",
                arkret_wire::ServiceOperationId::SELF_APPLET_COMMAND_INSTALL_V1,
                &json!(b_body),
                "epoch-real-B-install",
            )
            .await
    })
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "actual B registration/installation: {value}"
    );
    let b_install: AppletInstallResponseBody = serde_json::from_value(value).unwrap();
    assert_eq!(b_install.service_id, a_install.service_id);
    assert_ne!(b_install.registration_epoch, a_install.registration_epoch);
    assert_ne!(b_install.install_id, a_install.install_id);

    let before = boxed_step(|| source_tuple_footprint(fixture)).await;
    let (status, problem) =
        boxed_step(|| epoch_transaction(fixture, &package_b, &a_request, &a_identity)).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "same delivery ID cannot change its current key/epoch record: {problem}"
    );
    assert_eq!(
        problem["type"],
        "https://arkret.org/problems/duplicate_conflict"
    );
    assert_eq!(boxed_step(|| source_tuple_footprint(fixture)).await, before);
    let (status, problem) = boxed_step(|| {
        epoch_transaction(
            fixture,
            &native.package,
            &a_request,
            "epoch-retired-A-transport",
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "A HTTP key really is retired: {problem}"
    );
    assert_eq!(
        problem["type"],
        "https://arkret.org/problems/http_signature_invalid"
    );
    assert_eq!(boxed_step(|| source_tuple_footprint(fixture)).await, before);
    let business_before = boxed_step(|| native_business_footprint(fixture)).await;
    let (status, value) = boxed_step(|| {
        epoch_transaction(
            fixture,
            &package_b,
            &a_request,
            "epoch-current-B-recovers-A",
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "B HTTP recovers the exact accepted A Event: {value}"
    );
    let recovered: AppletTransactionResponseBody = serde_json::from_value(value).unwrap();
    assert_eq!(recovered, a_outcome);
    assert_eq!(
        boxed_step(|| native_business_footprint(fixture)).await,
        business_before
    );
    let unchanged = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&event_a.event_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(unchanged.event, event_a);
    assert_eq!(unchanged.commit, a_full.commit);
    let unchanged_fact = fixture
        .state
        .test_persistence()
        .authority_commits()
        .producer_signer_fact(&event_a, &unchanged.commit)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        arkret_canonical::canonical_json_bytes(&unchanged_fact).unwrap(),
        arkret_canonical::canonical_json_bytes(&a_fact).unwrap()
    );

    let signer_b = Ed25519PayloadSigner::new(
        applet_service_signing_key(&package_b.webhook_signature_policy.key_ref),
        applet_service_did(&package_b),
        package_b.webhook_signature_policy.key_ref.clone(),
    );
    let revoke = realm_actor_mls_fixture::signed_event(
        &package_b,
        service,
        scope,
        EventKind::CapabilityRevoke,
        json!(CapabilityRevokePayload {
            grant_id: child_id.clone(),
            expected_commit_id: a_full.commit.commit_id.clone(),
            reason: Some("original issuer cleanup using current B".into())
        }),
        Some(&parent),
        &signer_b,
    );
    let revoke_body = json!(AppletEventTransactionRequestBody {
        applet_id: applet,
        source_id: package_b.service_id.clone(),
        events: vec![revoke.clone()],
        committed_events: vec![],
        signals: vec![]
    });
    let (status, value) = boxed_step(|| {
        epoch_transaction(
            fixture,
            &package_b,
            &revoke_body,
            "epoch-current-B-fresh-revoke",
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "fresh B producer, B HTTP, historical A target: {value}"
    );
    let revoked = boxed_step(|| {
        realm_actor_mls_fixture::grant_boundary_assert_accepted(fixture, &revoke, value)
    })
    .await;
    let record = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&revoke.event_id)
        .await
        .unwrap()
        .unwrap();
    let fact = fixture
        .state
        .test_persistence()
        .authority_commits()
        .producer_signer_fact(&revoke, &record.commit)
        .await
        .unwrap()
        .unwrap();
    let HistoricalProducerSignerFact::Service(source) = &fact else {
        panic!("real B Service signer fact required");
    };
    assert_eq!(
        source.verification_method,
        package_b.webhook_signature_policy.key_ref
    );
    assert_eq!(source.key.registration_epoch, b_install.registration_epoch);
    let b_registration = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&b_install.registration_event_ref)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        source.key.registration_ref,
        arkret_wire::CommittedEventRef {
            event_id: b_registration.event.event_id,
            commit_id: b_registration.commit.commit_id,
            stream_ref: b_registration.commit.stream_ref,
            stream_position: b_registration.commit.stream_position,
        }
    );
    assert_eq!(
        source.key.authorization_ref,
        arkret_wire::CommittedEventRef {
            event_id: original.event.event_id,
            commit_id: original.commit.commit_id,
            stream_ref: original.commit.stream_ref,
            stream_position: original.commit.stream_position,
        }
    );
    let HistoricalProducerSignerFact::Service(a_source) = &a_fact else {
        panic!("the original A Event retains its exact Service fact");
    };
    assert_ne!(
        source.key.public_key_base64url,
        a_source.key.public_key_base64url
    );
    assert_ne!(source.verification_method, a_source.verification_method);
    let full = arkret_wire::CommittedEventFullView {
        event: record.event,
        commit: record.commit,
    };
    fact.validate_commit_binding(&full, suite).unwrap();
    arkret_identity::account_device_signer_evidence::verify_historical_producer_event_signature(
        &revoke, &fact, suite,
    )
    .unwrap();
    let rows = fixture
        .state
        .test_persistence()
        .capability_grant_current_states()
        .snapshot_for_realm(&fixture.realm)
        .await
        .unwrap();
    for id in [&parent, &child_id] {
        assert_eq!(
            rows.iter().find(|r| &r.grant_id == id).unwrap().status,
            coland_storage::CapabilityGrantCurrentStatus::Revoked
        );
    }
    let business_before = boxed_step(|| native_business_footprint(fixture)).await;
    let (status, value) = boxed_step(|| {
        epoch_transaction(
            fixture,
            &package_b,
            &revoke_body,
            "epoch-current-B-revoke-replay",
        )
    })
    .await;
    assert_eq!(status, StatusCode::OK, "B Revoke exact recovery: {value}");
    assert_eq!(
        serde_json::from_value::<AppletTransactionResponseBody>(value).unwrap(),
        revoked
    );
    assert_eq!(
        boxed_step(|| native_business_footprint(fixture)).await,
        business_before
    );
    let (status, value) = boxed_step(|| {
        epoch_transaction(
            fixture,
            &package_b,
            &a_request,
            "epoch-B-recovers-A-after-revoke",
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an exact A receipt remains recoverable after B revoked the child: {value}"
    );
    assert_eq!(
        serde_json::from_value::<AppletTransactionResponseBody>(value).unwrap(),
        a_outcome
    );
    let rows = fixture
        .state
        .test_persistence()
        .capability_grant_current_states()
        .snapshot_for_realm(&fixture.realm)
        .await
        .unwrap();
    let current = rows.iter().find(|row| row.grant_id == child_id).unwrap();
    assert_eq!(
        current.status,
        coland_storage::CapabilityGrantCurrentStatus::Revoked
    );
    assert_eq!(
        current.revision.commit_id, full.commit.commit_id,
        "recovering an accepted Grant must not reapply it over the later Revoke"
    );
    assert_eq!(
        boxed_step(|| native_business_footprint(fixture)).await,
        business_before
    );
    arkret_identity::account_device_signer_evidence::verify_historical_producer_event_signature(
        &event_a, &a_fact, suite,
    )
    .unwrap();
}
