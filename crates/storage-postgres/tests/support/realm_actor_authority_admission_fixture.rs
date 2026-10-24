// Included in realm_native_fixture. Every candidate retains its real native
// inception, control signature and Service-authored outer Event.

fn authority_admission_candidate(
    package: &AppletPackage,
    fixture: &Fixture,
    registration: &EventId,
    grant: &arkret_wire::GrantId,
    bot: bool,
) -> (RealmActorCreatePayload, Ed25519PayloadSigner) {
    let (mut candidate, signer) = realm_candidate(package, &fixture.realm, registration, grant);
    candidate.request_id = uuid::Uuid::now_v7().simple().to_string();
    if bot {
        candidate.actor_role = RealmActorCreatePayloadActorRole::Bot;
        candidate.external_ref = None;
    } else {
        candidate.external_ref.as_mut().unwrap().external_id =
            format!("authority-boundary-{}", uuid::Uuid::now_v7());
    }
    candidate.control_signature = sign_detached_object(
        &candidate.creation_transcript(),
        DetachedSignatureContext::RealmActorCreation,
        candidate.control_method_kid.clone(),
        candidate.control_signature.created_at,
        &SigningKey::from_bytes(&[33; 32]),
    )
    .unwrap();
    arkret_identity::verify_realm_actor_initial_resolution(&candidate, chrono::Utc::now()).unwrap();
    (candidate, signer)
}

fn authority_admission_create(
    candidate: &RealmActorCreatePayload,
    signer: &Ed25519PayloadSigner,
) -> arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequestBody {
    let event = arkret::author_realm_actor_create(
        candidate.clone(),
        arkret_canonical::DigestSuite::Sha256,
        candidate.control_signature.created_at,
        signer,
    )
    .unwrap();
    arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequestBody::Event(
        arkret_wire::EventAdmissionSubmission::new(event),
    )
}

async fn authority_admission_send(
    fixture: &Fixture,
    package: &AppletPackage,
    request: &arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequestBody,
) -> (StatusCode, Value) {
    fixture
        .service_post(
            package,
            "/_arkret/self/events",
            arkret_wire::ServiceOperationId::SelfEventsCommandSubmitV1.as_str(),
            &json!(request),
            &format!("authority-boundary-{}", uuid::Uuid::now_v7()),
        )
        .await
}

pub(super) async fn run_authority_admission(pool: PgPool) {
    let (fixture, _governor) = boxed_step(|| network_fixture(pool.clone())).await;
    let factory = AppletAuthoringFactory {
        fixture,
        packages: Default::default(),
        scopes: Default::default(),
    };
    let id = AppletId::new(format!("ak:applet:{}", uuid::Uuid::now_v7())).unwrap();
    let mut native = NativeService::new(&id, &factory.fixture.state.service_core_id());
    realm_actor_mls_fixture::enable(&mut native.package);
    native
        .package
        .requested_scopes
        .push("ak.applet.bridge_error".into());
    native.package.requested_scopes.sort();
    install_admission_resign_package(&mut native.package);
    factory
        .packages
        .lock()
        .await
        .insert(id.to_string(), native.package.clone());
    let install = boxed_step(|| factory.prepare_install(&id, "realm-authority-admission")).await;
    let outcome = boxed_step(|| commit_install_http(&factory.fixture, &install)).await;
    let coland_storage::AppletAdmissionRequest::Install(body) = &install.input.candidate.request;
    let package = &body.applet_package;
    let basis = &body.authoring_request_basis;
    let registration = &basis.registration_event.event_id;
    assert_eq!(&outcome.registration_event_ref, registration);
    let grant_for = |action: &str| {
        let event = basis
            .capability_grant_events
            .iter()
            .find(|event| {
                event.payload["grant"]["actions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|value| value == action)
            })
            .unwrap();
        arkret_wire::GrantId::from_event_id(&event.event_id)
    };
    let bot_grant = grant_for("ak.applet.bot.provision");
    let ghost_grant = grant_for("ak.applet.ghost.provision");
    let mut actors = Vec::new();
    let mut originals = Vec::new();
    for _ in 0..2 {
        let (candidate, signer) = authority_admission_candidate(
            package,
            &factory.fixture,
            registration,
            &bot_grant,
            true,
        );
        let request = authority_admission_create(&candidate, &signer);
        let (status, value) =
            boxed_step(|| authority_admission_send(&factory.fixture, package, &request)).await;
        assert_eq!(status, StatusCode::OK, "independent Bot creation: {value}");
        let arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequestBody::Event(
            submission,
        ) = &request
        else {
            unreachable!()
        };
        let original = factory
            .fixture
            .state
            .test_persistence()
            .authority_commits()
            .committed_event(&submission.event.event_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(original.event, submission.event);
        boxed_step(|| private_material(&factory.fixture, &candidate, &original.commit)).await;
        let before = boxed_step(|| native_business_footprint(&factory.fixture)).await;
        let (status, replay) =
            boxed_step(|| authority_admission_send(&factory.fixture, package, &request)).await;
        assert_eq!(status, StatusCode::OK, "independent Bot retry: {replay}");
        assert_eq!(
            boxed_step(|| native_business_footprint(&factory.fixture)).await,
            before,
            "exact Bot creation retry cannot create another identity, outcome or quota use"
        );
        actors.push(candidate.actor_id);
        originals.push(original);
    }
    assert_ne!(actors[0], actors[1]);
    assert_ne!(originals[0].event.event_id, originals[1].event.event_id);
    assert_ne!(originals[0].commit.commit_id, originals[1].commit.commit_id);
    let bridge_grant = grant_for("ak.applet.bridge_error");
    boxed_step(|| {
        realm_actor_mls_fixture::grant_authority_boundaries(
            &factory.fixture,
            package,
            &actors[0],
            registration,
            &bridge_grant,
        )
    })
    .await;

    let mut foreign_namespace = package.clone();
    foreign_namespace.base_url = "https://outside-registered-namespace.example/".into();
    let (outside, signer) = authority_admission_candidate(
        &foreign_namespace,
        &factory.fixture,
        registration,
        &ghost_grant,
        false,
    );
    let request = authority_admission_create(&outside, &signer);
    let (status, value) =
        boxed_step(|| authority_admission_send(&factory.fixture, package, &request)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "Ghost DID host is independent of Service host: {value}"
    );
    let arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequestBody::Event(
        submission,
    ) = &request
    else {
        unreachable!()
    };
    let accepted = factory
        .fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&submission.event.event_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(accepted.event, submission.event);
    assert_eq!(accepted.commit.event_ref, submission.event.event_id);
    assert_eq!(accepted.event.payload["actor_id"], json!(outside.actor_id));
    boxed_step(|| private_material(&factory.fixture, &outside, &accepted.commit)).await;
    let before = boxed_step(|| native_business_footprint(&factory.fixture)).await;
    let (status, replay) =
        boxed_step(|| authority_admission_send(&factory.fixture, package, &request)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "independently hosted Ghost exact retry: {replay}"
    );
    let replay: arkret_models_collaboration::authority_commit::SelfAuthoritySubmitResponseBody =
        serde_json::from_value(replay).unwrap();
    replay.validate_for_request(&request).unwrap();
    let arkret_models_collaboration::authority_commit::SelfAuthoritySubmitResponseBody::Ordinary(
        arkret_wire::AuthoritySubmitResponseBody::Accepted { commit, .. },
    ) = replay
    else {
        panic!("independently hosted Ghost retry must recover its original Commit")
    };
    assert_eq!(commit, accepted.commit);
    assert_eq!(
        boxed_step(|| native_business_footprint(&factory.fixture)).await,
        before,
        "independent DID hosting must not duplicate the accepted creation or its effects"
    );

    let (accepted_candidate, signer) =
        authority_admission_candidate(package, &factory.fixture, registration, &ghost_grant, false);
    let accepted = authority_admission_create(&accepted_candidate, &signer);
    let (status, value) =
        boxed_step(|| authority_admission_send(&factory.fixture, package, &accepted)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "accepted before grant closure: {value}"
    );
    let (fresh, signer) =
        authority_admission_candidate(package, &factory.fixture, registration, &ghost_grant, false);
    let fresh = authority_admission_create(&fresh, &signer);
    let rows = factory
        .fixture
        .state
        .test_persistence()
        .capability_grant_current_states()
        .snapshot_for_realm(&factory.fixture.realm)
        .await
        .unwrap();
    let current = rows.iter().find(|row| row.grant_id == ghost_grant).unwrap();
    let close = factory.fixture.admin_event(
        EventKind::CapabilityRevoke,
        ScopeRef::Realm { realm_id: factory.fixture.realm.clone() },
        json!({"grant_id":ghost_grant,"expected_revision":current.revision,"reason":"creation source closed after candidate signing"}),
    );
    let (status, value) = factory
        .fixture
        .admin_post(
            "/_arkret/self/events",
            arkret_wire::ServiceOperationId::SelfEventsCommandSubmitV1.as_str(),
            &json!(
                arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequestBody::Event(
                    arkret_wire::EventAdmissionSubmission::new(close)
                )
            ),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "close real creation grant: {value}");
    let before = boxed_step(|| native_business_footprint(&factory.fixture)).await;
    let (status, problem) =
        boxed_step(|| authority_admission_send(&factory.fixture, package, &fresh)).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "fresh signed candidate: {problem}"
    );
    assert_eq!(
        problem["type"],
        "https://arkret.org/problems/capability_denied"
    );
    assert_eq!(
        boxed_step(|| native_business_footprint(&factory.fixture)).await,
        before,
        "a previously signed fresh candidate must recheck its exact creation grant"
    );
    let (status, value) =
        boxed_step(|| authority_admission_send(&factory.fixture, package, &accepted)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "already accepted exact retry: {value}"
    );
    assert_eq!(
        boxed_step(|| native_business_footprint(&factory.fixture)).await,
        before
    );
    let creations = PgAuthorityCommitStore { pool }
        .applet_realm_actor_creations(&factory.fixture.realm, &id, Some(&package.service_id))
        .await
        .unwrap();
    assert_eq!(creations.len(), 4);
    assert!(
        creations
            .iter()
            .any(|record| record.event.payload["actor_id"] == json!(outside.actor_id))
    );
    for actor in actors {
        assert!(
            creations
                .iter()
                .any(|record| record.event.payload["actor_id"] == json!(actor))
        );
    }
    let first_candidate: RealmActorCreatePayload =
        serde_json::from_value(json!(originals[0].event.payload)).unwrap();
    boxed_step(|| {
        run_active_revoke(
            &factory.fixture,
            package,
            &first_candidate,
            &originals[0].commit,
        )
    })
    .await;
    boxed_step(|| {
        authority_material_survives_service_rotation(&factory.fixture, &native, &outcome)
    })
    .await;
}

async fn authority_material_survives_service_rotation(
    fixture: &Fixture,
    native: &NativeService,
    install: &AppletInstallResponseBody,
) {
    use arkret_models_collaboration::applet_installation_authority::{
        AppletAuthorityMaterialResponseBody, AppletAuthorityMaterialRequestBody,
    };
    let path = format!(
        "/_arkret/self/applets/{}/authority/material",
        install.applet_id
    );
    let request = AppletAuthorityMaterialRequestBody {
        effective_scope: ScopeRef::Realm {
            realm_id: fixture.realm.clone(),
        },
        grant_ids: install.capability_grant_refs.clone(),
    };
    let body = json!(request);
    let operation = arkret_wire::ServiceOperationId::SelfAppletAuthorityReadMaterialV1.as_str();
    let (status, before) = fixture
        .service_post(
            &native.package,
            &path,
            operation,
            &body,
            "authority-original-service-method",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "original material: {before}");
    let original: AppletAuthorityMaterialResponseBody = serde_json::from_value(before.clone()).unwrap();
    original
        .validate_for_request(&install.applet_id, &request)
        .unwrap();
    let mut duplicate = request.clone();
    duplicate.grant_ids = vec![request.grant_ids[0].clone(), request.grant_ids[0].clone()];
    let footprint = boxed_step(|| native_business_footprint(fixture)).await;
    let (status, problem) = fixture
        .service_post(
            &native.package,
            &path,
            operation,
            &json!(duplicate),
            "authority-duplicate-original",
        )
        .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "uniqueItems violation: {problem}"
    );
    assert_eq!(
        problem["type"],
        "https://arkret.org/problems/schema_violation"
    );
    assert_eq!(
        boxed_step(|| native_business_footprint(fixture)).await,
        footprint
    );
    let account = ActorId::account(fixture.pcr.history.account.clone());
    let event=fixture.admin_event(EventKind::CapabilityGrant,request.effective_scope.clone(),json!({"grant":{
        "schema":"ak.schema.capability.v1","realm_id":fixture.realm,"issuer_id":account,"subject":account,
        "actions":["ak.event.read"],"resources":[{"kind":"realm","realm_id":fixture.realm,"match_scope":"realm_wide"}],"constraints":[],
        "issuer_authority_refs":[{"kind":"realm_root","realm_id":fixture.realm,"authority_event_ref":fixture.authority_event_ref,"authority_generation":"0"}],
        "issued_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())
    }}));
    let foreign_id = arkret_wire::GrantId::from_event_id(&event.event_id);
    let (status, value) = fixture
        .admin_post(
            "/_arkret/self/events",
            arkret_wire::ServiceOperationId::SelfEventsCommandSubmitV1.as_str(),
            &json!(
                arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequestBody::Event(
                    arkret_wire::EventAdmissionSubmission::new(event)
                )
            ),
            None,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "real foreign subject grant: {value}"
    );
    let mut foreign = request.clone();
    foreign.grant_ids = vec![foreign_id];
    let footprint = boxed_step(|| native_business_footprint(fixture)).await;
    let (status, problem) = fixture
        .service_post(
            &native.package,
            &path,
            operation,
            &json!(foreign),
            "authority-foreign-original",
        )
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "material from a foreign subject must be unavailable: {problem}"
    );
    assert_eq!(
        boxed_step(|| native_business_footprint(fixture)).await,
        footprint
    );
    // The new unrelated grant advances the public control head. Capture the
    // unchanged requested originals again before testing Service rotation.
    let (status, before) = fixture
        .service_post(
            &native.package,
            &path,
            operation,
            &body,
            "authority-before-service-rotation",
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "current material before real rotation: {before}"
    );
    assert_eq!(
        original.registration.event.event_id,
        install.registration_event_ref
    );
    assert_eq!(
        original.grant_events.len(),
        install.capability_grant_refs.len()
    );
    for record in std::iter::once(&original.registration).chain(&original.grant_events) {
        assert_eq!(record.event.event_id, record.commit.event_ref);
        assert!(record.commit.producer_signer_fact_digest.is_some());
        let evidence = record.producer_device_evidence.as_ref().unwrap();
        arkret_identity::account_device_signer_evidence::verify_historical_account_device_signer_evidence(
            evidence,
            &fixture.pcr.history.account,
            &fixture.pcr.history.founding_device_id,
        )
        .unwrap();
    }
    let old_source = native.service_resolution.lock().unwrap().clone();
    let ResolutionMethodHistoryEvidence::WebvhLog {
        mut log_entries,
        witness_records,
        ..
    } = old_source.method_history_evidence
    else {
        panic!("real Service must have a native WebVH history");
    };
    let mut document = log_entries.last().unwrap()["state"].clone();
    let did = applet_service_did(&native.package);
    let authority = Url::parse(&native.package.base_url)
        .unwrap()
        .authority()
        .to_owned();
    let inception = fixture_applet_service_inception(&authority);
    assert_eq!(inception.did, did.as_str());
    let method = format!("{did}#applet-native-key-new");
    document["verificationMethod"]
        .as_array_mut()
        .unwrap()
        .retain(|value| value["id"] != native.package.webhook_signature_policy.key_ref.as_str());
    document["verificationMethod"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":method,"type":"Multikey","controller":did,
            "publicKeyMultibase":arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                SigningKey::from_bytes(&[44;32]).verifying_key().as_bytes()
            ),
        }));
    document["assertionMethod"] = json!([method]);
    document["authentication"] = json!([method]);
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
            version_created_at: chrono::Utc::now() - chrono::Duration::seconds(1),
        },
    )
    .unwrap();
    log_entries.push(rotation.log_entry);
    let source = arkret_identity::build_authenticated_webvh_service_resolution(
        native.package.service_id.clone(),
        "applet_service".into(),
        serde_json::from_value(document).unwrap(),
        log_entries,
        witness_records,
        chrono::Utc::now(),
    )
    .unwrap();
    *native.service_resolution.lock().unwrap() = source.clone();
    let now = chrono::Utc::now();
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
        fetched_at: now,
        expires_at: now + chrono::Duration::minutes(15),
        updated_at: now,
    };
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
    let mut rotated = native.package.clone();
    rotated.webhook_signature_policy.key_ref = DidUrl::new(method).unwrap();
    let footprint = boxed_step(|| native_business_footprint(fixture)).await;
    let (status, after) = fixture
        .service_post(
            &rotated,
            &path,
            operation,
            &body,
            "authority-current-service-method",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "rotated Service material: {after}");
    assert_eq!(
        after, before,
        "Service rotation cannot rewrite accepted installation originals"
    );
    let (status, problem) = fixture
        .service_post(
            &native.package,
            &path,
            operation,
            &body,
            "authority-removed-service-method",
        )
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "removed Service key: {problem}"
    );
    assert_eq!(
        boxed_step(|| native_business_footprint(fixture)).await,
        footprint
    );

    // Corrupt only the stored original after proving the normal historical read.
    // The current Device remains valid, so a projection-based reconstruction
    // would incorrectly make this material read succeed.
    use diesel_async::RunQueryDsl as _;
    let mut connection = fixture.pool.get().await.unwrap();
    let deleted =
        diesel::sql_query("DELETE FROM account_device_committed_evidence WHERE commit_id=$1")
            .bind::<diesel::sql_types::Text, _>(original.registration.commit.commit_id.as_str())
            .execute(&mut connection)
            .await
            .unwrap();
    assert_eq!(deleted, 1);
    drop(connection);
    let footprint = boxed_step(|| native_business_footprint(fixture)).await;
    let (status, problem) = fixture
        .service_post(
            &rotated,
            &path,
            operation,
            &body,
            "authority-missing-accepted-device-root",
        )
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "missing accepted Device root: {problem}"
    );
    assert_eq!(
        boxed_step(|| native_business_footprint(fixture)).await,
        footprint
    );
}
