// Included inside the real Realm actor fixture so these checks share its
// original Service creation, control-signed Device and authenticated HTTP path.

pub(super) async fn native_business_footprint(fixture: &Fixture) -> Value {
    use diesel::sql_types::Jsonb;
    use diesel_async::RunQueryDsl as _;
    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type = Jsonb)]
        value: Value,
    }
    let mut connection = fixture.pool.get().await.unwrap();
    let mut result = serde_json::Map::new();
    for table in [
        "canonical_events",
        "realm_commits",
        "realm_actor_creations",
        "realm_actor_current_results",
        "realm_actor_private_signer_facts",
        "principal_resolutions",
        "accounts",
        "pcr_device_generation_current_results",
        "capability_quota_counters",
        "capability_quota_buckets",
        "capability_quota_consumptions",
        "peer_keypackage_claims",
        "keypackage_claim_welcome_bindings",
        "realm_keypackage_claim_sources",
        "keypackage_claim_sources",
        "member_state_current_results",
        "actor_profile_current_results",
        "applet_managed_identities",
    ] {
        let row = diesel::sql_query(format!(
            "SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb) AS value FROM {table} r"
        ))
        .get_result::<Row>(&mut connection)
        .await
        .unwrap();
        result.insert(table.to_owned(), row.value);
    }
    Value::Object(result)
}

async fn realm_device_transport_refusals(
    fixture: &Fixture,
    candidate: &RealmActorCreatePayload,
    original_metadata: &arkret_models_integration::AppletManagedDeviceMetadata,
    original_request: &arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest,
    original: &coland_storage::CommittedEventRecord,
) {
    let authority = fixture
        .state
        .test_persistence()
        .device_revocations()
        .applet_managed_device_authority(
            &candidate.actor_id,
            &original_metadata.device_id,
            chrono::Utc::now(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(authority.actor_id, candidate.actor_id);
    assert!(authority.actor_id.as_account_id().is_none());
    let fingerprint = arkret_canonical::ed25519_pubkey_to_did_key_multibase(&authority.public_key);
    let method = DidUrl::new(format!("did:key:{fingerprint}#{fingerprint}")).unwrap();
    let before = boxed_step(|| native_business_footprint(fixture)).await;
    for fault in [
        "wrong_destination",
        "changed_body",
        "wrong_signature",
        "expired_signature",
        "mixed_credentials",
        "wrong_authorization",
        "unknown_device",
        "wrong_applet",
    ] {
        let mut metadata = original_metadata.clone();
        metadata.nonce = arkret_canonical::base64url_encode(rand::random::<[u8; 32]>());
        match fault {
            "wrong_authorization" => {
                metadata.authorization_event_id =
                    EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0xb1; 32]);
            }
            "unknown_device" => {
                metadata.device_id =
                    arkret_wire::DeviceId::new(format!("ak:device:{}", uuid::Uuid::now_v7()))
                        .unwrap();
            }
            "wrong_applet" => {
                metadata.applet_id =
                    AppletId::new(format!("ak:applet:{}", uuid::Uuid::now_v7())).unwrap();
            }
            _ => {}
        }
        let (status, problem) = managed_device_post_with_fault(
            fixture,
            &metadata,
            &method,
            "/_arkret/self/events",
            arkret_wire::ServiceOperationId::SelfEventsCommandSubmitV1,
            &json!(original_request),
            &[79; 32],
            Some(fault),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{fault}: {problem}");
        assert_eq!(
            problem["type"],
            "https://arkret.org/problems/unauthenticated"
        );
        assert_eq!(
            boxed_step(|| native_business_footprint(fixture)).await,
            before,
            "{fault}"
        );
    }
    // A new valid HTTP proof recovers the original accepted join and Commit.
    // The retired Account/PCR managed-forward carrier is never reconstructed.
    let mut metadata = original_metadata.clone();
    metadata.nonce = arkret_canonical::base64url_encode(rand::random::<[u8; 32]>());
    let (status, replay) = managed_device_post(
        fixture,
        &metadata,
        &method,
        "/_arkret/self/events",
        arkret_wire::ServiceOperationId::SelfEventsCommandSubmitV1,
        &json!(original_request),
        &[79; 32],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "real native exact replay: {replay}");
    let recovered = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&original.event.event_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(recovered.event, original.event);
    assert_eq!(recovered.commit, original.commit);
    assert_eq!(
        boxed_step(|| native_business_footprint(fixture)).await,
        before
    );
    boxed_step(|| {
        realm_device_physical_expiry_refuses_current_http(fixture, candidate, original_request)
    })
    .await;
}

async fn realm_device_physical_expiry_refuses_current_http(
    fixture: &Fixture,
    candidate: &RealmActorCreatePayload,
    original_request: &arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest,
) {
    let source = fixture
        .state
        .test_persistence()
        .authority_commits()
        .applet_realm_actor_creations(&fixture.realm, &candidate.applet_id)
        .await
        .unwrap()
        .into_iter()
        .find(|original| original.event.payload.get("actor_id") == Some(&json!(candidate.actor_id)))
        .expect("real accepted Realm actor creation");
    let expires_at = arkret_canonical::normalize_timestamp_canonical(
        chrono::Utc::now() + chrono::Duration::seconds(5),
    );
    let device = boxed_step(|| {
        authorize_device_until(
            fixture,
            candidate,
            &source.commit,
            80,
            &["ak.applet.join", "ak.message.create"],
            Some(expires_at),
        )
    })
    .await;
    let authority = fixture
        .state
        .test_persistence()
        .device_revocations()
        .applet_managed_device_authority(&candidate.actor_id, &device, chrono::Utc::now())
        .await
        .unwrap()
        .expect("Device must actually be admitted before expiry");
    assert!(chrono::Utc::now() < expires_at);
    let metadata = arkret_models_integration::AppletManagedDeviceMetadata {
        actor_id: candidate.actor_id.clone(),
        device_id: device,
        authorization_event_id: authority.authorization_ref.event_id,
        applet_id: candidate.applet_id.clone(),
        effective_scope: candidate.creation_scope.clone(),
        nonce: arkret_canonical::base64url_encode(rand::random::<[u8; 32]>()),
    };
    let fingerprint = arkret_canonical::ed25519_pubkey_to_did_key_multibase(&authority.public_key);
    let before = boxed_step(|| native_business_footprint(fixture)).await;
    tokio::time::sleep(
        (expires_at - chrono::Utc::now())
            .to_std()
            .unwrap_or_default()
            + std::time::Duration::from_millis(30),
    )
    .await;
    // A newly signed transport proof cannot revive the physically expired
    // accepted Device, even while the original Event remains historical fact.
    let (status, problem) = managed_device_post(
        fixture,
        &metadata,
        &DidUrl::new(format!("did:key:{fingerprint}#{fingerprint}")).unwrap(),
        "/_arkret/self/events",
        arkret_wire::ServiceOperationId::SelfEventsCommandSubmitV1,
        &json!(original_request),
        &[80; 32],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "expired current Device: {problem}"
    );
    assert_eq!(
        problem["type"],
        "https://arkret.org/problems/unauthenticated"
    );
    assert_eq!(
        boxed_step(|| native_business_footprint(fixture)).await,
        before
    );
}

async fn realm_creation_writer_failure_rolls_back(
    fixture: &Fixture,
    package: &AppletPackage,
    original_request: &Value,
) {
    use diesel_async::SimpleAsyncConnection as _;
    let before = boxed_step(|| native_business_footprint(fixture)).await;
    {
        let mut connection = fixture.pool.get().await.unwrap();
        connection.batch_execute(
            "CREATE FUNCTION test_realm_actor_creation_writer_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'actual Realm actor current writer failure'; END $$; CREATE TRIGGER test_realm_actor_creation_writer_failure BEFORE INSERT ON realm_actor_current_results FOR EACH ROW EXECUTE FUNCTION test_realm_actor_creation_writer_failure();"
        ).await.unwrap();
    }
    let (status, problem) = fixture
        .service_post(
            package,
            "/_arkret/self/events",
            arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
            original_request,
            "actual-realm-actor-writer-failure",
        )
        .await;
    {
        let mut connection = fixture.pool.get().await.unwrap();
        connection.batch_execute("DROP TRIGGER test_realm_actor_creation_writer_failure ON realm_actor_current_results; DROP FUNCTION test_realm_actor_creation_writer_failure();").await.unwrap();
    }
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "writer failure: {problem}"
    );
    assert_eq!(
        problem["type"],
        "https://arkret.org/problems/internal_error"
    );
    assert_eq!(
        boxed_step(|| native_business_footprint(fixture)).await,
        before,
        "the actual writer must roll back queued original, Commit, creation, private current and quota together"
    );
}

async fn retired_managed_pcr_creation_is_rejected(
    fixture: &Fixture,
    package: &AppletPackage,
    creation_grant: &arkret_wire::GrantId,
) {
    let original = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(fixture.authority_event_ref.as_ref().unwrap())
        .await
        .unwrap()
        .unwrap();
    let mut retired = original.event;
    retired.payload.get_mut("object").unwrap()["purpose"] = json!("applet_managed_control");
    retired.executed_by = Some(ActorId::service(package.service_id.clone()));
    retired.applet_id = Some(package.applet_id.clone());
    retired.authorization_ref = Some(creation_grant.clone().into());
    retired.producer_proof = None;
    let mut authored = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
        retired,
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap();
    let signer = Ed25519PayloadSigner::new(
        SigningKey::from_bytes(&[42; 32]),
        applet_service_did(package),
        package.webhook_auth.key_ref.clone(),
    );
    arkret_signatures::sign_event(
        &mut authored,
        &signer,
        arkret_signatures::SignEventOptions::new(),
    )
    .unwrap();
    let retired = authored.into_event();
    let bytes = arkret_signatures::EventProofBuilder::new()
        .envelope_bytes(&retired)
        .unwrap();
    arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
        retired.producer_proof.as_ref().unwrap(),
        &bytes,
        retired.actual_signer(),
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: SigningKey::from_bytes(&[42; 32])
                .verifying_key()
                .to_bytes()
                .to_vec(),
        },
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap();
    let request = arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest::Event(
        arkret_wire::EventAdmissionSubmission::new(retired),
    );
    let before = boxed_step(|| native_business_footprint(fixture)).await;
    let (status, problem) = fixture
        .service_post(
            package,
            "/_arkret/self/events",
            arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
            &json!(request),
            "retired-managed-pcr-rejected",
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{problem}");
    assert_eq!(
        problem["type"],
        "https://arkret.org/problems/schema_violation"
    );
    assert_eq!(
        boxed_step(|| native_business_footprint(fixture)).await,
        before
    );
}

async fn retired_managed_forward_carrier_is_rejected(
    fixture: &Fixture,
    package: &AppletPackage,
    original: &coland_storage::CommittedEventRecord,
) {
    use arkret_models_collaboration::authority_commit::{
        AuthorityForwardBranch, PeerAuthorityForwardEventRequest, PeerAuthoritySubmitRequest,
    };
    let request =
        PeerAuthoritySubmitRequest::AuthorityForwardEvent(PeerAuthorityForwardEventRequest {
            branch: AuthorityForwardBranch::AuthorityForward,
            event_submission: arkret_wire::EventAdmissionSubmission::new(original.event.clone()),
            mls_genesis_material: None,
            producer_device_evidence: None,
            producer_agent_evidence: None,
        });
    let mut retired = json!(request);
    retired["producer_managed_provenance"] = json!({});
    let before = boxed_step(|| native_business_footprint(fixture)).await;
    let (status, problem) = fixture
        .service_post(
            package,
            "/_arkret/peer/events",
            arkret_wire::ServiceOperationId::PEER_EVENTS_COMMAND_SUBMIT_V1,
            &retired,
            "retired-managed-forward-carrier-rejected",
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{problem}");
    assert_eq!(
        problem["type"],
        "https://arkret.org/problems/schema_violation"
    );
    assert_eq!(
        boxed_step(|| native_business_footprint(fixture)).await,
        before
    );
}

async fn realm_profile_control_and_writer_atomicity(
    fixture: &Fixture,
    candidate: &RealmActorCreatePayload,
    creation_commit: &arkret_wire::RealmCommit,
) {
    use arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest;
    use arkret_models_collaboration::events_payloads::ActorProfileCreatePayload;
    use diesel_async::SimpleAsyncConnection as _;
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let payload: ActorProfileCreatePayload = serde_json::from_value(json!({"object": {
        "actor_id":candidate.actor_id,
        "actor_kind": match candidate.actor_role {
            RealmActorCreatePayloadActorRole::Bot => "bot",
            RealmActorCreatePayloadActorRole::Ghost => "integration",
        },
        "display_name":"Original Realm actor private Profile"
    }}))
    .unwrap();
    let intent =
        arkret_event_draft::TypedEventDraft::<arkret_wire::event_spec::ProfileCreate>::new(
            ScopeRef::RealmControl {
                realm_id: fixture.realm.clone(),
            },
            candidate.actor_id.clone(),
            payload,
        )
        .unwrap()
        .with_applet_id(candidate.applet_id.clone())
        .into_intent(at)
        .unwrap();
    let mut authored = intent
        .author_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .unwrap();
    arkret_signatures::sign_event(
        &mut authored,
        &Ed25519PayloadSigner::new(
            SigningKey::from_bytes(&[33; 32]),
            candidate.initial_resolution.did.clone(),
            candidate.control_method_kid.clone(),
        ),
        arkret_signatures::SignEventOptions::new().with_created_at(at),
    )
    .unwrap();
    let event = authored.into_event();
    assert!(event.executed_by.is_none());
    assert!(event.authorization_ref.is_none());
    let request = SelfAuthoritySubmitRequest::Event(arkret_wire::EventAdmissionSubmission::new(
        event.clone(),
    ));
    request.validate().unwrap();
    let before = boxed_step(|| native_business_footprint(fixture)).await;
    {
        let mut conn = fixture.pool.get().await.unwrap();
        conn.batch_execute("CREATE FUNCTION test_realm_profile_writer_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'actual Realm Profile writer failure'; END $$; CREATE TRIGGER test_realm_profile_writer_failure BEFORE INSERT ON realm_actor_current_results FOR EACH ROW WHEN (NEW.selector->>'kind'='realm_actor_profile') EXECUTE FUNCTION test_realm_profile_writer_failure();").await.unwrap();
    }
    let (status, problem) =
        boxed_step(|| realm_profile_post(fixture, candidate, creation_commit, &request)).await;
    {
        let mut conn = fixture.pool.get().await.unwrap();
        conn.batch_execute("DROP TRIGGER test_realm_profile_writer_failure ON realm_actor_current_results; DROP FUNCTION test_realm_profile_writer_failure();").await.unwrap();
    }
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "Profile current writer: {problem}"
    );
    assert_eq!(
        problem["type"],
        "https://arkret.org/problems/internal_error"
    );
    assert_eq!(
        boxed_step(|| native_business_footprint(fixture)).await,
        before,
        "Profile current writer failure must roll back Event, Commit, signer fact and quota together"
    );
    let (status, accepted) =
        boxed_step(|| realm_profile_post(fixture, candidate, creation_commit, &request)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "actual control-signed Profile: {accepted}"
    );
    let original = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&event.event_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(original.event, event);
    assert_eq!(original.commit.stream_ref, creation_commit.stream_ref);
    let after = boxed_step(|| native_business_footprint(fixture)).await;
    let (status, replay) =
        boxed_step(|| realm_profile_post(fixture, candidate, creation_commit, &request)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "exact Profile original recovery: {replay}"
    );
    let outcome: arkret_models_collaboration::authority_commit::SelfAuthoritySubmitOutcome =
        serde_json::from_value(replay).unwrap();
    outcome.validate_for_request(&request).unwrap();
    let recovered = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&event.event_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(recovered.event, original.event);
    assert_eq!(recovered.commit, original.commit);
    assert_eq!(
        boxed_step(|| native_business_footprint(fixture)).await,
        after
    );
}

async fn realm_profile_post(
    fixture: &Fixture,
    candidate: &RealmActorCreatePayload,
    creation_commit: &arkret_wire::RealmCommit,
    request: &arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest,
) -> (StatusCode, Value) {
    let metadata = RealmActorControlHttpMetadata {
        actor_id: candidate.actor_id.clone(),
        control_ref: arkret_wire::CommittedEventRef {
            event_id: creation_commit.event_ref.clone(),
            commit_id: creation_commit.commit_id.clone(),
            stream_ref: creation_commit.stream_ref.clone(),
            stream_position: creation_commit.stream_position,
        },
        nonce: arkret_canonical::base64url_encode(rand::random::<[u8; 32]>()),
    };
    control_post(
        fixture,
        &metadata,
        &candidate.control_method_kid,
        "/_arkret/self/events",
        arkret_wire::ServiceOperationId::SelfEventsCommandSubmitV1,
        &json!(request),
    )
    .await
}
