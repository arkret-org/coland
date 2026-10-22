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
        "realm_actor_operation_outcomes",
        "applet_authoring_completions",
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
        "management_review_requests",
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
        .applet_realm_actor_creations(&fixture.realm, &candidate.applet_id, None)
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
    for table in [
        "realm_actor_current_results",
        "applet_authoring_completions",
    ] {
        {
            let mut connection = fixture.pool.get().await.unwrap();
            connection.batch_execute(&format!(
            "CREATE FUNCTION test_realm_actor_creation_writer_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'actual Realm actor current writer failure'; END $$; CREATE TRIGGER test_realm_actor_creation_writer_failure BEFORE INSERT ON {table} FOR EACH ROW EXECUTE FUNCTION test_realm_actor_creation_writer_failure();"
        )).await.unwrap();
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
            connection.batch_execute(&format!("DROP TRIGGER test_realm_actor_creation_writer_failure ON {table}; DROP FUNCTION test_realm_actor_creation_writer_failure();")).await.unwrap();
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
}

async fn realm_creation_quota_grant(fixture: &Fixture, source: &Event) -> arkret_wire::GrantId {
    use arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest;
    let mut payload: arkret_models_collaboration::events_payloads::CapabilityGrantPayload =
        serde_json::from_value(json!(source.payload)).unwrap();
    payload.grant.constraints.push(
        serde_json::from_value(json!({
            "constraint_kind":"quota","constraint_subkind":"rate","effect":"allow",
            "max_operations":1,"period":"P1D","constraint_scope":"per_realm"
        }))
        .unwrap(),
    );
    payload.grant.issued_at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let event = fixture.admin_event(
        EventKind::CapabilityGrant,
        source.scope_ref.clone(),
        json!(payload),
    );
    let grant = arkret_wire::GrantId::from_event_id(&event.event_id);
    let request = SelfAuthoritySubmitRequest::Event(arkret_wire::EventAdmissionSubmission::new(
        event.clone(),
    ));
    let (status, outcome) = fixture
        .admin_post(
            "/_arkret/self/events",
            arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
            &json!(request),
            None,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "actual creation quota grant: {outcome}"
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
    grant
}

async fn realm_creation_uniqueness_refuses_new_originals(
    fixture: &Fixture,
    package: &AppletPackage,
    registration: &EventId,
    original_grant: &Event,
    winner: &RealmActorCreatePayload,
    original: &coland_storage::CommittedEventRecord,
) {
    use arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest;
    let grant = arkret_wire::GrantId::from_event_id(&original_grant.event_id);
    assert!(
        original_grant.payload["grant"]["constraints"]
            .as_array()
            .is_none_or(|constraints| constraints.iter().all(|c| c["constraint_kind"] != "quota"))
    );
    let before = boxed_step(|| native_business_footprint(fixture)).await;
    for conflict in ["external", "request"] {
        let (candidate, signer) = realm_candidate(package, &fixture.realm, registration, &grant);
        assert_ne!(candidate.actor_id, winner.actor_id);
        let mut value = json!(candidate);
        value.as_object_mut().unwrap().remove("control_signature");
        value["request_id"] = json!(uuid::Uuid::now_v7().simple().to_string());
        value["external_ref"]["external_id"] = json!(format!("unique-{}", uuid::Uuid::now_v7()));
        if conflict == "external" {
            value["external_ref"] = json!(winner.external_ref);
            assert_ne!(value["request_id"], json!(winner.request_id));
        } else {
            value["request_id"] = json!(winner.request_id);
            assert_ne!(value["external_ref"], json!(winner.external_ref));
        }
        let transcript: RealmActorCreationTranscript =
            serde_json::from_value(value.clone()).unwrap();
        value["control_signature"] = json!(
            sign_detached_object(
                &transcript,
                DetachedSignatureContext::RealmActorCreation,
                candidate.control_method_kid.clone(),
                candidate.control_signature.created_at,
                &SigningKey::from_bytes(&[33; 32]),
            )
            .unwrap()
        );
        let candidate: RealmActorCreatePayload = serde_json::from_value(value).unwrap();
        arkret_identity::verify_realm_actor_initial_resolution(&candidate, chrono::Utc::now())
            .unwrap();
        let event = arkret::author_realm_actor_create(
            candidate.clone(),
            arkret_canonical::DigestSuite::Sha256,
            candidate.control_signature.created_at,
            &signer,
        )
        .unwrap();
        let request = SelfAuthoritySubmitRequest::Event(
            arkret_wire::EventAdmissionSubmission::new(event.clone()),
        );
        request.validate().unwrap();
        let (status, problem) = fixture
            .service_post(
                package,
                "/_arkret/self/events",
                arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
                &json!(request),
                if conflict == "external" {
                    "occupied-external"
                } else {
                    "occupied-request"
                },
            )
            .await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "{conflict} uniqueness: {problem}"
        );
        assert_eq!(
            problem["type"],
            "https://arkret.org/problems/failed_precondition"
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
        assert_eq!(
            boxed_step(|| native_business_footprint(fixture)).await,
            before,
            "a different signed {conflict} original leaves no identity/current/fact/Commit/quota/completion"
        );
    }
    let request = SelfAuthoritySubmitRequest::Event(arkret_wire::EventAdmissionSubmission::new(
        original.event.clone(),
    ));
    let (status, body) = fixture
        .service_post(
            package,
            "/_arkret/self/events",
            arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
            &json!(request),
            "occupied-keys-winner-exact-retry",
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "original retry after conflicts: {body}"
    );
    let replay = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&original.event.event_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(replay.event, original.event);
    assert_eq!(replay.commit, original.commit);
    assert_eq!(
        boxed_step(|| native_business_footprint(fixture)).await,
        before
    );
}

async fn realm_device_wrong_possession_is_rejected(
    fixture: &Fixture,
    candidate: &RealmActorCreatePayload,
    correct: &arkret_models_collaboration::events_payloads::DeviceAuthorizePayload,
    metadata: &RealmActorControlHttpMetadata,
    at: chrono::DateTime<chrono::Utc>,
) {
    use arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest;
    use ed25519_dalek::Signer as _;
    arkret_signatures::verify_realm_device_authorize_possession(correct, &candidate.actor_id)
        .unwrap();
    let mut bad = correct.clone();
    let input = bad
        .realm_device_possession_signature_input(&candidate.actor_id)
        .unwrap();
    bad.device_signature = serde_json::from_value(json!(arkret_canonical::base64url_encode(
        SigningKey::from_bytes(&[91; 32]).sign(&input).to_bytes(),
    )))
    .unwrap();
    assert!(
        arkret_signatures::verify_realm_device_authorize_possession(&bad, &candidate.actor_id)
            .is_err()
    );
    let intent =
        arkret_event_draft::TypedEventDraft::<arkret_wire::event_spec::DeviceAuthorize>::new(
            ScopeRef::RealmControl {
                realm_id: fixture.realm.clone(),
            },
            candidate.actor_id.clone(),
            bad,
        )
        .unwrap()
        .with_applet_id(candidate.applet_id.clone())
        .into_intent(at)
        .unwrap();
    let mut authored = intent
        .author_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .unwrap();
    let signer = Ed25519PayloadSigner::new(
        SigningKey::from_bytes(&[33; 32]),
        candidate.initial_resolution.did.clone(),
        candidate.control_method_kid.clone(),
    );
    arkret_signatures::sign_event(
        &mut authored,
        &signer,
        arkret_signatures::SignEventOptions::new().with_created_at(at),
    )
    .unwrap();
    let event = authored.into_event();
    let request = SelfAuthoritySubmitRequest::Event(arkret_wire::EventAdmissionSubmission::new(
        event.clone(),
    ));
    request.validate().unwrap();
    let before = boxed_step(|| native_business_footprint(fixture)).await;
    let (status, problem) = control_post(
        fixture,
        metadata,
        &candidate.control_method_kid,
        "/_arkret/self/events",
        arkret_wire::ServiceOperationId::SelfEventsCommandSubmitV1,
        &json!(request),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "inner Device possession: {problem}"
    );
    assert_eq!(
        problem["type"],
        "https://arkret.org/problems/failed_precondition"
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
    assert_eq!(
        boxed_step(|| native_business_footprint(fixture)).await,
        before,
        "wrong inner PoP cannot retain Device current, Event, Commit, signer fact or quota"
    );
}

async fn realm_creation_quota_exhaustion(
    fixture: &Fixture,
    package: &AppletPackage,
    registration: &EventId,
    grant: &arkret_wire::GrantId,
) {
    use arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest;
    let before = boxed_step(|| native_business_footprint(fixture)).await;
    let counters = before["capability_quota_counters"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["grant_id"] == json!(grant))
        .collect::<Vec<_>>();
    assert_eq!(
        counters.len(),
        1,
        "the accepted original spends exactly one real quota counter"
    );
    assert_eq!(counters[0]["consumed"], 1);
    assert_eq!(
        before["capability_quota_consumptions"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["grant_id"] == json!(grant))
            .count(),
        1,
        "the exact accepted retry cannot create another quota identity"
    );
    let (candidate, signer) = realm_candidate(package, &fixture.realm, registration, grant);
    let mut value = json!(candidate);
    value.as_object_mut().unwrap().remove("control_signature");
    value["request_id"] = json!(uuid::Uuid::now_v7().simple().to_string());
    value["external_ref"]["external_id"] = json!(format!("quota-second-{}", uuid::Uuid::now_v7()));
    let transcript: RealmActorCreationTranscript = serde_json::from_value(value.clone()).unwrap();
    value["control_signature"] = json!(
        sign_detached_object(
            &transcript,
            DetachedSignatureContext::RealmActorCreation,
            candidate.control_method_kid.clone(),
            candidate.control_signature.created_at,
            &SigningKey::from_bytes(&[33; 32]),
        )
        .unwrap()
    );
    let candidate: RealmActorCreatePayload = serde_json::from_value(value).unwrap();
    arkret_identity::verify_realm_actor_initial_resolution(&candidate, chrono::Utc::now()).unwrap();
    let event = arkret::author_realm_actor_create(
        candidate.clone(),
        arkret_canonical::DigestSuite::Sha256,
        candidate.control_signature.created_at,
        &signer,
    )
    .unwrap();
    let request =
        SelfAuthoritySubmitRequest::Event(arkret_wire::EventAdmissionSubmission::new(event));
    request.validate().unwrap();
    let (status, problem) = fixture
        .service_post(
            package,
            "/_arkret/self/events",
            arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
            &json!(request),
            "realm-actor-creation-quota-exhausted",
        )
        .await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "second real creation after exhausted quota: {problem}"
    );
    assert_eq!(problem["type"], "https://arkret.org/problems/rate_limited");
    assert_eq!(
        boxed_step(|| native_business_footprint(fixture)).await,
        before,
        "a second valid creation cannot retain identity/current/source/Commit or spend quota after refusal"
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
        &retired.actor_id,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: SigningKey::from_bytes(&[42; 32])
                .verifying_key()
                .to_bytes()
                .to_vec(),
        },
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap();
    // realm-actors section 3 and creation contract: Service self ingress admits only its own
    // RealmActor control originals, never the retired delegated Account/PCR
    // aggregate. That capability fence precedes payload-purpose admission.
    // Independently prove that neither the closed payload nor the governance
    // classifier can reinterpret this original as a supported Realm genesis.
    assert!(
        serde_json::from_value::<
            arkret_models_collaboration::events_payloads::realm::RealmCreatePayload,
        >(json!(retired.payload))
        .is_err()
    );
    assert!(arkret_wire::GenesisGovernance::from_genesis(&retired).is_err());
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
    assert_eq!(status, StatusCode::FORBIDDEN, "{problem}");
    assert_eq!(
        problem["type"],
        "https://arkret.org/problems/capability_denied"
    );
    assert_eq!(
        problem["detail"],
        "creation does not match its authenticated Service"
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
    boxed_step(|| {
        realm_profile_update_source_failure_and_cas(fixture, candidate, creation_commit, &original)
    })
    .await;
}

async fn realm_profile_update_source_failure_and_cas(
    fixture: &Fixture,
    candidate: &RealmActorCreatePayload,
    creation_commit: &arkret_wire::RealmCommit,
    original: &coland_storage::CommittedEventRecord,
) {
    use arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest;
    use arkret_models_collaboration::events_payloads::ActorProfileUpdatePayload;
    use diesel_async::SimpleAsyncConnection as _;
    let make_update = |label: &str| {
        let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        let payload: ActorProfileUpdatePayload = serde_json::from_value(json!({
            "target_ref":arkret_wire::ActorProfileId::from_event_id(&original.event.event_id),
            "patch":{"display_name":label},
            "expected_revision":{"commit_id":original.commit.commit_id,"stream_position":original.commit.stream_position}
        })).unwrap();
        let intent =
            arkret_event_draft::TypedEventDraft::<arkret_wire::event_spec::ProfileUpdate>::new(
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
        SelfAuthoritySubmitRequest::Event(arkret_wire::EventAdmissionSubmission::new(
            authored.into_event(),
        ))
    };
    let request = make_update("Current Realm Profile successor");
    request.validate().unwrap();
    let before = boxed_step(|| native_business_footprint(fixture)).await;
    {
        let mut conn = fixture.pool.get().await.unwrap();
        conn.batch_execute("CREATE FUNCTION test_realm_profile_source_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'actual Realm Profile source writer failure'; END $$; CREATE TRIGGER test_realm_profile_source_failure BEFORE INSERT ON realm_actor_private_signer_facts FOR EACH ROW EXECUTE FUNCTION test_realm_profile_source_failure();").await.unwrap();
    }
    let (status, problem) =
        boxed_step(|| realm_profile_post(fixture, candidate, creation_commit, &request)).await;
    {
        let mut conn = fixture.pool.get().await.unwrap();
        conn.batch_execute("DROP TRIGGER test_realm_profile_source_failure ON realm_actor_private_signer_facts; DROP FUNCTION test_realm_profile_source_failure();").await.unwrap();
    }
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "Profile source retention: {problem}"
    );
    assert_eq!(
        problem["type"],
        "https://arkret.org/problems/internal_error"
    );
    assert_eq!(
        boxed_step(|| native_business_footprint(fixture)).await,
        before,
        "retained source failure after the typed current write must roll the entire successor back"
    );
    let (status, successor) =
        boxed_step(|| realm_profile_post(fixture, candidate, creation_commit, &request)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "exact successor after rollback: {successor}"
    );
    let after = boxed_step(|| native_business_footprint(fixture)).await;
    let stale = make_update("Stale original Profile revision");
    let (status, problem) =
        boxed_step(|| realm_profile_post(fixture, candidate, creation_commit, &stale)).await;
    assert_eq!(status, StatusCode::CONFLICT, "Profile CAS: {problem}");
    assert_eq!(
        problem["type"],
        "https://arkret.org/problems/failed_precondition"
    );
    assert_eq!(
        boxed_step(|| native_business_footprint(fixture)).await,
        after
    );
    let mut repeated_creation = original.event.clone();
    repeated_creation.created_at =
        arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    repeated_creation.producer_proof = None;
    let mut authored = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
        repeated_creation,
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap();
    arkret_signatures::sign_event(
        &mut authored,
        &Ed25519PayloadSigner::new(
            SigningKey::from_bytes(&[33; 32]),
            candidate.initial_resolution.did.clone(),
            candidate.control_method_kid.clone(),
        ),
        arkret_signatures::SignEventOptions::new(),
    )
    .unwrap();
    let repeated_creation = SelfAuthoritySubmitRequest::Event(
        arkret_wire::EventAdmissionSubmission::new(authored.into_event()),
    );
    let (status, problem) =
        boxed_step(|| realm_profile_post(fixture, candidate, creation_commit, &repeated_creation))
            .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "create-once Profile: {problem}"
    );
    assert_eq!(
        problem["type"],
        "https://arkret.org/problems/failed_precondition"
    );
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
