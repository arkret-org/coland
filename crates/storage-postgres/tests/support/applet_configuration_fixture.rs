// Included inside the native Realm fixture so all operations use its accepted
// Account, actual installation transaction and independently hosted Applet.
pub(super) async fn run_configuration(pool: PgPool) {
    use arkret_bridge_runtime::{ArkretEdge, AuthoringJournal, FileAuthoringStore};
    use arkret_models_integration::{
        AppletConfigurationAdmissionStatus as Admission, AppletConfigurationCommand as Command,
        AppletConfigurationIntent, AppletConfigurationResponseBody as Outcome,
        AppletConfigurationRequestBody, AppletConfigurationSelection,
    };
    let (fixture, _governor_server) = boxed_step(|| network_fixture(pool.clone())).await;
    let factory = AppletAuthoringFactory {
        fixture,
        packages: Default::default(),
        scopes: Default::default(),
    };
    let id = AppletId::new(format!("ak:applet:{}", uuid::Uuid::now_v7())).unwrap();
    let mut native = NativeService::new(&id, &factory.fixture.state.service_core_id());
    native
        .package
        .endpoint_policy
        .endpoints
        .push(AppletEndpointEntry {
            method: AppletEndpointMethod::Post,
            path: "/_arkret/edge/applet/configuration".into(),
            authentication_kind: Some(AppletEndpointAuth::WebhookSignature),
            description: None,
            extra: Default::default(),
        });
    let method = native
        .package
        .proof
        .as_ref()
        .unwrap()
        .verification_method
        .clone();
    let controller = arkret_identity::verification_method_did(method.as_str()).unwrap();
    let signer = Ed25519PayloadSigner::from_did_key_seed([13; 32], controller, method.clone());
    native
        .package
        .stamp_registration_epoch(&applet_registration_epoch_evidence(&native.package))
        .unwrap();
    native.package.stamp_package_digest().unwrap();
    native.package.sign(&signer, &method).unwrap();
    factory
        .packages
        .lock()
        .await
        .insert(id.to_string(), native.package.clone());
    let install = boxed_step(|| factory.prepare_install(&id, "admin-configuration")).await;
    let scope = install.effective_scope.clone();
    install
        .commit(&PgAppletStore { pool: pool.clone() })
        .await
        .unwrap();
    let package = &native.package;
    let did = applet_service_did(package);
    let config: arkret_bridge_runtime::Config = serde_json::from_value(json!({
        "bridge":{"bridge_id":"actual-configuration"},
        "arkret":{
            "server_url":factory.fixture.state.config().public_base_url,
            "applet_base_url":package.base_url,"service_did":did,
            "service_resolution":fixture_applet_service_history(package),
            "trust_domain":factory.fixture.state.config().trust_domain,
            "applet_id":id,"signing_key_seed_hex":"2a".repeat(32),
            "verification_method_fragment":"#applet-service-key",
            "trusted_server_did":factory.fixture.state.service_did(),
            "applet_namespaces":package.namespaces,
            "managed_actor_authoring":{"principal_endpoint":package.base_url,"key_encryption_key_hex":"54".repeat(32)}
        }
    })).unwrap();
    let path = std::env::temp_dir().join(format!(
        "arkret-configuration-{}.redb",
        uuid::Uuid::now_v7()
    ));
    let http = native_http_client(std::time::Duration::from_secs(30));
    let station_url: Url = factory
        .fixture
        .state
        .config()
        .public_base_url
        .parse()
        .unwrap();
    let client = arkret::ClientBuilder::new(station_url.clone())
        .loopback_service_discovery(station_url.host_str().unwrap(), station_url.port().unwrap())
        .unwrap()
        .http_client(http)
        .build()
        .unwrap();
    let make_edge = || {
        Arc::new(
            ArkretEdge::new_outbound(
                Arc::new(config.clone()),
                client.clone(),
                Ed25519PayloadSigner::new(
                    SigningKey::from_bytes(&[42; 32]),
                    did.clone(),
                    package.webhook_signature_policy.key_ref.clone(),
                ),
                AuthoringJournal::new(FileAuthoringStore::shared(path.clone()).unwrap()),
            )
            .unwrap(),
        )
    };
    let make_router = || {
        Arc::new(salvo::Service::new(
            arkret_bridge_runtime::web::managed_applet_router(make_edge()).unwrap(),
        ))
    };
    *native.managed_router.lock().unwrap() = Some(make_router());
    let endpoint = format!("/_arkret/self/applets/{id}/configuration");
    let mut request = AppletConfigurationRequestBody {
        command: Command::Recover,
        intent: AppletConfigurationIntent {
                    service_id: package.service_id.clone(),
            request_id: format!("ak:request:{}", uuid::Uuid::now_v7())
                .parse()
                .unwrap(),
            effective_scope: scope,
            selection: AppletConfigurationSelection::NewBot {
                display_name: Some("Configured Bot".into()),
            },
        },
        approval_signatures: None,
    };
    let submit = |request: AppletConfigurationRequestBody| {
        let endpoint = endpoint.clone();
        let fixture = &factory.fixture;
        async move {
            fixture
                .admin_post(
                    &endpoint,
                    arkret_wire::ServiceOperationId::SELF_APPLET_CONFIGURATION_COMMAND_SUBMIT_V1,
                    &json!(request),
                    Some(request.intent.request_id.as_str()),
                )
                .await
        }
    };
    let (status, pending) = boxed_step(|| submit(request.clone())).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "recover before execution: {pending}"
    );
    let pending: Outcome = serde_json::from_value(pending).unwrap();
    assert_eq!(pending.admission_status, Admission::NotStarted);
    assert!(pending.source_response_body.unwrap().create_event.is_none());
    request.command = Command::Configure;
    let (status, accepted) = boxed_step(|| submit(request.clone())).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "actual configuration creation: {accepted}"
    );
    let accepted: Outcome = serde_json::from_value(accepted).unwrap();
    assert_eq!(accepted.admission_status, Admission::Accepted);
    let original = accepted
        .source_response_body
        .as_ref()
        .unwrap()
        .create_event
        .as_ref()
        .unwrap();
    let candidate: RealmActorCreatePayload =
        serde_json::from_value(json!(original.payload)).unwrap();
    assert_eq!(candidate.actor_role, RealmActorCreatePayloadActorRole::Bot);
    assert!(candidate.actor_id.as_realm_actor_id().is_some());
    let committed = factory
        .fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&original.event_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(committed.event, **original);
    let completion = durable_completion(&factory.fixture, &candidate.actor_id).await;
    assert_eq!(completion.creation_ref.event_id, original.event_id);
    assert_eq!(completion.creation_ref.commit_id, committed.commit.commit_id);
    assert_eq!(durable_completion(&factory.fixture, &candidate.actor_id).await.creation_ref, completion.creation_ref,
        "repeated durable enumeration preserves the exact original");
    let delivery = prepare_configuration_completion(&factory.fixture, &completion)
        .await
        .unwrap();
    let retry = prepare_configuration_completion(&factory.fixture, &completion)
        .await
        .unwrap();
    assert_eq!(
        json!(delivery),
        json!(retry),
        "unexpired transport attempts retain exact bytes"
    );
    boxed_step(|| deliver_configuration_completion(&factory.fixture, &completion, &delivery))
        .await
        .unwrap();
    let receipts = FileAuthoringStore::shared(path.clone())
        .unwrap()
        .entries_with_prefix("managed-authoring/delivery/")
        .unwrap();
    assert_eq!(receipts.len(), 1, "one original durable HTTP receipt");
    let receipt: Value = serde_json::from_str(&receipts[0].1).unwrap();
    let authentication: arkret_models_integration::AppletDeliveryAuthenticationRecord =
        serde_json::from_value(receipt["record"].clone()).unwrap();
    assert_eq!(
        receipt["record"]
            .as_object()
            .unwrap()
            .len(),
        14
    );
    assert_eq!(
        authentication.registration_epoch,
        native.package.registration_epoch
    );
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    boxed_step(|| deliver_configuration_completion(&factory.fixture, &completion, &delivery))
        .await
        .unwrap();
    assert_eq!(
        FileAuthoringStore::shared(path.clone())
            .unwrap()
            .entries_with_prefix("managed-authoring/delivery/")
            .unwrap(),
        receipts,
        "fresh HTTP times preserve the original full authentication record and outcome"
    );
    tokio::time::sleep(std::time::Duration::from_secs(61)).await;
    assert!(
        boxed_step(|| deliver_configuration_completion(&factory.fixture, &completion, &delivery))
            .await
            .is_err(),
        "expired material cannot authorize another receipt even if an outcome was retained"
    );
    let fresh = prepare_configuration_completion(&factory.fixture, &completion)
        .await
        .unwrap();
    assert_ne!(fresh.idempotency_key, delivery.idempotency_key);
    assert_eq!(
        json!(fresh.context.as_ref().unwrap().material.material),
        json!(delivery.context.as_ref().unwrap().material.material),
        "refresh preserves original Event, Commit and signer fact"
    );
    let mut conflict = fresh.clone();
    conflict.idempotency_key = delivery.idempotency_key.clone();
    let rejected =
        boxed_step(|| deliver_configuration_completion(&factory.fixture, &completion, &conflict))
            .await
            .unwrap_err();
    assert!(
        rejected.contains("duplicate_conflict"),
        "changed material under the same transport identity: {rejected}"
    );
    *native.managed_router.lock().unwrap() = None;
    *native.managed_router.lock().unwrap() = Some(make_router());
    boxed_step(|| deliver_configuration_completion(&factory.fixture, &completion, &fresh))
        .await
        .unwrap();
    assert!(
        factory
            .fixture
            .state
            .test_persistence()
            .applets()
            .acknowledge_authoring_completion(
                &completion.applet_id,
                &completion.request_digest,
                &delivery.idempotency_key,
                chrono::Utc::now()
            )
            .await
            .is_err(),
        "late acknowledgement cannot consume a newer attempt"
    );
    let recovered_edge = make_edge();
    let recovery = arkret_bridge_runtime::applet_configuration::AppletConfigurationService::new(
        recovered_edge.clone(),
    )
    .unwrap();
    assert_eq!(
        boxed_step(|| recovery.recover_accepted_configurations())
            .await
            .unwrap(),
        0,
        "the durable HTTP completion already installed custody before restart"
    );
    assert!(
        recovered_edge
            .installed_managed_authoring(&request.intent.effective_scope, &candidate.actor_id)
            .unwrap()
            .is_some()
    );
    assert_eq!(
        boxed_step(|| recovery.recover_accepted_configurations())
            .await
            .unwrap(),
        0
    );
    *native.managed_router.lock().unwrap() = Some(make_router());
    request.command = Command::Recover;
    let (status, replay) = boxed_step(|| submit(request.clone())).await;
    assert_eq!(status, StatusCode::OK, "cold exact configuration: {replay}");
    assert_eq!(
        arkret_canonical::canonical_json_bytes(&accepted).unwrap(),
        arkret_canonical::canonical_json_bytes(&replay).unwrap()
    );
    let mut changed = request.clone();
    changed.intent.selection = AppletConfigurationSelection::NewBot {
        display_name: Some("Different intent".into()),
    };
    let (status, _) = boxed_step(|| submit(changed)).await;
    assert_ne!(status, StatusCode::OK);

    let mut existing = request.clone();
    existing.intent.request_id = format!("ak:request:{}", uuid::Uuid::now_v7())
        .parse()
        .unwrap();
    existing.intent.selection = AppletConfigurationSelection::ExistingRealmActor {
        actor_id: candidate.actor_id.clone(),
    };
    existing.command = Command::Configure;
    let (status, reused) = boxed_step(|| submit(existing.clone())).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "select the accepted managed identity: {reused}"
    );
    let reused: Outcome = serde_json::from_value(reused).unwrap();
    assert_eq!(reused.admission_status, Admission::Accepted);
    let source = reused.source_response_body.as_ref().unwrap();
    assert_eq!(source.actor_id.as_ref(), Some(&candidate.actor_id));
    assert!(source.create_event.is_none());
    assert_eq!(
        source.creation_refs.as_ref().unwrap().as_slice()[0].event_id,
        original.event_id
    );
    existing.command = Command::Recover;
    let (status, replay) = boxed_step(|| submit(existing)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "recover selected identity: {replay}"
    );
    assert_eq!(json!(reused), replay);

    // The Applet finishes and durably retains the candidate, but its HTTPS
    // connection closes before the governing Station receives any response.
    let (completed, observed) = tokio::sync::oneshot::channel();
    *native.configuration_response_fault.lock().unwrap() = Some(ConfigurationResponseFault {
        completed,
        release: None,
    });
    let mut lost = request.clone();
    lost.intent.request_id = format!("ak:request:{}", uuid::Uuid::now_v7())
        .parse()
        .unwrap();
    lost.command = Command::Configure;
    let (status, failure) = boxed_step(|| submit(lost.clone())).await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "lost Applet response: {failure}"
    );
    let retained = observed.await.unwrap();
    let lost_candidate: arkret_wire::Event =
        serde_json::from_value(retained["create_event"].clone()).unwrap();
    assert!(
        factory
            .fixture
            .state
            .test_persistence()
            .authority_commits()
            .committed_event(&lost_candidate.event_id)
            .await
            .unwrap()
            .is_none()
    );
    *native.managed_router.lock().unwrap() = Some(make_router());
    lost.command = Command::Recover;
    let (status, recovered) = boxed_step(|| submit(lost.clone())).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "recover the original after response loss: {recovered}"
    );
    assert_eq!(recovered["admission_status"], "accepted");
    assert_eq!(recovered["source_response_body"], retained);
    let committed = factory
        .fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&lost_candidate.event_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(committed.event, lost_candidate);
    let (status, replay) = boxed_step(|| submit(lost)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(recovered, replay);

    request.intent.request_id = format!("ak:request:{}", uuid::Uuid::now_v7())
        .parse()
        .unwrap();
    request.command = Command::Cancel;
    let (status, cancelled) = boxed_step(|| submit(request.clone())).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "cancel before authoring: {cancelled}"
    );
    assert_eq!(cancelled["admission_status"], "cancelled");
    request.command = Command::Configure;
    let (status, cancelled) = boxed_step(|| submit(request.clone())).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "cancelled cannot restart: {cancelled}"
    );
    assert_eq!(cancelled["admission_status"], "cancelled");
    assert!(cancelled["source_response_body"].get("create_event").is_none());

    boxed_step(|| {
        cross_station_configuration(&factory.fixture, &id, &package.service_id, &request.intent.effective_scope)
    })
    .await;

    // Policy requires an actual Service request and a real administrator vote.
    // The initial configuration click alone cannot satisfy this requirement.
    let administrator = ActorId::account(factory.fixture.pcr.history.account.clone());
    let policy_id = format!("ak:policy:{}", uuid::Uuid::now_v7());
    let policy = factory.fixture.admin_event(EventKind::PolicySet,
        ScopeRef::Realm { realm_id: factory.fixture.realm.clone() }, json!({
            "policy_id":policy_id,"expected_revision":null,
            "value":{"schema":"ak.schema.policy.v1","id":policy_id,"realm_id":factory.fixture.realm,
                "policy_kind":"applet","default_effect":"allow","created_by":administrator,
                "created_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now()),
                "rules":[{"rule_id":"configuration_creation","kind":"applet","effect":"require_review",
                    "applet_target":{"kind":"all"},"applet_operations":["create_bot"],
                    "review_requirement":{"approver_actor_ids":[administrator],"threshold":1,"max_age_seconds":3600}}]}
        }));
    boxed_step(|| configuration_admin_event(&factory.fixture, policy)).await;
    request.intent.request_id = format!("ak:request:{}", uuid::Uuid::now_v7())
        .parse()
        .unwrap();
    request.command = Command::Configure;
    let (status, pending) = boxed_step(|| submit(request.clone())).await;
    assert_eq!(status, StatusCode::OK, "Policy configuration: {pending}");
    let pending: Outcome = serde_json::from_value(pending).unwrap();
    assert_eq!(pending.admission_status, Admission::Pending);
    let candidate = pending
        .source_response_body
        .as_ref()
        .unwrap()
        .create_event
        .as_deref()
        .unwrap();
    assert!(
        factory
            .fixture
            .state
            .test_persistence()
            .authority_commits()
            .committed_event(&candidate.event_id)
            .await
            .unwrap()
            .is_none()
    );
    let review_id = pending
        .review_request_id
        .as_ref()
        .expect("actual Service review id");
    let material = factory
        .fixture
        .state
        .test_persistence()
        .agents()
        .management_review_material(
            &ActorId::service(package.service_id.clone()),
            review_id.as_str(),
            &[],
        )
        .await
        .unwrap();
    let reference = material.request.configuration_ref.as_ref().unwrap();
    assert_eq!(reference.request_id, request.intent.request_id);
    assert_eq!(reference.intent_digest, pending.intent_digest);
    assert_eq!(
        material
            .request
            .target
            .canonical_target_digest()
            .unwrap()
            .as_str(),
        arkret_canonical::canonical_sha256(candidate).unwrap()
    );
    let vote = configuration_review_vote(&factory.fixture, &material.request);
    let decision = arkret_models_integration::ManagementReviewDecisionRequestBody {
        request_id: review_id.to_string(),
        expected_status: arkret_models_integration::ManagementReviewStatus::Pending,
        decision: arkret_models_integration::ManagementReviewDecision::Approve,
        approval_signatures: vec![vote],
    };
    let decision_body = json!(decision);
    let (status, approved) = boxed_step(|| {
        factory.fixture.admin_post(
            "/_arkret/self/management-reviews/decisions",
            arkret_wire::ServiceOperationId::SELF_MANAGEMENT_REVIEW_COMMAND_DECIDE_V1,
            &decision_body,
            Some(review_id.as_str()),
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "real configuration approval: {approved}"
    );
    assert_eq!(approved["status"], "approved");
    *native.managed_router.lock().unwrap() = Some(make_router());
    request.command = Command::Recover;
    let (status, admitted) = boxed_step(|| submit(request.clone())).await;
    assert_eq!(status, StatusCode::OK, "approved cold recovery: {admitted}");
    let admitted: Outcome = serde_json::from_value(admitted).unwrap();
    assert_eq!(admitted.admission_status, Admission::Accepted);
    assert_eq!(
        admitted
            .source_response_body
            .as_ref()
            .unwrap()
            .create_event
            .as_deref(),
        Some(candidate)
    );
    let material = factory
        .fixture
        .state
        .test_persistence()
        .agents()
        .management_review_material(
            &ActorId::service(package.service_id.clone()),
            review_id.as_str(),
            &[],
        )
        .await
        .unwrap();
    assert_eq!(
        material.outcome.status,
        arkret_models_integration::ManagementReviewStatus::Consumed
    );
    request.intent.request_id = arkret_wire::new_prefixed_uuid7("ak:request:")
        .parse()
        .unwrap();
    request.command = Command::Configure;
    let (status, pending) = boxed_step(|| submit(request.clone())).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "forwardable configuration approval: {pending}"
    );
    let pending: Outcome = serde_json::from_value(pending).unwrap();
    assert_eq!(pending.admission_status, Admission::Pending);
    let review_id = pending.review_request_id.as_ref().unwrap();
    let material = factory
        .fixture
        .state
        .test_persistence()
        .agents()
        .management_review_material(
            &ActorId::service(package.service_id.clone()),
            review_id.as_str(),
            &[],
        )
        .await
        .unwrap();
    request.approval_signatures = Some(vec![configuration_review_vote(
        &factory.fixture,
        &material.request,
    )]);
    request.command = Command::Recover;
    let (status, accepted) = boxed_step(|| submit(request.clone())).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "configuration carries the original real Account vote: {accepted}"
    );
    assert_eq!(accepted["admission_status"], "accepted");
    let material = factory
        .fixture
        .state
        .test_persistence()
        .agents()
        .management_review_material(
            &ActorId::service(package.service_id.clone()),
            review_id.as_str(),
            &[],
        )
        .await
        .unwrap();
    assert_eq!(
        material.outcome.status,
        arkret_models_integration::ManagementReviewStatus::Consumed
    );

    request.intent.request_id = format!("ak:request:{}", uuid::Uuid::now_v7())
        .parse()
        .unwrap();
    request.approval_signatures = None;
    request.command = Command::Configure;
    let (status, pending) = boxed_step(|| submit(request.clone())).await;
    assert_eq!(status, StatusCode::OK, "pending before handoff: {pending}");
    assert_eq!(pending["admission_status"], "pending");
    let destination_database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    let (next_governor, _next_server) =
        boxed_step(|| network_fixture(destination_database.pool())).await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let (completed, observed) = tokio::sync::oneshot::channel();
    let (release, delayed) = std::sync::mpsc::channel();
    *native.configuration_response_fault.lock().unwrap() = Some(ConfigurationResponseFault {
        completed,
        release: Some(delayed),
    });
    let mut delayed_request = request.clone();
    delayed_request.command = Command::Recover;
    let (late_response, (manifest, bytes)) =
        tokio::join!(boxed_step(|| submit(delayed_request)), async {
            let source = observed.await.unwrap();
            assert_eq!(source, pending["source_response_body"]);
            let head = store
                .stream_head(&arkret_wire::CommitStreamRef::Realm {
                    realm_id: factory.fixture.realm.clone(),
                })
                .await
                .unwrap()
                .unwrap();
            let authority = store
                .current_authority(&factory.fixture.realm)
                .await
                .unwrap()
                .unwrap();
            let change = factory.fixture.admin_event(
                EventKind::RealmGovernanceStationChange,
                ScopeRef::Realm {
                    realm_id: factory.fixture.realm.clone(),
                },
                json!({
                        "expected_governance_generation": (authority.generation).to_string(),
                        "expected_realm_stream_commit_id": head.commit_id,
                "new_governance_station_id": next_governor.state.service_core_id()
                    }),
            );
            boxed_step(|| configuration_admin_event(&factory.fixture, change)).await;
            let (manifest, bytes) = store
                .export_management_private_state(&factory.fixture.realm)
                .await
                .unwrap();
            // Release the genuine Applet response only after the signed governance
            // change has frozen the Realm's private transfer bytes.
            release.send(()).unwrap();
            (manifest, bytes)
        });
    assert_eq!(
        late_response.0,
        StatusCode::SERVICE_UNAVAILABLE,
        "late Applet result cannot rewrite the frozen ledger: {}",
        late_response.1
    );
    let (_, after_late_response) = store
        .export_management_private_state(&factory.fixture.realm)
        .await
        .unwrap();
    assert_eq!(bytes, after_late_response);
    let archive: Value = serde_json::from_slice(&bytes).unwrap();
    let row = archive["tables"]["applet_configurations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["request_id"] == json!(request.intent.request_id))
        .unwrap();
    assert_eq!(row["outcome"], pending);
    assert_eq!(row["candidate"], pending["source_response_body"]["create_event"]);
    assert_eq!(
        row["ingress"]["requester_account_id"],
        json!(factory.fixture.pcr.history.account)
    );
    for command in [Command::Cancel, Command::Recover, Command::Configure] {
        request.command = command;
        let (status, response) = boxed_step(|| submit(request.clone())).await;
        assert_ne!(
            status,
            StatusCode::OK,
            "frozen configuration must remain untouched: {response}"
        );
        let (_, after) = store
            .export_management_private_state(&factory.fixture.realm)
            .await
            .unwrap();
        assert_eq!(bytes, after, "frozen private configuration cannot change");
    }
    assert!(
        prepare_configuration_completion(&factory.fixture, &completion)
            .await
            .is_err(),
        "frozen completion cannot create a new transport attempt"
    );
    assert!(
        factory
            .fixture
            .state
            .test_persistence()
            .applets()
            .acknowledge_authoring_completion(
                &completion.applet_id,
                &completion.request_digest,
                &fresh.idempotency_key,
                chrono::Utc::now()
            )
            .await
            .is_err(),
        "late completion ACK cannot mutate the frozen handoff ledger"
    );
    let (_, after) = store
        .export_management_private_state(&factory.fixture.realm)
        .await
        .unwrap();
    assert_eq!(bytes, after);
    boxed_step(|| independent_management_archive(&factory.fixture, &manifest, &bytes, &archive))
        .await;
    boxed_step(|| {
        configuration_handoff_resume(
            &factory.fixture,
            &next_governor,
            &request,
            &manifest,
            &bytes,
            &pending,
            &completion,
        )
    })
    .await;
}

async fn deliver_configuration_completion(
    fixture: &Fixture,
    completion: &coland_storage::AppletAuthoringCompletion,
    delivery: &coland_storage::AppletAuthoringCompletion,
) -> Result<arkret_models_integration::AppletTransactionResponseBody, String> {
    let http = reqwest::Client::builder()
        .tls_backend_rustls()
        .tls_certs_only(reqwest::Certificate::from_pem_bundle(&native_tls_material().ca).unwrap())
        .build()
        .unwrap();
    let client = arkret_http_client::Client::builder(delivery.endpoint.parse().unwrap())
        .http_client(http)
        .retry(arkret_http_client::RetryConfig::disabled())
        .http_message_signer(arkret_http_client::HttpMessageSigner::new(
            fixture
                .state
                .service_verification_method("notary-key")
                .unwrap()
                .to_string(),
            fixture.state.notary_signing_key().as_ref().clone(),
        ))
        .build()
        .unwrap();
    let body = arkret_models_integration::AppletTransactionRequestBody::Authoring(Box::new(
        arkret_models_integration::AppletAuthoringTransactionRequestBody {
            applet_id: completion.applet_id.clone(),
            source_id: delivery.source_id.clone(),
            authoring_context: delivery.context.clone().expect("prepared completion"),
        },
    ));
    let body = arkret_identity::VerifiedSubmission::from_verified_events(body, &[]).unwrap();
    let outcome = client
        .applet_transaction_from_service(
            &delivery.idempotency_key,
            &body,
            &delivery.source_id,
            &delivery.destination_id,
        )
        .await
        .map_err(|e| e.to_string())?;
    match &outcome {
        arkret_models_integration::AppletTransactionResponseBody::Accepted {
            committed_event_refs,
            rejections,
            retry_after_ms,
        } if committed_event_refs.is_empty()
            && rejections.is_empty()
            && retry_after_ms.is_none() =>
        {
            Ok(outcome)
        }
        _ => Err(format!("historical completion did not finish: {outcome:?}")),
    }
}

async fn prepare_configuration_completion(
    fixture: &Fixture,
    completion: &coland_storage::AppletAuthoringCompletion,
) -> coland_services::ServiceResult<coland_storage::AppletAuthoringCompletion> {
    completion_application(&fixture.state)
        .prepare_applet_authoring_completion(
            completion,
            &fixture.state.service_core_id(),
            &fixture.state.service_verification_method("notary-key").unwrap(),
            fixture.state.notary_signing_key().as_ref(),
        )
        .await

}

// The same signed activation is exercised by configuration and native MLS.
async fn activate_fixture_handoff(
    previous: &Fixture,
    next: &Fixture,
    manifest: &arkret_models_collaboration::authority_commit::ManagementPrivateHandoffManifest,
    bytes: &[u8],
) {
    use arkret_models_collaboration::authority_commit::{
        AuthorityRealmAuthorityHandoffRequestBody, HistoricalProducerSignerFactEntry, historical_signer_facts_digest,
    };
    use arkret_wire::*;
    let source = PgAuthorityCommitStore {
        pool: previous.pool.clone(),
    };
    let target = PgAuthorityCommitStore {
        pool: next.pool.clone(),
    };
    let local_identity = next
        .state
        .test_persistence()
        .service_identity()
        .get()
        .await
        .unwrap()
        .unwrap();
    let archive: Value = serde_json::from_slice(bytes).unwrap();
    // Ordinary pre-import is a fixture prerequisite. The management-private
    // transfer, signed activation and subsequent configuration are production
    // operations against an independent destination database and HTTPS host.
    management_archive_fixture::seed_ordinary_on_foreign_station(
        &previous.pool,
        &next.pool,
        archive["tables"].as_object().unwrap(),
    )
    .await;
    next.state
        .test_persistence()
        .service_identity()
        .put(local_identity)
        .await
        .unwrap();
    let restored = coland_test_support::app_state_with_persistence(
        next.state.config().clone(),
        Arc::new(coland_storage_postgres::PgPersistenceStore::new(
            next.pool.clone(),
        )),
    )
    .await;
    assert_eq!(restored.service_core_id(), next.state.service_core_id());
    // The receiving operator knows the outgoing peer's locator. Discovery still
    // authenticates its complete history and Describe over the real HTTPS host.
    // The old Station learns the new route from the production handoff itself.
    next.state
        .service_route_resolver()
        .unwrap()
        .resolve_carrier(
            &arkret_models_identity::ServiceResolutionCarrier::ResolutionUrl {
                resolution_url: format!(
                    "{}{}",
                    previous
                        .state
                        .config()
                        .public_base_url
                        .trim_end_matches('/'),
                    arkret_models_identity::canonical_service_resolution_path(
                        &previous.state.service_core_id(),
                    ),
                ),
            },
            &previous.state.service_core_id(),
            "station",
            chrono::Utc::now(),
        )
        .await
        .unwrap();
    target
        .import_management_private_state(manifest, bytes)
        .await
        .unwrap();
    let (_, imported) = target
        .export_management_private_state(&previous.realm)
        .await
        .unwrap();
    assert_eq!(bytes, imported);

    let material = source
        .realm_state_snapshot_material(&previous.realm)
        .await
        .unwrap()
        .unwrap();
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let snapshot = coland_services::authority_commit::build_signed_realm_state_snapshot(
        &material,
        previous
            .state
            .service_verification_method("notary-key")
            .unwrap(),
        previous.state.notary_signing_key().as_ref(),
        at,
    )
    .unwrap();
    let mut facts = Vec::new();
    for full in source.handoff_originals(&previous.realm).await.unwrap() {
        assert_eq!(
            arkret_identity::verification_method_did(
                full.commit.signature.verification_method.as_str()
            )
            .unwrap(),
            previous.state.service_did(),
            "handoff fixture must retain actual governance signatures: {}",
            full.event.event_id
        );
        if full.commit.producer_signer_fact_digest.is_some() {
            facts.push(HistoricalProducerSignerFactEntry {
                target: CommittedEventRef {
                    event_id: full.event.event_id.clone(),
                    commit_id: full.commit.commit_id.clone(),
                    stream_ref: full.commit.stream_ref.clone(),
                    stream_position: full.commit.stream_position,
                },
                producer_signer_fact: source
                    .producer_signer_fact(&full.event, &full.commit)
                    .await
                    .unwrap()
                    .unwrap(),
            });
        }
    }
    facts.sort_by_key(|entry| {
        (
            arkret_canonical::canonical_json_bytes(&entry.target.stream_ref).unwrap(),
            entry.target.stream_position,
            entry.target.event_id.to_string(),
            entry.target.commit_id.to_string(),
        )
    });
    let heads = material.visible_stream_heads.clone();
    let head = heads
        .iter()
        .find(|head| {
            head.stream_ref
                == (CommitStreamRef::Realm {
                    realm_id: previous.realm.clone(),
                })
        })
        .unwrap()
        .clone();
    let change = source
        .committed_event_by_commit_id(&head.commit_id)
        .await
        .unwrap()
        .unwrap();
    let mut handoff = RealmAuthorityHandoff {
        handoff_id: RealmAuthorityHandoffId::from_digest(rand::random()),
        realm_id: previous.realm.clone(),
        from_generation: material.governance_generation,
        to_generation: material.governance_generation + 1,
        from_service_id: previous.state.service_core_id(),
        to_service_id: next.state.service_core_id(),
        change_event_ref: change.event.event_id.clone(),
        change_commit_id: change.commit.commit_id.clone(),
        final_stream_heads_digest: Hash::new(arkret_canonical::canonical_sha256(&heads).unwrap())
            .unwrap(),
        historical_signer_facts_digest: Some(historical_signer_facts_digest(&facts).unwrap()),
        snapshot_ref: snapshot.snapshot_id.clone(),
        pcr_private_state_digest: None,
        management_private_state_digest: Some(manifest.digest().unwrap()),
        old_authority_signature: snapshot.signature.clone(),
        new_authority_acceptance_signature: snapshot.signature.clone(),
    };
    let unsigned = arkret_canonical::unsigned_value(
        &handoff,
        &[
            "old_authority_signature",
            "new_authority_acceptance_signature",
        ],
    )
    .unwrap();
    handoff.old_authority_signature = sign_detached_object(
        &unsigned,
        DetachedSignatureContext::RealmAuthorityHandoffOld,
        previous
            .state
            .service_verification_method("notary-key")
            .unwrap(),
        at,
        previous.state.notary_signing_key().as_ref(),
    )
    .unwrap();
    handoff.new_authority_acceptance_signature = sign_detached_object(
        &unsigned,
        DetachedSignatureContext::RealmAuthorityHandoffNewAcceptance,
        next.state
            .service_verification_method("notary-key")
            .unwrap(),
        at,
        next.state.notary_signing_key().as_ref(),
    )
    .unwrap();
    let bundle_request = RealmAuthorityBundleRequestBody {
        realm_id: previous.realm.clone(),
        nonce: Base64UrlString::new(arkret_canonical::base64url_encode(
            rand::random::<[u8; 32]>(),
        ))
        .unwrap(),
    };
    let mut response = TestClient::post(format!(
        "{}/_arkret/open/realm-authority/bundle",
        previous
            .state
            .config()
            .public_base_url
            .trim_end_matches('/')
    ))
    .add_header(
        "arkret-operation",
        ServiceOperationId::OPEN_REALM_AUTHORITY_READ_BUNDLE_V1,
        true,
    )
    .add_header("content-type", "application/json", true)
    .body(arkret_canonical::canonical_json_bytes(&bundle_request).unwrap())
    .send(&service(previous.state.clone()))
    .await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    let mut bundle: RealmAuthorityBundle = response.take_json().await.unwrap();
    assert_eq!(
        bundle.genesis_commit.signature.verification_method,
        previous
            .state
            .service_verification_method("notary-key")
            .unwrap(),
        "handoff genesis must carry the actual governance signature"
    );
    let resolution_path =
        arkret_models_identity::canonical_service_resolution_path(&next.state.service_core_id());
    let mut response = TestClient::get(format!(
        "{}{resolution_path}",
        next.state.config().public_base_url
    ))
    .add_header(
        "arkret-operation",
        ServiceOperationId::OPEN_SERVICE_READ_RESOLUTION_V1,
        true,
    )
    .send(&service(next.state.clone()))
    .await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    bundle.current_route_record = response.take_json::<Value>().await.unwrap();
    bundle.current_generation = handoff.to_generation;
    bundle.current_service_id = handoff.to_service_id.clone();
    bundle.realm_stream_head = head.clone();
    bundle.authority_transitions.push(RealmAuthorityTransition {
        change_event: change.event,
        change_commit: change.commit,
        handoff: handoff.clone(),
    });
    bundle.bundle_issued_at = at;
    bundle.current_assertion.current_generation = handoff.to_generation;
    bundle.current_assertion.current_service_id = handoff.to_service_id.clone();
    bundle.current_assertion.last_handoff_ref = Some(handoff.handoff_id.clone());
    bundle.current_assertion.realm_stream_head = head;
    bundle.current_assertion.expires_at = at + chrono::Duration::minutes(5);
    bundle.current_assertion.signature = sign_detached_object(
        &arkret_canonical::unsigned_value(&bundle.current_assertion, &["signature"]).unwrap(),
        DetachedSignatureContext::RealmAuthorityCurrentAssertion,
        next.state
            .service_verification_method("notary-key")
            .unwrap(),
        at,
        next.state.notary_signing_key().as_ref(),
    )
    .unwrap();
    let activation = AuthorityRealmAuthorityHandoffRequestBody {
        handoff,
        final_stream_heads: heads,
        snapshot,
        authority_bundle: bundle,
        historical_signer_facts: Some(facts),
        pcr_private_state: None,
        management_private_state: Some(manifest.clone()),
    };
    activation.validate_new_handoff().unwrap();
    let mut invalid_signature = activation.clone();
    invalid_signature
        .handoff
        .new_authority_acceptance_signature
        .signature = Base64UrlString::new(arkret_canonical::base64url_encode([0u8; 64])).unwrap();
    invalid_signature
        .authority_bundle
        .authority_transitions
        .last_mut()
        .unwrap()
        .handoff = invalid_signature.handoff.clone();
    let (status, refused) = configuration_peer_post(
        previous,
        next,
        "/_arkret/peer/realm-authority/handoff",
        ServiceOperationId::PEER_REALM_AUTHORITY_COMMAND_HANDOFF_V1,
        &invalid_signature,
    )
    .await;
    assert_ne!(status, StatusCode::OK);
    assert_eq!(
        refused["type"], "https://arkret.org/problems/signature_invalid",
        "{refused}"
    );
    assert_eq!(
        target
            .current_authority(&previous.realm)
            .await
            .unwrap()
            .unwrap()
            .generation,
        manifest.governance_generation
    );
    let mut public_objects = Vec::new();
    for full in source.handoff_originals(&previous.realm).await.unwrap() {
        if full.event.kind != EventKind::MlsGenesis {
            continue;
        }
        let payload: arkret_models_collaboration::events_payloads::MlsGenesisPayload =
            serde_json::from_value(serde_json::to_value(&full.event.payload).unwrap()).unwrap();
        for reference in [&payload.group_info_ref, &payload.ratchet_tree_ref] {
            let record = previous
                .state
                .test_persistence()
                .blobs()
                .get(reference.as_str())
                .await
                .unwrap()
                .unwrap();
            let bytes = previous.state.test_object_by_sha256(&record.sha256).await;
            assert_eq!(
                reference.as_str(),
                format!("ak:blob:{}", arkret_canonical::sha256_digest(&bytes))
            );
            assert_eq!(
                next.state
                    .test_persistence()
                    .blobs()
                    .get(reference.as_str())
                    .await
                    .unwrap(),
                Some(record.clone()),
                "the imported index alone does not import its public bytes"
            );
            public_objects.push((record.storage_key, bytes));
        }
    }
    if !public_objects.is_empty() {
        // Neither absent nor corrupted public objects may enable authority.
        // Only public GroupInfo/tree bytes are copied, never member secrets.
        for corrupt in [false, true] {
            if corrupt {
                for (key, bytes) in &public_objects {
                    next.state
                        .test_put_object(key, vec![0; bytes.len()])
                        .await
                        .unwrap();
                }
            }
            let (status, refused) = configuration_peer_post(
                previous,
                next,
                "/_arkret/peer/realm-authority/handoff",
                ServiceOperationId::PEER_REALM_AUTHORITY_COMMAND_HANDOFF_V1,
                &activation,
            )
            .await;
            assert_ne!(status, StatusCode::OK);
            assert_eq!(
                refused["type"], "https://arkret.org/problems/temporarily_unavailable",
                "{refused}"
            );
            assert!(
                refused["detail"]
                    .as_str()
                    .unwrap_or("")
                    .contains("MLS public material"),
                "{refused}"
            );
            assert_eq!(
                target
                    .current_authority(&previous.realm)
                    .await
                    .unwrap()
                    .unwrap()
                    .generation,
                manifest.governance_generation
            );
            assert!(
                target
                    .authority_handoffs(&previous.realm)
                    .await
                    .unwrap()
                    .is_empty()
            );
            let (_, unchanged) = target
                .export_management_private_state(&previous.realm)
                .await
                .unwrap();
            assert_eq!(bytes, unchanged);
        }
        for (key, bytes) in public_objects {
            next.state.test_put_object(&key, bytes).await.unwrap();
        }
    }
    for (sender, receiver) in [(previous, next), (next, previous)] {
        let (status, result) = configuration_peer_post(
            sender,
            receiver,
            "/_arkret/peer/realm-authority/handoff",
            ServiceOperationId::PEER_REALM_AUTHORITY_COMMAND_HANDOFF_V1,
            &activation,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "activate signed configuration handoff: {result}"
        );
    }
}

async fn configuration_handoff_resume(
    previous: &Fixture,
    next: &Fixture,
    request: &arkret_models_integration::AppletConfigurationRequestBody,
    manifest: &arkret_models_collaboration::authority_commit::ManagementPrivateHandoffManifest,
    bytes: &[u8],
    pending: &Value,
    completion: &coland_storage::AppletAuthoringCompletion,
) {
    use arkret_wire::*;
    boxed_step(|| activate_fixture_handoff(previous, next, manifest, bytes)).await;
    let source = PgAuthorityCommitStore {
        pool: previous.pool.clone(),
    };
    let target = PgAuthorityCommitStore {
        pool: next.pool.clone(),
    };
    assert!(
        prepare_configuration_completion(previous, completion)
            .await
            .is_err(),
        "outgoing governor cannot prepare another attempt"
    );
    let resumed_delivery = prepare_configuration_completion(next, completion)
        .await
        .unwrap();
    assert_eq!(resumed_delivery.source_id, next.state.service_core_id());
    assert_eq!(
        resumed_delivery.context.as_ref().unwrap().material.governance_generation,
        manifest.governance_generation + 1
    );
    let arkret_models_integration::RealmActorMaterial::Event { event, commit, .. } =
        &resumed_delivery.context.as_ref().unwrap().material.material
    else {
        panic!("creation material required")
    };
    assert_eq!(event.event_id, completion.creation_ref.event_id);
    assert_eq!(commit.commit_id, completion.creation_ref.commit_id);
    let reference = pending["review_request_id"].as_str().unwrap();
    let outcome: arkret_models_integration::AppletConfigurationResponseBody =
        serde_json::from_value(pending.clone()).unwrap();
    let candidate = outcome.source_response_body.unwrap().create_event.unwrap();
    let candidate_payload: RealmActorCreatePayload =
        serde_json::from_value(json!(candidate.payload)).unwrap();
    let actor = ActorId::service(candidate_payload.service_id.clone());
    let review = next
        .state
        .test_persistence()
        .agents()
        .management_review_material(&actor, reference, &[])
        .await
        .unwrap();
    assert_eq!(
        review.outcome.status,
        arkret_models_integration::ManagementReviewStatus::Pending,
        "handoff preserves unchanged review pins for independent current revalidation"
    );
    let mut continued = request.clone();
    continued.command = arkret_models_integration::AppletConfigurationCommand::Recover;
    continued.approval_signatures =
        Some(vec![configuration_review_vote(previous, &review.request)]);
    let path = format!(
        "/_arkret/self/applets/{}/configuration",
        candidate_payload.applet_id
    );
    let (status, resumed) = previous
        .admin_post(
            &path,
            ServiceOperationId::SELF_APPLET_CONFIGURATION_COMMAND_SUBMIT_V1,
            &json!(continued),
            Some(continued.intent.request_id.as_str()),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "original Account resumes through the new governor: {resumed}"
    );
    assert_eq!(
        resumed["admission_status"], "accepted",
        "continued configuration: {resumed}"
    );
    assert_eq!(resumed["source_response_body"], pending["source_response_body"]);
    let accepted = target
        .committed_event(&candidate.event_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(accepted.event, *candidate);
    assert_eq!(
        accepted.commit.governance_generation,
        manifest.governance_generation + 1
    );
    assert!(
        source
            .committed_event(&accepted.event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    let (status, replay) = previous
        .admin_post(
            &path,
            ServiceOperationId::SELF_APPLET_CONFIGURATION_COMMAND_SUBMIT_V1,
            &json!(continued),
            Some(continued.intent.request_id.as_str()),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "accepted continuation replay: {replay}"
    );
    assert_eq!(
        replay, resumed,
        "replay returns the original new-generation result"
    );
    tokio::time::sleep(std::time::Duration::from_secs(31)).await;
    let delivered =
        boxed_step(|| coland_http::state::deliver_pending_applet_completions(&next.state))
            .await
            .unwrap();
    assert!(
        delivered >= 1,
        "the production sweeper delivers after governance handoff"
    );
    #[derive(diesel::QueryableByName)]
    struct CompletionStatus {
        #[diesel(sql_type = diesel::sql_types::Bool)]
        delivered: bool,
    }
    use diesel_async::RunQueryDsl as _;
    let mut conn = next.pool.get().await.unwrap();
    let status = diesel::sql_query("SELECT delivered_at IS NOT NULL AS delivered FROM applet_authoring_completions WHERE applet_id=$1 AND request_digest=$2")
        .bind::<diesel::sql_types::Text, _>(completion.applet_id.as_str())
        .bind::<diesel::sql_types::Text, _>(completion.request_digest.as_str())
        .get_result::<CompletionStatus>(&mut conn).await.unwrap();
    assert!(
        status.delivered,
        "the exact original creation receives a durable network acknowledgement"
    );
}

fn configuration_review_vote(
    fixture: &Fixture,
    request: &arkret_models_integration::ManagementReviewRequestBody,
) -> arkret_wire::ApprovalSignature {
    use arkret_wire::*;
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let root = SigningKey::from_bytes(&[70; 32]);
    let multibase =
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(root.verifying_key().as_bytes());
    let method = DidUrl::new(format!("did:key:{multibase}#{multibase}")).unwrap();
    let arkret_models_integration::ManagementReviewTarget::Event { event } = &request.target;
    let mut vote = ApprovalSignature {
        input: ApprovalSignatureInput {
            approval_context: ApprovalContext::Management {
                request_id: request.request_id.clone(),
                management_operation: request.management_operation,
                effective_scope: request.effective_scope.clone(),
            },
            approval_target: ApprovalTarget::Event {
                event_id: event.event_id.clone(),
            },
            request_canonical_digest: request.target.canonical_target_digest().unwrap(),
            operation: ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1.into(),
            action: CapabilityActionId::AppletBotProvision,
            realm_id: event.realm_id.clone(),
            initiating_actor_id: event.actual_signer().clone(),
            approver_did: fixture.pcr.history.did.clone(),
            approved_at: at,
            nonce: format!(
                "{}{}",
                uuid::Uuid::new_v4().simple(),
                uuid::Uuid::new_v4().simple()
            ),
        },
        proof: ApprovalSignatureProof {
            kind: ApprovalSignatureProofKind::DetachedJws,
            verification_method: method.clone(),
            jws: String::new(),
        },
    };
    vote.proof.jws =
        arkret_signatures::Ed25519DetachedJwsSigner::from_seed([70; 32], method.as_str())
            .sign_detached_jws(
                &arkret_signatures::approval_signature::approval_signature_signing_bytes(&vote)
                    .unwrap(),
            );
    vote
}

async fn cross_station_configuration(governor: &Fixture, applet: &AppletId, service: &arkret_wire::DidCoreId, scope: &ScopeRef) {
    use arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequestBody;
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    let (account_station, _server) = boxed_step(|| network_fixture(database.pool())).await;
    for (reader, destination) in [(&account_station, governor), (governor, &account_station)] {
        let service_id = destination.state.service_core_id();
        reader
            .state
            .service_route_resolver()
            .unwrap()
            .resolve_carrier(
                &arkret_models_identity::ServiceResolutionCarrier::ResolutionUrl {
                    resolution_url: format!(
                        "{}{}",
                        destination
                            .state
                            .config()
                            .public_base_url
                            .trim_end_matches('/'),
                        arkret_models_identity::canonical_service_resolution_path(&service_id)
                    ),
                },
                &service_id,
                "station",
                chrono::Utc::now(),
            )
            .await
            .unwrap();
    }
    let realm_scope = ScopeRef::Realm {
        realm_id: governor.realm.clone(),
    };
    let invite = governor.admin_event(EventKind::InviteCreate, realm_scope.clone(), json!({
        "invitee_account_id":account_station.pcr.history.account,
        "introduction_evidence_digest":format!("sha256:{}", "c".repeat(64)),
        "expires_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now()+chrono::Duration::hours(1))
    }));
    boxed_step(|| accepted_admin_domain_event(governor, invite.clone())).await;
    let authority = governor
        .state
        .test_persistence()
        .authority_commits()
        .current_authority(&governor.realm)
        .await
        .unwrap()
        .unwrap();
    account_station
        .state
        .test_persistence()
        .authority_commits()
        .record_remote_authority(&authority, &account_station.state.service_core_id())
        .await
        .unwrap();
    let accept = account_station.admin_event(EventKind::InviteAccept, realm_scope.clone(), json!({
        "invite_id":arkret_wire::InviteId::from_event_id(&invite.event_id),"previous_state":"pending",
        "invitee_account_id":account_station.pcr.history.account
    }));
    let accept_body = json!(SelfAuthoritySubmitRequestBody::Event(
        arkret_wire::EventAdmissionSubmission::new(accept)
    ));
    let (status, result) = boxed_step(|| {
        account_station.admin_post(
            "/_arkret/self/events",
            arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
            &accept_body,
            None,
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "foreign administrator membership: {result}"
    );
    let endpoint = format!("/_arkret/self/applets/{applet}/configuration");
    let mut request = arkret_models_integration::AppletConfigurationRequestBody {
        command: arkret_models_integration::AppletConfigurationCommand::Recover,
        intent: arkret_models_integration::AppletConfigurationIntent {
            service_id: service.clone(),
            request_id: arkret_wire::new_prefixed_uuid7("ak:request:")
                .parse()
                .unwrap(),
            effective_scope: scope.clone(),
            selection: arkret_models_integration::AppletConfigurationSelection::NewBot {
                display_name: Some("Foreign admin Bot".into()),
            },
        },
        approval_signatures: None,
    };
    let submit = |request: arkret_models_integration::AppletConfigurationRequestBody| {
        let station = &account_station;
        let endpoint = endpoint.clone();
        async move {
            station
                .admin_post(
                    &endpoint,
                    arkret_wire::ServiceOperationId::SELF_APPLET_CONFIGURATION_COMMAND_SUBMIT_V1,
                    &json!(request),
                    Some(request.intent.request_id.as_str()),
                )
                .await
        }
    };
    let (status, refused) = boxed_step(|| submit(request.clone())).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "membership is not configuration authority: {refused}"
    );
    let mut peer = arkret_models_integration::AppletConfigurationPeerRequestBody {
        requester_account_id: account_station.pcr.history.account.clone(),
        request: request.clone(),
    };
    peer.requester_account_id.station_id = governor.state.service_core_id();
    let (status, _) =
        boxed_step(|| peer_configuration_post(&account_station, governor, applet, &peer, false))
            .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "source Station cannot claim a different Account Station"
    );
    peer.requester_account_id = account_station.pcr.history.account.clone();
    let (status, _) =
        boxed_step(|| peer_configuration_post(&account_station, governor, applet, &peer, true))
            .await;
    assert_ne!(
        status,
        StatusCode::OK,
        "tampered original peer body is rejected"
    );
    let grant = governor.admin_event(EventKind::CapabilityGrant, realm_scope, json!({"grant":{
        "schema":"ak.schema.capability.v1","realm_id":governor.realm,
        "issuer_id":ActorId::account(governor.pcr.history.account.clone()),
        "subject":ActorId::account(account_station.pcr.history.account.clone()),
        "actions":["ak.realm.admin"],"resources":[{"kind":"realm","realm_id":governor.realm}],"constraints":[],
        "issuer_authority_refs":[{"kind":"realm_root","realm_id":governor.realm,"authority_event_ref":governor.authority_event_ref,"authority_generation":"0"}],
        "issued_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())
    }}));
    let grant_id = arkret_wire::GrantId::from_event_id(&grant.event_id);
    let grant_event_id = grant.event_id.clone();
    boxed_step(|| configuration_admin_event(governor, grant)).await;
    request.command = arkret_models_integration::AppletConfigurationCommand::Configure;
    let (status, accepted) = boxed_step(|| submit(request.clone())).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "account Station to governance Station to Applet: {accepted}"
    );
    assert_eq!(accepted["admission_status"], "accepted");
    use diesel::sql_types::{Jsonb, Text};
    use diesel_async::RunQueryDsl;
    #[derive(diesel::QueryableByName)]
    struct Ledger {
        #[diesel(sql_type = Jsonb)]
        intent: Value,
        #[diesel(sql_type = Jsonb)]
        ingress: Value,
    }
    let mut conn = governor.pool.get().await.unwrap();
    let ledger = diesel::sql_query(
        "SELECT intent,ingress FROM applet_configurations WHERE realm_id=$1 AND request_id=$2",
    )
    .bind::<Text, _>(governor.realm.as_str())
    .bind::<Text, _>(request.intent.request_id.as_str())
    .get_result::<Ledger>(&mut conn)
    .await
    .unwrap();
    assert_eq!(
        ledger.intent["originating_actor_id"],
        json!(ActorId::account(
            account_station.pcr.history.account.clone()
        ))
    );
    assert_eq!(
        ledger.ingress["source"]["source_service_id"],
        json!(account_station.state.service_core_id())
    );
    assert!(!ledger.ingress.to_string().contains(&account_station.token));
    drop(conn);
    request.command = arkret_models_integration::AppletConfigurationCommand::Recover;
    let (status, replay) = boxed_step(|| submit(request.clone())).await;
    assert_eq!(status, StatusCode::OK, "foreign exact recovery: {replay}");
    assert_eq!(accepted, replay);
    let original = governor
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&grant_event_id)
        .await
        .unwrap()
        .unwrap();
    let revoke = governor.admin_event(EventKind::CapabilityRevoke,
        ScopeRef::Realm { realm_id: governor.realm.clone() }, json!({
            "grant_id": grant_id,
            "expected_revision": {"commit_id": original.commit.commit_id, "stream_position": original.commit.stream_position}
        }));
    boxed_step(|| configuration_admin_event(governor, revoke)).await;
    let (status, refused) = boxed_step(|| submit(request)).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "revoked administration cannot recover private configuration: {refused}"
    );
}

async fn peer_configuration_post(
    source: &Fixture,
    destination: &Fixture,
    applet: &AppletId,
    body: &arkret_models_integration::AppletConfigurationPeerRequestBody,
    tamper: bool,
) -> (StatusCode, Value) {
    let bytes = arkret_canonical::canonical_json_bytes(body).unwrap();
    let path = format!("/_arkret/peer/applets/{applet}/configuration");
    let sent = if tamper {
        let mut changed = body.clone();
        changed.requester_account_id = destination.pcr.history.account.clone();
        arkret_canonical::canonical_json_bytes(&changed).unwrap()
    } else {
        bytes.clone()
    };
    configuration_peer_post_wire(
        source,
        destination,
        &path,
        arkret_wire::ServiceOperationId::PEER_APPLET_CONFIGURATION_COMMAND_SUBMIT_V1,
        bytes,
        sent,
    )
    .await
}

async fn configuration_peer_post(
    source: &Fixture,
    destination: &Fixture,
    path: &str,
    operation: &str,
    body: &impl serde::Serialize,
) -> (StatusCode, Value) {
    let bytes = arkret_canonical::canonical_json_bytes(body).unwrap();
    configuration_peer_post_wire(source, destination, path, operation, bytes.clone(), bytes).await
}

async fn configuration_peer_post_wire(
    source: &Fixture,
    destination: &Fixture,
    path: &str,
    operation: &str,
    bytes: Vec<u8>,
    sent: Vec<u8>,
) -> (StatusCode, Value) {
    let digest = content_digest_header(&bytes);
    let request_url = format!(
        "{}{path}",
        destination
            .state
            .config()
            .public_base_url
            .trim_end_matches('/')
    );
    let target = url::Url::parse(&request_url).unwrap();
    let parts = SignedRequestParts {
        method: "POST".into(),
        target_uri: request_url.clone(),
        authority: target[url::Position::BeforeHost..url::Position::AfterPort].into(),
        path: path.to_owned(),
        headers: vec![
            ("arkret-operation".into(), operation.into()),
            ("content-type".into(), "application/json".into()),
            (
                "idempotency-key".into(),
                arkret_canonical::sha256_digest(&bytes),
            ),
            ("content-digest".into(), digest.clone()),
            ("source-service-id".into(), source.state.service_id().into()),
            (
                "destination-service-id".into(),
                destination.state.service_id().into(),
            ),
            (
                "source-trust-domain".into(),
                source.state.config().trust_domain.to_string(),
            ),
            (
                "destination-trust-domain".into(),
                destination.state.config().trust_domain.to_string(),
            ),
        ],
        body_digest: Some(digest),
    };
    let signature = sign_http_message_for_scenario(
        &parts,
        HttpSignatureScenario::ServiceToServiceV1,
        &[
            "content-digest",
            "idempotency-key",
            "source-trust-domain",
            "destination-trust-domain",
        ],
        "sig1",
        source
            .state
            .service_verification_method("notary-key")
            .unwrap()
            .as_str(),
        chrono::Utc::now().timestamp(),
        source.state.notary_signing_key().as_ref(),
    )
    .unwrap();
    let client = native_http_client(std::time::Duration::from_secs(45));
    let mut request = client.post(request_url);
    for (name, value) in parts.headers {
        request = request.header(name, value);
    }
    let response = request
        .header("signature-input", signature.signature_input_header)
        .header("signature", signature.signature_header)
        .body(sent)
        .send()
        .await
        .unwrap();
    (response.status(), response.json().await.unwrap())
}

async fn configuration_admin_event(fixture: &Fixture, event: Event) {
    let body = json!(
        arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequestBody::Event(
            arkret_wire::EventAdmissionSubmission::new(event)
        )
    );
    let (status, response) = fixture
        .admin_post(
            "/_arkret/self/events",
            arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
            &body,
            None,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "administrator Event with actual peer fanout: {response}"
    );
}

pub(super) async fn handoff_runtime_realm(previous: &Fixture, next: &Fixture) {
    let store = PgAuthorityCommitStore {
        pool: previous.pool.clone(),
    };
    let head = store
        .stream_head(&arkret_wire::CommitStreamRef::Realm {
            realm_id: previous.realm.clone(),
        })
        .await
        .unwrap()
        .unwrap();
    let authority = store
        .current_authority(&previous.realm)
        .await
        .unwrap()
        .unwrap();
    let change = previous.admin_event(
        EventKind::RealmGovernanceStationChange,
        ScopeRef::Realm {
            realm_id: previous.realm.clone(),
        },
        json!({"expected_governance_generation":(authority.generation).to_string(),
            "expected_realm_stream_commit_id":head.commit_id,
            "new_governance_station_id":next.state.service_core_id()}),
    );
    let request = arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequestBody::Event(
        arkret_wire::EventAdmissionSubmission::new(change.clone()),
    );
    // Keep client orchestration outside the server's admission stack, exactly
    // as a deployed Account client sending the same signed change would be.
    let (status, outcome) = previous
        .admin_post_network(
            "/_arkret/self/events",
            arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
            &json!(request),
            change.event_id.as_str(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "real governance change: {outcome}");
    let (manifest, bytes) = store
        .export_management_private_state(&previous.realm)
        .await
        .unwrap();
    boxed_step(|| activate_fixture_handoff(previous, next, &manifest, &bytes)).await;
    assert!(
        store
            .export_management_private_state(&previous.realm)
            .await
            .is_err(),
        "the former governor cannot issue another outgoing archive after activation"
    );
}
