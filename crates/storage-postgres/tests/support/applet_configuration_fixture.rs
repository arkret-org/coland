// Included inside the native Realm fixture so all operations use its accepted
// Account, actual installation transaction and independently hosted Applet.
pub(super) async fn run_configuration(pool: PgPool) {
    use arkret_bridge_runtime::{ArkretEdge, AuthoringJournal, FileAuthoringStore};
    use arkret_models_integration::{
        AppletConfigurationAdmissionStatus as Admission, AppletConfigurationCommand as Command,
        AppletConfigurationIntent, AppletConfigurationOutcome as Outcome,
        AppletConfigurationRequest, AppletConfigurationSelection,
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
            auth: Some(AppletEndpointAuth::WebhookSignature),
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
    let http = reqwest::Client::builder()
        .add_root_certificate(
            reqwest::Certificate::from_pem(include_bytes!(
                "../../../server/tests/fixtures/outbox-test-ca.pem"
            ))
            .unwrap(),
        )
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap();
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
        let edge = Arc::new(
            ArkretEdge::new_outbound(
                Arc::new(config.clone()),
                client.clone(),
                Ed25519PayloadSigner::new(
                    SigningKey::from_bytes(&[42; 32]),
                    did.clone(),
                    package.webhook_auth.key_ref.clone(),
                ),
                AuthoringJournal::new(FileAuthoringStore::shared(path.clone()).unwrap()),
            )
            .unwrap(),
        );
        edge
    };
    let make_router = || {
        Arc::new(salvo::Service::new(
            arkret_bridge_runtime::web::managed_applet_router(make_edge()).unwrap(),
        ))
    };
    *native.managed_router.lock().unwrap() = Some(make_router());
    let endpoint = format!("/_arkret/self/applets/{id}/configuration");
    let mut request = AppletConfigurationRequest {
        command: Command::Recover,
        intent: AppletConfigurationIntent {
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
    let submit = |request: AppletConfigurationRequest| {
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
    assert!(pending.source_outcome.unwrap().create_event.is_none());
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
        .source_outcome
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
    let recovered_edge = make_edge();
    let recovery = arkret_bridge_runtime::applet_configuration::AppletConfigurationService::new(
        recovered_edge.clone(),
    )
    .unwrap();
    assert_eq!(
        boxed_step(|| recovery.recover_accepted_configurations())
            .await
            .unwrap(),
        1
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
    assert!(cancelled["source_outcome"].get("create_event").is_none());

    boxed_step(|| {
        cross_station_configuration(&factory.fixture, &id, &request.intent.effective_scope)
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
        .source_outcome
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
            .source_outcome
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
    let store = PgAuthorityCommitStore { pool: pool.clone() };
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
            "expected_governance_generation": authority.generation,
            "expected_realm_stream_commit_id": head.commit_id,
            "new_governance_station_id": "ak:did_core:web:configuration-next.example"
        }),
    );
    boxed_step(|| configuration_admin_event(&factory.fixture, change)).await;
    let (manifest, bytes) = store
        .export_management_private_state(&factory.fixture.realm)
        .await
        .unwrap();
    let archive: Value = serde_json::from_slice(&bytes).unwrap();
    let row = archive["tables"]["applet_configurations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["request_id"] == json!(request.intent.request_id))
        .unwrap();
    assert_eq!(row["outcome"], pending);
    assert_eq!(row["candidate"], pending["source_outcome"]["create_event"]);
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
    boxed_step(|| independent_management_archive(&factory.fixture, &manifest, &bytes, &archive))
        .await;
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

async fn cross_station_configuration(governor: &Fixture, applet: &AppletId, scope: &ScopeRef) {
    use arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest;
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
    let accept_body = json!(SelfAuthoritySubmitRequest::Event(
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
    let mut request = arkret_models_integration::AppletConfigurationRequest {
        command: arkret_models_integration::AppletConfigurationCommand::Recover,
        intent: arkret_models_integration::AppletConfigurationIntent {
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
    let submit = |request: arkret_models_integration::AppletConfigurationRequest| {
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
    let mut peer = arkret_models_integration::AppletConfigurationPeerRequest {
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
        "issuer_authority_refs":[{"kind":"realm_root","realm_id":governor.realm,"authority_event_ref":governor.authority_event_ref,"authority_generation":0}],
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
    body: &arkret_models_integration::AppletConfigurationPeerRequest,
    tamper: bool,
) -> (StatusCode, Value) {
    let bytes = arkret_canonical::canonical_json_bytes(body).unwrap();
    let digest = content_digest_header(&bytes);
    let path = format!("/_arkret/peer/applets/{applet}/configuration");
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
        path: path.clone(),
        headers: vec![
            (
                "arkret-operation".into(),
                arkret_wire::ServiceOperationId::PEER_APPLET_CONFIGURATION_COMMAND_SUBMIT_V1.into(),
            ),
            ("content-type".into(), "application/json".into()),
            (
                "idempotency-key".into(),
                arkret_canonical::canonical_sha256(body).unwrap(),
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
    let mut request = TestClient::post(request_url);
    for (name, value) in parts.headers {
        request = request.add_header(
            salvo::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            value,
            true,
        );
    }
    let bytes = if tamper {
        let mut changed = body.clone();
        changed.requester_account_id = destination.pcr.history.account.clone();
        arkret_canonical::canonical_json_bytes(&changed).unwrap()
    } else {
        bytes
    };
    let mut response = request
        .add_header("signature-input", signature.signature_input_header, true)
        .add_header("signature", signature.signature_header, true)
        .body(bytes)
        .send(&service(destination.state.clone()))
        .await;
    (
        response.status_code.unwrap(),
        response.take_json().await.unwrap(),
    )
}

async fn configuration_admin_event(fixture: &Fixture, event: Event) {
    let body = json!(
        arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest::Event(
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
