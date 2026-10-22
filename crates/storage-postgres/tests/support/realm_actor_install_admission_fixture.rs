// Included inside realm_native_fixture. All writes use actual authenticated HTTP.
async fn install_admission_footprint(fixture: &Fixture) -> Value {
    use diesel::sql_types::Jsonb;
    use diesel_async::RunQueryDsl as _;
    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type=Jsonb)]
        value: Value,
    }
    let mut value = boxed_step(|| async { native_business_footprint(fixture).await }).await;
    let mut connection = fixture.pool.get().await.unwrap();
    for table in [
        "applet_installations",
        "applet_namespace_claims",
        "applet_authoring_units",
        "applet_registration_instances",
        "applet_registration_current_results",
        "idempotency_keys",
    ] {
        let row=diesel::sql_query(format!("SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb) AS value FROM {table} r"))
            .get_result::<Row>(&mut connection).await.unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert(table.into(), row.value);
    }
    value
}

fn install_admission_resign_package(package: &mut AppletPackage) {
    let method = package.proof.as_ref().unwrap().verification_method.clone();
    package
        .stamp_registration_epoch(&applet_registration_epoch_evidence(package))
        .unwrap();
    package.stamp_package_digest().unwrap();
    let did = arkret_identity::verification_method_did(method.as_str()).unwrap();
    package
        .sign(
            &Ed25519PayloadSigner::from_did_key_seed([13; 32], did, method.clone()),
            &method,
        )
        .unwrap();
}

fn install_admission_rebind_package(fixture: &Fixture, body: &mut AppletInstallRequestBody) {
    let package = &body.applet_package;
    let basis = &mut body.authoring_request_basis;
    basis.package_digest = package.package_digest.clone().unwrap();
    basis.registration_event = fixture.admin_event(
        EventKind::AppletRegistration,
        ScopeRef::realm(basis.effective_scope.realm_id().clone()),
        serde_json::to_value(
            package
                .to_registration(&applet_registration_epoch_evidence(package), serde_json::from_value(basis.registration_event.payload["expected_revision"].clone()).unwrap())
                .unwrap(),
        )
        .unwrap(),
    );
    for original in &mut basis.capability_grant_events {
        let mut payload: CapabilityGrantPayload =
            serde_json::from_value(json!(original.payload)).unwrap();
        for constraint in &mut payload.grant.constraints {
            if constraint.applet_id.as_ref() == Some(&package.applet_id) {
                constraint.registration_epoch = Some(package.registration_epoch.clone());
            }
        }
        *original = fixture.admin_event(
            EventKind::CapabilityGrant,
            basis.effective_scope.clone(),
            json!(payload),
        );
    }
}

async fn install_admission_repreview(fixture: &Fixture, body: &mut AppletInstallRequestBody) {
    let preview = AppletInstallPreviewRequestBody {
        applet_package: body.applet_package.clone(),
        authoring_request_basis: body.authoring_request_basis.clone(),
    };
    let (status, value) = boxed_step(|| async {
        fixture
            .admin_post(
                "/_arkret/self/applets/install/preview",
                arkret_wire::ServiceOperationId::SelfAppletInstallCommandPreviewV1.as_str(),
                &json!(preview),
                None,
            )
            .await
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "valid original signatures and recomputed plan, before independent installation consent: {value}"
    );
    let plan: AppletInstallPlan = serde_json::from_value(value["plan"].clone()).unwrap();
    body.plan_digest = plan.plan_digest;
}

pub(super) async fn prepare_expiring_install(
    factory: &AppletAuthoringFactory,
    applet: &AppletId,
    scope_label: &str,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> AppletInstallRequestBody {
    let expires_at = arkret_canonical::normalize_timestamp_canonical(expires_at);
    let unit = boxed_step(|| async { factory.prepare_install(applet, scope_label).await }).await;
    let coland_storage::AppletAdmissionRequest::Install(body) = unit.input.candidate.request else {
        panic!("actual install request required")
    };
    let mut body = *body;
    for original in &mut body.authoring_request_basis.capability_grant_events {
        let mut payload: CapabilityGrantPayload =
            serde_json::from_value(json!(original.payload)).unwrap();
        let mut temporal = GrantConstraint::new(
            arkret_models_collaboration::governance::grant_constraint::GrantConstraintKind::Temporal,
            arkret_models_collaboration::governance::grant_constraint::GrantConstraintEffect::Allow,
        );
        temporal.expires_at = Some(expires_at);
        payload.grant.constraints.push(temporal);
        *original = factory.fixture.admin_event(
            EventKind::CapabilityGrant,
            body.authoring_request_basis.effective_scope.clone(),
            json!(payload),
        );
    }
    // All accepted installation sources expire together. A separately granted
    // read/business parent must remain live in the caller's disclosure test.
    install_admission_repreview(&factory.fixture, &mut body).await;
    body
}

pub(super) async fn install_admission_policy(
    fixture: &Fixture,
    applet: &AppletId,
    service: &arkret_wire::DidCoreId,
    operation: &str,
) {
    let actor = ActorId::account(fixture.pcr.history.account.clone());
    let scope = ScopeRef::Realm {
        realm_id: fixture.realm.clone(),
    };
    let target = if operation == "install" {
        json!({"kind":"requester","actor_id":actor})
    } else {
        json!({"kind":"installation","applet_id":applet,"service_id":service,"effective_scope":scope})
    };
    let id = format!("ak:policy:{}", uuid::Uuid::now_v7());
    let event=fixture.admin_event(EventKind::PolicySet,scope,json!({"policy_id":id,"expected_revision":null,"value":{
        "schema":"ak.schema.policy.v1","id":id,"realm_id":fixture.realm,"policy_kind":"applet","default_effect":"allow","created_by":actor,
        "created_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now()),
        "rules":[{"rule_id":"native_admission_current_policy","kind":"applet","effect":"deny","applet_target":target,"applet_operations":[operation]}]}}));
    let request = arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest::Event(
        arkret_wire::EventAdmissionSubmission::new(event.clone()),
    );
    let (status, value) = boxed_step(|| async {
        fixture
            .admin_post(
                "/_arkret/self/events",
                arkret_wire::ServiceOperationId::SelfEventsCommandSubmitV1.as_str(),
                &json!(request),
                None,
            )
            .await
    })
    .await;
    assert_eq!(status, StatusCode::OK, "real PolicySet: {value}");
    assert_eq!(
        fixture
            .state
            .test_persistence()
            .authority_commits()
            .committed_event(&event.event_id)
            .await
            .unwrap()
            .unwrap()
            .event,
        event
    );
}

async fn station_excludes_applet_queries(fixture: &Fixture) {
    use arkret_wire::ServiceOperationId as Op;
    let client = native_http_client(std::time::Duration::from_secs(30));
    let base = fixture.state.config().public_base_url.trim_end_matches('/');
    let response = client.get(format!("{base}/_arkret/describe"))
        .header("Arkret-Operation", Op::ServerReadDescribeV1.as_str()).send().await.unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let describe: arkret::ServiceDescribe = response.json().await.unwrap();
    for (operation, path) in [
        (Op::EdgeAppletRealmReadResolveV1, "realms/known-portal"),
        (Op::EdgeAppletReadProtocolMetadataV1, "protocols/fixture"),
        (Op::EdgeAppletThirdPartyUsersReadListV1, "third_party/users?protocol=fixture&external_id=known"),
        (Op::EdgeAppletThirdPartyLocationsReadListV1, "third_party/locations?protocol=fixture&external_id=known"),
    ] {
        assert!(!describe.supports_operation(operation));
        let response = client.get(format!("{base}/_arkret/edge/applet/{path}"))
            .header("Arkret-Operation", operation.as_str()).send().await.unwrap();
        assert_eq!(response.status().as_u16(), 404, "Station cannot answer Applet lookup {operation:?}");
    }
}

pub(super) async fn run_install_admission(pool: PgPool) {
    let (fixture, _station) = boxed_step(|| async { network_fixture(pool).await }).await;
    let factory = AppletAuthoringFactory {
        fixture,
        packages: Default::default(),
        scopes: Default::default(),
    };
    for missing in ["profile", "approval", "policy", "enabled"] {
        let id = AppletId::new(format!("ak:applet:{}", uuid::Uuid::now_v7())).unwrap();
        let mut service = NativeService::new(&id, &factory.fixture.state.service_core_id());
        realm_actor_mls_fixture::enable(&mut service.package);
        factory
            .packages
            .lock()
            .await
            .insert(id.to_string(), service.package.clone());
        let unit =
            boxed_step(|| async { factory.prepare_install(&id, "native-e2ee-admission").await })
                .await;
        let coland_storage::AppletAdmissionRequest::Install(body) = unit.input.candidate.request
        else {
            panic!("actual install required")
        };
        let mut body = *body;
        match missing {
            "profile" => body
                .applet_package
                .claimed_profiles
                .retain(|p| p != arkret_wire::ProfileId::APPLET_E2EE_JOIN_V1),
            "enabled" => body.applet_package.e2ee_policy.enabled = false,
            "approval" => {
                body.authoring_request_basis
                    .approval_request
                    .e2ee_join_allowed = false
            }
            "policy" => {
                body.authoring_request_basis.e2ee_policy =
                    Some(serde_json::from_value(json!({})).unwrap())
            }
            _ => unreachable!(),
        }
        if matches!(missing, "profile" | "enabled") {
            install_admission_resign_package(&mut body.applet_package);
            install_admission_rebind_package(&factory.fixture, &mut body);
        }
        install_admission_repreview(&factory.fixture, &mut body).await;
        let before =
            boxed_step(|| async { install_admission_footprint(&factory.fixture).await }).await;
        let key = format!("e2ee-missing-{missing}");
        let (status, problem) = boxed_step(|| async {
            factory
                .fixture
                .admin_post(
                    "/_arkret/self/applets/install",
                    arkret_wire::ServiceOperationId::SelfAppletCommandInstallV1.as_str(),
                    &json!(body),
                    Some(&key),
                )
                .await
        })
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "missing independent E2EE {missing}: {problem}"
        );
        assert_eq!(
            problem["type"],
            "https://arkret.org/problems/applet_e2ee_join_unauthorized"
        );
        assert_eq!(
            boxed_step(|| async { install_admission_footprint(&factory.fixture).await }).await,
            before
        );
    }
    boxed_step(|| station_excludes_applet_queries(&factory.fixture)).await;
    boxed_step(|| async { install_admission_reproof_and_missing_creation(&factory).await }).await;
    boxed_step(|| install_admission_circle_claim_independence(&factory)).await;
    let id = AppletId::new(format!("ak:applet:{}", uuid::Uuid::now_v7())).unwrap();
    let mut service = NativeService::new(&id, &factory.fixture.state.service_core_id());
    realm_actor_mls_fixture::enable(&mut service.package);
    factory
        .packages
        .lock()
        .await
        .insert(id.to_string(), service.package.clone());
    let unit = boxed_step(|| async {
        factory
            .prepare_install(&id, "policy-after-real-preview")
            .await
    })
    .await;
    let coland_storage::AppletAdmissionRequest::Install(body) = unit.input.candidate.request else {
        panic!("actual install required")
    };
    install_admission_policy(&factory.fixture, &id, &service.package.service_id, "install").await;
    let before = boxed_step(|| async { install_admission_footprint(&factory.fixture).await }).await;
    let (status, problem) = boxed_step(|| async {
        factory
            .fixture
            .admin_post(
                "/_arkret/self/applets/install",
                arkret_wire::ServiceOperationId::SelfAppletCommandInstallV1.as_str(),
                &json!(body),
                Some("policy-after-real-preview"),
            )
            .await
    })
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "current policy must override real earlier preview: {problem}"
    );
    assert_eq!(
        problem["type"],
        "https://arkret.org/problems/capability_denied"
    );
    assert_eq!(
        boxed_step(|| async { install_admission_footprint(&factory.fixture).await }).await,
        before
    );
}

async fn install_admission_exact_material_binding(
    fixture: &Fixture,
    package: &AppletPackage,
    scope: &ScopeRef,
    install: &AppletInstallOutcome,
) -> arkret_models_collaboration::applet_installation_authority::AppletAuthorityMaterialOutcome {
    use arkret_models_collaboration::applet_installation_authority::{
        AppletAuthorityMaterialOutcome, AppletAuthorityMaterialRequestBody,
        AppletInstallationCurrentBinding,
    };
    let request = AppletAuthorityMaterialRequestBody {
        effective_scope: scope.clone(),
        grant_ids: install.capability_grant_refs.clone(),
    };
    let path = format!(
        "/_arkret/self/applets/{}/authority/material",
        install.applet_id
    );
    let footprint = boxed_step(|| install_admission_footprint(fixture)).await;
    let read_key = uuid::Uuid::now_v7().to_string();
    let (status, value) = boxed_step(|| async {
        fixture
            .service_post(
                package,
                &path,
                arkret_wire::ServiceOperationId::SelfAppletAuthorityReadMaterialV1.as_str(),
                &json!(request),
                &read_key,
            )
            .await
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "exact installation material: {value}"
    );
    let material: AppletAuthorityMaterialOutcome = serde_json::from_value(value).unwrap();
    material
        .validate_for_request(&install.applet_id, &request)
        .unwrap();
    let original = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&install.registration_event_ref)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(material.registration.event.scope_ref, ScopeRef::realm(scope.realm_id().clone()));
    assert_eq!(json!(material.registration.event), json!(original.event));
    assert_eq!(json!(material.registration.commit), json!(original.commit));
    let AppletInstallationCurrentBinding::Active {
        registration_ref,
        registration_epoch,
        service_id,
    } = &material.current_binding
    else {
        panic!("accepted exact installation must remain active");
    };
    assert_eq!(&registration_ref.event_id, &install.registration_event_ref);
    assert_eq!(registration_ref.commit_id, original.commit.commit_id);
    assert_eq!(registration_ref.stream_ref, original.commit.stream_ref);
    assert_eq!(
        registration_ref.stream_position,
        original.commit.stream_position
    );
    assert_eq!(registration_epoch, &install.registration_epoch);
    assert_eq!(json!(service_id), original.event.payload["service_id"]);
    assert_eq!(
        boxed_step(|| install_admission_footprint(fixture)).await,
        footprint
    );
    material
}

async fn install_admission_reproof_and_missing_creation(factory: &AppletAuthoringFactory) {
    // A proof refresh changes neither security epoch nor an already accepted
    // Realm installation. Each Circle retains its accepted Realm registration original.
    let id = AppletId::new(format!("ak:applet:{}", uuid::Uuid::now_v7())).unwrap();
    let mut service = NativeService::new(&id, &factory.fixture.state.service_core_id());
    realm_actor_mls_fixture::enable(&mut service.package);
    factory
        .packages
        .lock()
        .await
        .insert(id.to_string(), service.package.clone());
    let first =
        boxed_step(|| async { factory.prepare_install(&id, "reproof-first-realm").await }).await;
    let first_outcome =
        boxed_step(|| async { commit_install_http(&factory.fixture, &first).await }).await;
    let coland_storage::AppletAdmissionRequest::Install(first_body) = first.input.candidate.request
    else {
        unreachable!()
    };
    let first_registration = first_body
        .authoring_request_basis
        .registration_event
        .clone();
    let provision = first_body
        .authoring_request_basis
        .capability_grant_events
        .iter()
        .find(|event| {
            event.payload["grant"]["actions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|action| action == "ak.applet.ghost.provision")
        })
        .unwrap();
    let (candidate, signer) = authority_admission_candidate(
        &service.package,
        &factory.fixture,
        &first_registration.event_id,
        &arkret_wire::GrantId::from_event_id(&provision.event_id),
        false,
    );
    let pending = arkret::author_realm_actor_create(
        candidate.clone(),
        arkret_canonical::DigestSuite::Sha256,
        candidate.control_signature.created_at,
        &signer,
    )
    .unwrap();
    let first_material = boxed_step(|| {
        install_admission_exact_material_binding(
            &factory.fixture,
            &service.package,
            &first_body.authoring_request_basis.effective_scope,
            &first_outcome,
        )
    })
    .await;
    let prior_proof = service.package.proof.clone();
    let prior_epoch = service.package.registration_epoch.clone();
    // Fresh proof is real and time-distinct, but the security transcript is unchanged.
    tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    install_admission_resign_package(&mut service.package);
    assert_eq!(service.package.registration_epoch, prior_epoch);
    assert_ne!(service.package.proof, prior_proof);
    factory
        .packages
        .lock()
        .await
        .insert(id.to_string(), service.package.clone());
    let second = boxed_step(|| async {
        factory
            .prepare_install(&id, "reproof-circle:scope-right")
            .await
    })
    .await;
    assert_ne!(
        second.effective_scope,
        first_body.authoring_request_basis.effective_scope
    );
    let second_outcome =
        boxed_step(|| async { commit_install_http(&factory.fixture, &second).await }).await;
    assert_ne!(
        first_outcome.registration_event_ref,
        second_outcome.registration_event_ref
    );
    assert_eq!(
        first_outcome.registration_epoch,
        second_outcome.registration_epoch
    );
    let refreshed_material = boxed_step(|| {
        install_admission_exact_material_binding(
            &factory.fixture,
            &service.package,
            &first_body.authoring_request_basis.effective_scope,
            &first_outcome,
        )
    })
    .await;
    assert_eq!(
        json!(refreshed_material.registration),
        json!(first_material.registration)
    );
    assert_eq!(
        json!(refreshed_material.grant_events),
        json!(first_material.grant_events)
    );
    boxed_step(|| {
        install_admission_exact_material_binding(
            &factory.fixture,
            &service.package,
            &second.effective_scope,
            &second_outcome,
        )
    })
    .await;
    let request = arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest::Event(
        arkret_wire::EventAdmissionSubmission::new(pending.clone()),
    );
    let (status, result) = boxed_step(|| async {
        factory
            .fixture
            .service_post(
                &first_body.applet_package,
                "/_arkret/self/events",
                arkret_wire::ServiceOperationId::SelfEventsCommandSubmitV1.as_str(),
                &json!(request),
                "pending-before-cross-scope-reproof",
            )
            .await
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "original creation source survives same-security cross-scope reproof: {result}"
    );
    let accepted = factory
        .fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&pending.event_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(accepted.event, pending);
    assert_eq!(
        factory
            .fixture
            .state
            .test_persistence()
            .authority_commits()
            .committed_event(&first_registration.event_id)
            .await
            .unwrap()
            .unwrap()
            .event,
        first_registration
    );
    // A separate, real installation grants business and Bot operations but
    // intentionally withholds Ghost provision. It cannot create a fresh Ghost.
    let id = AppletId::new(format!("ak:applet:{}", uuid::Uuid::now_v7())).unwrap();
    let service = NativeService::new(&id, &factory.fixture.state.service_core_id());
    factory
        .packages
        .lock()
        .await
        .insert(id.to_string(), service.package.clone());
    let unit = boxed_step(|| async {
        factory
            .prepare_install(&id, "no-ghost-creation-action")
            .await
    })
    .await;
    let coland_storage::AppletAdmissionRequest::Install(body) = unit.input.candidate.request else {
        unreachable!()
    };
    let mut body = *body;
    body.authoring_request_basis
        .capability_grant_events
        .retain(|event| {
            !event.payload["grant"]["actions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|action| action == "ak.applet.ghost.provision")
        });
    body.authoring_request_basis
        .approval_request
        .approve_actions
        .retain(|action| action != "ak.applet.ghost.provision");
    install_admission_repreview(&factory.fixture, &mut body).await;
    let (status, installed) = boxed_step(|| async {
        factory
            .fixture
            .admin_post(
                "/_arkret/self/applets/install",
                arkret_wire::ServiceOperationId::SelfAppletCommandInstallV1.as_str(),
                &json!(body),
                Some("actual-install-no-ghost"),
            )
            .await
    })
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "actual partial installation without Ghost creation: {installed}"
    );
    let wrong_source = &body.authoring_request_basis.capability_grant_events[0];
    let (candidate, signer) = authority_admission_candidate(
        &service.package,
        &factory.fixture,
        &body.authoring_request_basis.registration_event.event_id,
        &arkret_wire::GrantId::from_event_id(&wrong_source.event_id),
        false,
    );
    let original = arkret::author_realm_actor_create(
        candidate.clone(),
        arkret_canonical::DigestSuite::Sha256,
        candidate.control_signature.created_at,
        &signer,
    )
    .unwrap();
    let request = arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest::Event(
        arkret_wire::EventAdmissionSubmission::new(original.clone()),
    );
    let before = boxed_step(|| async { install_admission_footprint(&factory.fixture).await }).await;
    let (status, problem) = boxed_step(|| async {
        factory
            .fixture
            .service_post(
                &service.package,
                "/_arkret/self/events",
                arkret_wire::ServiceOperationId::SelfEventsCommandSubmitV1.as_str(),
                &json!(request),
                "no-ghost-grant-fresh-create",
            )
            .await
    })
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "real fresh creation cannot borrow a non-provision grant: {problem}"
    );
    assert_eq!(
        problem["type"],
        "https://arkret.org/problems/capability_denied"
    );
    assert_eq!(
        boxed_step(|| async { install_admission_footprint(&factory.fixture).await }).await,
        before
    );
    assert!(
        factory
            .fixture
            .state
            .test_persistence()
            .authority_commits()
            .committed_event(&original.event_id)
            .await
            .unwrap()
            .is_none()
    );
}

pub(super) async fn policy_blocks_fresh_native_join(fixture: &Fixture, package: &AppletPackage) {
    let scope = ScopeRef::Realm {
        realm_id: fixture.realm.clone(),
    };
    let installation = PgAppletStore {
        pool: fixture.pool.clone(),
    }
    .get(
        package.applet_id.as_str(),
        package.service_id.as_str(),
        &coland_storage::applet_effective_scope_key(&scope).unwrap(),
    )
    .await
    .unwrap()
    .unwrap();
    let registration: Event =
        serde_json::from_value(installation["registration_event"].clone()).unwrap();
    let grants: Vec<Event> =
        serde_json::from_value(installation["capability_grant_events"].clone()).unwrap();
    let creation = grants
        .iter()
        .find(|e| {
            e.payload["grant"]["actions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|a| a == "ak.applet.ghost.provision")
        })
        .unwrap();
    let join = grants
        .iter()
        .find(|e| {
            e.payload["grant"]["actions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|a| a == "ak.applet.join")
        })
        .unwrap();
    let (candidate, signer) = authority_admission_candidate(
        package,
        fixture,
        &registration.event_id,
        &arkret_wire::GrantId::from_event_id(&creation.event_id),
        false,
    );
    let event = arkret::author_realm_actor_create(
        candidate.clone(),
        arkret_canonical::DigestSuite::Sha256,
        candidate.control_signature.created_at,
        &signer,
    )
    .unwrap();
    let request = arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest::Event(
        arkret_wire::EventAdmissionSubmission::new(event.clone()),
    );
    let (status, value) = boxed_step(|| async {
        fixture
            .service_post(
                package,
                "/_arkret/self/events",
                arkret_wire::ServiceOperationId::SelfEventsCommandSubmitV1.as_str(),
                &json!(request),
                "policy-real-fresh-subject",
            )
            .await
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "real new subject before policy change: {value}"
    );
    let original = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&event.event_id)
        .await
        .unwrap()
        .unwrap();
    let device = boxed_step(|| async {
        authorize_device_with_actions(
            fixture,
            &candidate,
            &original.commit,
            92,
            &["ak.applet.join", "ak.event.read", "ak.mls.commit"],
        )
        .await
    })
    .await;
    let authority = fixture
        .state
        .test_persistence()
        .device_revocations()
        .applet_managed_device_authority(&candidate.actor_id, &device, chrono::Utc::now())
        .await
        .unwrap()
        .unwrap();
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let draft = arkret_event_draft::TypedEventDraft::<arkret_wire::event_spec::MemberState>::new(
        scope.clone(),
        candidate.actor_id.clone(),
        serde_json::from_value(json!({"member_id":candidate.actor_id,"membership":"join"}))
            .unwrap(),
    )
    .unwrap()
    .with_applet_id(package.applet_id.clone())
    .with_authorization_ref(arkret_wire::GrantId::from_event_id(&join.event_id).into())
    .into_intent(at)
    .unwrap();
    let mut authored = draft
        .author_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .unwrap();
    let method = DidUrl::new(format!("{}#{}", authority.native_did, device)).unwrap();
    arkret_signatures::sign_event(
        &mut authored,
        &Ed25519PayloadSigner::new(
            SigningKey::from_bytes(&[92; 32]),
            authority.native_did.clone(),
            method,
        ),
        arkret_signatures::SignEventOptions::new().with_created_at(at),
    )
    .unwrap();
    let join_event = authored.into_event();
    let request = arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest::Event(
        arkret_wire::EventAdmissionSubmission::new(join_event.clone()),
    );
    // A distinct accepted identity still joins after both provision sources
    // close. The original subject below is already created and authorized too.
    boxed_step(|| admission_native_endpoint(fixture, package, 93, true)).await;
    install_admission_policy(fixture, &package.applet_id, &package.service_id, "join").await;
    let metadata = AppletManagedDeviceMetadata {
        actor_id: candidate.actor_id,
        device_id: device,
        authorization_event_id: authority.authorization_ref.event_id.clone(),
        applet_id: package.applet_id.clone(),
        effective_scope: scope,
        nonce: arkret_canonical::base64url_encode(rand::random::<[u8; 32]>()),
    };
    let key = arkret_canonical::ed25519_pubkey_to_did_key_multibase(&authority.public_key);
    let native_method = DidUrl::new(format!("did:key:{key}#{key}")).unwrap();
    let before = boxed_step(|| async { install_admission_footprint(fixture).await }).await;
    let native_seed = [92; 32];
    let (status, problem) = boxed_step(|| async {
        managed_device_post(
            fixture,
            &metadata,
            &native_method,
            "/_arkret/self/events",
            arkret_wire::ServiceOperationId::SelfEventsCommandSubmitV1,
            &json!(request),
            &native_seed,
        )
        .await
    })
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "fresh native join after original explicit E2EE consent loses current Policy: {problem}"
    );
    assert_eq!(
        problem["type"],
        "https://arkret.org/problems/capability_denied"
    );
    assert_eq!(
        boxed_step(|| async { install_admission_footprint(fixture).await }).await,
        before
    );
    assert!(
        fixture
            .state
            .test_persistence()
            .authority_commits()
            .committed_event(&join_event.event_id)
            .await
            .unwrap()
            .is_none()
    );
}

pub(super) async fn admission_native_endpoint(
    fixture: &Fixture,
    package: &AppletPackage,
    key_seed: u8,
    close_creation: bool,
) -> (
    RealmActorCreatePayload,
    coland_storage::AppletManagedDeviceAuthority,
) {
    let scope = ScopeRef::Realm {
        realm_id: fixture.realm.clone(),
    };
    let installation = PgAppletStore {
        pool: fixture.pool.clone(),
    }
    .get(
        package.applet_id.as_str(),
        package.service_id.as_str(),
        &coland_storage::applet_effective_scope_key(&scope).unwrap(),
    )
    .await
    .unwrap()
    .unwrap();
    let registration: Event =
        serde_json::from_value(installation["registration_event"].clone()).unwrap();
    let grants: Vec<Event> =
        serde_json::from_value(installation["capability_grant_events"].clone()).unwrap();
    let source = |action: &str| {
        grants
            .iter()
            .find(|event| {
                event.payload["grant"]["actions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|a| a == action)
            })
            .unwrap()
    };
    let (candidate, signer) = authority_admission_candidate(
        package,
        fixture,
        &registration.event_id,
        &arkret_wire::GrantId::from_event_id(&source("ak.applet.ghost.provision").event_id),
        false,
    );
    let create = arkret::author_realm_actor_create(
        candidate.clone(),
        arkret_canonical::DigestSuite::Sha256,
        candidate.control_signature.created_at,
        &signer,
    )
    .unwrap();
    let request = arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest::Event(
        arkret_wire::EventAdmissionSubmission::new(create.clone()),
    );
    let (status, value) = boxed_step(|| async {
        fixture
            .service_post(
                package,
                "/_arkret/self/events",
                arkret_wire::ServiceOperationId::SelfEventsCommandSubmitV1.as_str(),
                &json!(request),
                &format!("native-endpoint-create-{}", uuid::Uuid::now_v7()),
            )
            .await
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "real independent target creation: {value}"
    );
    let accepted = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&create.event_id)
        .await
        .unwrap()
        .unwrap();
    let device = boxed_step(|| {
        authorize_obligation_device(
            fixture,
            &candidate,
            &accepted.commit,
            key_seed,
            arkret_canonical::normalize_timestamp_canonical(
                chrono::Utc::now() + chrono::Duration::minutes(15),
            ),
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
        .unwrap();
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let intent = arkret_event_draft::TypedEventDraft::<arkret_wire::event_spec::MemberState>::new(
        scope.clone(),
        candidate.actor_id.clone(),
        serde_json::from_value(json!({"member_id":candidate.actor_id,"membership":"join"}))
            .unwrap(),
    )
    .unwrap()
    .with_applet_id(package.applet_id.clone())
    .with_authorization_ref(
        arkret_wire::GrantId::from_event_id(&source("ak.applet.join").event_id).into(),
    )
    .into_intent(at)
    .unwrap();
    let mut authored = intent
        .author_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .unwrap();
    arkret_signatures::sign_event(
        &mut authored,
        &Ed25519PayloadSigner::new(
            SigningKey::from_bytes(&[key_seed; 32]),
            authority.native_did.clone(),
            DidUrl::new(format!("{}#{}", authority.native_did, device)).unwrap(),
        ),
        arkret_signatures::SignEventOptions::new().with_created_at(at),
    )
    .unwrap();
    let request = arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest::Event(
        arkret_wire::EventAdmissionSubmission::new(authored.into_event()),
    );
    let mut metadata = AppletManagedDeviceMetadata {
        actor_id: candidate.actor_id.clone(),
        device_id: device,
        authorization_event_id: authority.authorization_ref.event_id.clone(),
        applet_id: package.applet_id.clone(),
        effective_scope: scope,
        nonce: arkret_canonical::base64url_encode(rand::random::<[u8; 32]>()),
    };
    let key = arkret_canonical::ed25519_pubkey_to_did_key_multibase(&authority.public_key);
    let method = DidUrl::new(format!("did:key:{key}#{key}")).unwrap();
    let seed = [key_seed; 32];
    if close_creation {
        for original in grants.iter().filter(|event| {
            event.payload["grant"]["actions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|action| {
                    action == "ak.applet.bot.provision" || action == "ak.applet.ghost.provision"
                })
        }) {
            let grant = arkret_wire::GrantId::from_event_id(&original.event_id);
            let currents = fixture
                .state
                .test_persistence()
                .capability_grant_current_results()
                .snapshot_for_realm(&fixture.realm)
                .await
                .unwrap();
            let current = currents.iter().find(|row| row.grant_id == grant).unwrap();
            let event = fixture.admin_event(EventKind::CapabilityRevoke, ScopeRef::Realm { realm_id: fixture.realm.clone() },
                json!({"grant_id":grant,"expected_revision":current.revision,"reason":"stop fresh identity creation only"}));
            let body =
                arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest::Event(
                    arkret_wire::EventAdmissionSubmission::new(event),
                );
            let (status, value) = boxed_step(|| async {
                fixture
                    .admin_post(
                        "/_arkret/self/events",
                        arkret_wire::ServiceOperationId::SelfEventsCommandSubmitV1.as_str(),
                        &json!(body),
                        None,
                    )
                    .await
            })
            .await;
            assert_eq!(status, StatusCode::OK, "real provision withdrawal: {value}");
        }
        let still_current = fixture
            .state
            .test_persistence()
            .device_revocations()
            .applet_managed_device_authority(
                &candidate.actor_id,
                &authority.device_id,
                chrono::Utc::now(),
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(still_current.authorization_ref, authority.authorization_ref);
    } else {
        // A mutable installation mirror cannot substitute for the exact
        // immutable accepted request. Restore the real original before asserts.
        use diesel_async::RunQueryDsl as _;
        #[derive(diesel::QueryableByName)]
        struct OriginalInstall {
            #[diesel(sql_type = diesel::sql_types::Jsonb)]
            body: Value,
        }
        let digest = installation["install_body_digest"].as_str().unwrap();
        let mut connection = fixture.pool.get().await.unwrap();
        let original = diesel::sql_query("SELECT request_body AS body FROM applet_authoring_units WHERE canonical_request_hash=$1")
            .bind::<diesel::sql_types::Text,_>(digest).get_result::<OriginalInstall>(&mut connection).await.unwrap();
        let changed = diesel::sql_query("UPDATE applet_authoring_units SET request_body=jsonb_set(request_body,'{authoring_request_basis,e2ee_policy,mls_join_allowed}','false'::jsonb) WHERE canonical_request_hash=$1")
            .bind::<diesel::sql_types::Text,_>(digest).execute(&mut connection).await.unwrap();
        drop(connection);
        let before = boxed_step(|| install_admission_footprint(fixture)).await;
        let (status, problem) = boxed_step(|| async {
            managed_device_post(
                fixture,
                &metadata,
                &method,
                "/_arkret/self/events",
                arkret_wire::ServiceOperationId::SelfEventsCommandSubmitV1,
                &json!(request),
                &seed,
            )
            .await
        })
        .await;
        let after = boxed_step(|| install_admission_footprint(fixture)).await;
        let mut connection = fixture.pool.get().await.unwrap();
        let restored = diesel::sql_query(
            "UPDATE applet_authoring_units SET request_body=$2 WHERE canonical_request_hash=$1",
        )
        .bind::<diesel::sql_types::Text, _>(digest)
        .bind::<diesel::sql_types::Jsonb, _>(&original.body)
        .execute(&mut connection)
        .await
        .unwrap();
        drop(connection);
        assert_eq!(changed, 1);
        assert_eq!(restored, 1);
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "retained mirror must not bypass changed accepted consent original: {problem}"
        );
        assert_eq!(
            problem["type"],
            "https://arkret.org/problems/applet_e2ee_join_unauthorized"
        );
        assert_eq!(after, before);
    }
    metadata.nonce = arkret_canonical::base64url_encode(rand::random::<[u8; 32]>());
    let (status, value) = boxed_step(|| async {
        managed_device_post(
            fixture,
            &metadata,
            &method,
            "/_arkret/self/events",
            arkret_wire::ServiceOperationId::SelfEventsCommandSubmitV1,
            &json!(request),
            &seed,
        )
        .await
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "real independent target native Realm membership: {value}"
    );
    (candidate, authority)
}

pub(super) async fn admission_pause_target(fixture: &Fixture, candidate: &RealmActorCreatePayload) {
    let actor = &candidate.actor_id;
    let status_ref = actor_current_ref(
        fixture,
        actor,
        json!({"kind":"realm_actor_status","actor_id":actor,"gate":"owner"}),
    )
    .await;
    let control_ref = actor_current_ref(
        fixture,
        actor,
        json!({"kind":"realm_actor_control","actor_id":actor}),
    )
    .await;
    let event = owner_status_event(
        fixture,
        candidate,
        &status_ref,
        &candidate.control_method_kid,
        &[33; 32],
        RealmActorStatusSetPayloadState::Paused,
    );
    let metadata = RealmActorControlHttpMetadata {
        actor_id: actor.clone(),
        control_ref,
        nonce: arkret_canonical::base64url_encode(rand::random::<[u8; 32]>()),
    };
    let request = arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest::Event(
        arkret_wire::EventAdmissionSubmission::new(event.clone()),
    );
    let (status, value) = boxed_step(|| async {
        control_post(
            fixture,
            &metadata,
            &candidate.control_method_kid,
            "/_arkret/self/events",
            arkret_wire::ServiceOperationId::SelfEventsCommandSubmitV1,
            &json!(request),
        )
        .await
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "actual current target pause after signed claim: {value}"
    );
    assert!(
        fixture
            .state
            .test_persistence()
            .authority_commits()
            .committed_event(&event.event_id)
            .await
            .unwrap()
            .is_some()
    );
}

async fn install_admission_circle_claim_independence(factory: &AppletAuthoringFactory) {
    let fixture = &factory.fixture;
    let id = AppletId::new(format!("ak:applet:{}", uuid::Uuid::now_v7())).unwrap();
    let mut native = NativeService::new(&id, &fixture.state.service_core_id());
    realm_actor_mls_fixture::enable(&mut native.package);
    factory
        .packages
        .lock()
        .await
        .insert(id.to_string(), native.package.clone());
    let realm_unit = boxed_step(|| factory.prepare_install(&id, "claim-scope-parent-realm")).await;
    let _realm_outcome = boxed_step(|| commit_install_http(fixture, &realm_unit)).await;
    let circle_unit =
        boxed_step(|| factory.prepare_install(&id, "claim-scope-independent:scope-right")).await;
    let circle = circle_unit.effective_scope.clone();
    let _circle_outcome = boxed_step(|| commit_install_http(fixture, &circle_unit)).await;
    let coland_storage::AppletAdmissionRequest::Install(realm_body) =
        realm_unit.input.candidate.request
    else {
        unreachable!()
    };
    let coland_storage::AppletAdmissionRequest::Install(circle_body) =
        circle_unit.input.candidate.request
    else {
        unreachable!()
    };
    let source = |body: &AppletInstallRequestBody, action: &str| {
        body.authoring_request_basis
            .capability_grant_events
            .iter()
            .find(|e| {
                e.payload["grant"]["actions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|a| a == action)
            })
            .unwrap()
            .event_id
            .clone()
    };
    let (candidate, signer) = authority_admission_candidate(
        &native.package,
        fixture,
        &realm_body
            .authoring_request_basis
            .registration_event
            .event_id,
        &arkret_wire::GrantId::from_event_id(&source(&realm_body, "ak.applet.ghost.provision")),
        false,
    );
    let create = authority_admission_create(&candidate, &signer);
    let (status, value) =
        boxed_step(|| authority_admission_send(fixture, &native.package, &create)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "real dual-scope requester creation: {value}"
    );
    let event = match &create {
        arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest::Event(e) => {
            &e.event
        }
        _ => unreachable!(),
    };
    let original = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&event.event_id)
        .await
        .unwrap()
        .unwrap();
    let realm = ScopeRef::Realm {
        realm_id: fixture.realm.clone(),
    };
    let mut entries = vec![
        json!({"effective_scope":realm,"actions":["ak.applet.join","ak.circle.member.add","ak.event.read","ak.mls.commit","ak.mls.genesis"]}),
        json!({"effective_scope":circle,"actions":["ak.applet.join","ak.circle.member.add","ak.event.read","ak.mls.commit","ak.mls.genesis"]}),
    ];
    entries.sort_by_key(|r| arkret_canonical::canonical_json_bytes(&r["effective_scope"]).unwrap());
    let scopes: arkret_models_collaboration::events_payloads::AppletManagedDeviceScopes =
        serde_json::from_value(json!(entries)).unwrap();
    let device = boxed_step(|| {
        authorize_native_device_with_scopes(
            fixture,
            &candidate,
            &original.commit,
            98,
            &scopes,
            None,
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
        .unwrap();
    for scope in [&realm, &circle] {
        let (kind, payload, join_grant) = if scope == &realm {
            boxed_step(|| {
                realm_actor_mls_fixture::business_parent(
                    fixture,
                    &native.package,
                    &candidate.actor_id,
                    scope,
                )
            })
            .await;
            (
                EventKind::MemberState,
                json!({"member_id":candidate.actor_id,"membership":"join"}),
                arkret_wire::GrantId::from_event_id(&source(&realm_body, "ak.applet.join")),
            )
        } else {
            let ScopeRef::Circle { circle_id, .. } = scope else {
                unreachable!()
            };
            assert_eq!(scope, &circle_body.authoring_request_basis.effective_scope);
            // Circle membership is ordinary native business authority. Its
            // subject must be this actor, rather than the installation's
            // Service subject used by subject-only Realm join above.
            let child = boxed_step(|| {
                realm_actor_mls_fixture::business_grant_at_scope(
                    fixture,
                    &native.package,
                    &candidate.actor_id,
                    scope,
                )
            })
            .await;
            let parent = ordinary_realm::parent_membership_revision(
                &fixture.pool,
                &fixture.realm,
                &candidate.actor_id,
            )
            .await;
            (
                EventKind::CircleMemberState,
                json!({"circle_id":circle_id,"member_id":candidate.actor_id,"membership":"join","parent_membership_revision":parent}),
                child,
            )
        };
        let event = realm_actor_mls_fixture::admission_native_scope_event(
            &native.package,
            &candidate,
            &authority,
            scope,
            kind,
            payload,
            &join_grant,
            &[98; 32],
        );
        let request =
            arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest::Event(
                arkret_wire::EventAdmissionSubmission::new(event),
            );
        let mut response = boxed_step(|| {
            native_boundary_response(
                fixture,
                &authority,
                scope,
                &[98; 32],
                "/_arkret/self/events",
                arkret_wire::ServiceOperationId::SelfEventsCommandSubmitV1,
                Some(json!(request)),
            )
        })
        .await;
        let status = response.status_code;
        let value: Value = response.take_json().await.unwrap();
        assert_eq!(
            status,
            Some(StatusCode::OK),
            "genuine dual-scope native membership: {value}"
        );
    }
    let realm_refs = realm_body
        .authoring_request_basis
        .capability_grant_events
        .iter()
        .map(|e| arkret_wire::GrantId::from_event_id(&e.event_id))
        .collect::<Vec<_>>();
    boxed_step(|| {
        realm_actor_mls_fixture::admission_circle_claim_after_realm_fence(
            fixture,
            &native.package,
            &candidate,
            &authority,
            &circle,
            &realm_refs,
        )
    })
    .await;
}
