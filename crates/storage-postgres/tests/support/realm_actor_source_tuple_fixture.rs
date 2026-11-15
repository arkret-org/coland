// Included in realm_native_fixture: real native registration, identity and
// signed HTTP admissions. This is not a model of the source tuple evaluator.
async fn source_tuple_footprint(fixture: &Fixture) -> Value {
    use diesel::sql_types::Jsonb;
    use diesel_async::RunQueryDsl as _;
    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type=Jsonb)]
        value: Value,
    }
    let mut footprint = boxed_step(|| native_business_footprint(fixture)).await;
    let mut conn = fixture.pool.get().await.unwrap();
    for table in [
        "applet_installations",
        "applet_grant_registration_sources",
        "capability_grant_current_states",
        "applet_transactions",
        "idempotency_keys",
    ] {
        let row=diesel::sql_query(format!("SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb) AS value FROM {table} r"))
            .get_result::<Row>(&mut conn).await.unwrap();
        footprint
            .as_object_mut()
            .unwrap()
            .insert(table.into(), row.value);
    }
    footprint
}

pub(super) async fn continuous_registration_sources(pool: PgPool) {
    use arkret_models_collaboration::governance::grant_constraint::{
        GrantConstraintKind, GrantConstraintSubkind,
    };
    use arkret_wire::GrantId;
    let (fixture, _governor) = boxed_step(|| network_fixture(pool.clone())).await;
    let factory = AppletAuthoringFactory {
        fixture,
        packages: Default::default(),
        scopes: Default::default(),
    };
    let applet = AppletId::new(format!("ak:applet:{}", uuid::Uuid::now_v7())).unwrap();
    let mut native = NativeService::new(&applet, &factory.fixture.state.service_core_id());
    realm_actor_mls_fixture::enable(&mut native.package);
    native
        .package
        .requested_scopes
        .push("ak.applet.bridge_error".into());
    native.package.requested_scopes.sort();
    install_admission_resign_package(&mut native.package);
    let package = &native.package;
    factory
        .packages
        .lock()
        .await
        .insert(applet.to_string(), package.clone());
    let first = boxed_step(|| factory.prepare_install(&applet, "continuous-source-realm")).await;
    let first_outcome = boxed_step(|| commit_install_http(&factory.fixture, &first)).await;
    let scope = first.effective_scope.clone();
    let fixture = &factory.fixture;
    let service = ActorId::service(package.service_id.clone());
    let root = ActorId::account(fixture.pcr.history.account.clone());
    let p1 =
        boxed_step(|| realm_actor_mls_fixture::business_parent(fixture, package, &root, &scope))
            .await;
    let signer = Ed25519PayloadSigner::new(
        applet_service_signing_key(&package.webhook_signature_policy.key_ref),
        applet_service_did(package),
        package.webhook_signature_policy.key_ref.clone(),
    );
    let grant_for = |unit: &AppletFormalCommitUnit, action: &str| {
        let coland_storage::AppletAdmissionRequest::Install(body) = &unit.input.candidate.request;
        let event = body
            .authoring_request_basis
            .capability_grant_events
            .iter()
            .find(|e| {
                e.payload["grant"]["actions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|a| a == action)
            })
            .unwrap();
        GrantId::from_event_id(&event.event_id)
    };
    let bridge = |registration: &EventId, grant: &GrantId| {
        realm_actor_mls_fixture::signed_event(
            package,
            service.clone(),
            scope.clone(),
            EventKind::AppletBridgeError,
            json!({"applet_id":applet,"realm_id":fixture.realm,"failed_transaction_ref":registration,
            "error_class":"external_network","error_code":"external_unavailable",
            "retriable":true,"visibility_scope":"realm_members"}),
            Some(grant),
            &signer,
        )
    };
    let bridge1_grant = grant_for(&first, "ak.applet.bridge_error");
    let e1 = bridge(&first_outcome.registration_event_ref, &bridge1_grant);
    let (status, value) =
        boxed_step(|| realm_actor_mls_fixture::grant_boundary_send(fixture, package, &e1)).await;
    assert_eq!(status, StatusCode::OK, "R1 original: {value}");
    let e1_outcome =
        boxed_step(|| realm_actor_mls_fixture::grant_boundary_assert_accepted(fixture, &e1, value))
            .await;

    let second = boxed_step(|| factory.prepare_install(&applet, "continuous-source-realm")).await;
    let second_outcome = boxed_step(|| commit_install_http(fixture, &second)).await;
    assert_eq!(first_outcome.install_id, second_outcome.install_id);
    assert_eq!(
        first_outcome.registration_epoch,
        second_outcome.registration_epoch
    );
    assert_ne!(
        first_outcome.registration_event_ref, second_outcome.registration_event_ref,
        "a real safe reaffirmation changes current revision without replacing the instance"
    );
    let bridge2_grant = grant_for(&second, "ak.applet.bridge_error");
    let e2 = bridge(&second_outcome.registration_event_ref, &bridge2_grant);
    let (status, value) =
        boxed_step(|| realm_actor_mls_fixture::grant_boundary_send(fixture, package, &e2)).await;
    assert_eq!(status, StatusCode::OK, "R2 original: {value}");
    let e2_outcome =
        boxed_step(|| realm_actor_mls_fixture::grant_boundary_assert_accepted(fixture, &e2, value))
            .await;

    let provision = grant_for(&second, "ak.applet.bot.provision");
    let (candidate, actor_signer) = authority_admission_candidate(
        package,
        fixture,
        &second_outcome.registration_event_ref,
        &provision,
        true,
        &native.archive,
    );
    let request = authority_admission_create(&candidate, &actor_signer);
    let (status, value) = boxed_step(|| authority_admission_send(fixture, package, &request)).await;
    assert_eq!(status, StatusCode::OK, "genuine Bot source: {value}");
    let p2 = boxed_step(|| {
        realm_actor_mls_fixture::business_parent(fixture, package, &candidate.actor_id, &scope)
    })
    .await;
    let material_path = format!("/_arkret/self/applets/{applet}/authority/material");
    for (parent, registration) in [
        (&p1, &first_outcome.registration_event_ref),
        (&p2, &second_outcome.registration_event_ref),
    ] {
        let request=arkret_models_collaboration::applet_installation_authority::AppletAuthorityMaterialRequestBody {
            effective_scope:scope.clone(),grant_ids:vec![parent.clone()],
        };
        let (status, value) = boxed_step(|| async {
            fixture
                .service_post(
                    package,
                    &material_path,
                    arkret_wire::ServiceOperationId::SELF_APPLET_AUTHORITY_READ_MATERIAL_V1,
                    &json!(request),
                    &format!("continuous-original-{parent}"),
                )
                .await
        })
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "each exact original remains independently readable: {value}"
        );
        let material:arkret_models_collaboration::applet_installation_authority::AppletAuthorityMaterialResponseBody=serde_json::from_value(value).unwrap();
        material.validate_for_request(&applet, &request).unwrap();
        assert_eq!(&material.registration.event.event_id, registration);
    }
    let material_request=json!(arkret_models_collaboration::applet_installation_authority::AppletAuthorityMaterialRequestBody {
        effective_scope:scope.clone(),grant_ids:vec![p1.clone(),p2.clone()],
    });
    let (status, problem) = boxed_step(|| {
        fixture.service_post(
            package,
            &material_path,
            arkret_wire::ServiceOperationId::SELF_APPLET_AUTHORITY_READ_MATERIAL_V1,
            &material_request,
            "continuous-two-originals-one-material",
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "one material carrier cannot replace R1/R2 originals: {problem}"
    );
    let original = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&EventId::from_token_bytes(p1.token_bytes()).unwrap())
        .await
        .unwrap()
        .unwrap();
    let mut child: CapabilityGrantCreateBody =
        serde_json::from_value(original.event.payload["grant"].clone()).unwrap();
    child.issuer_id = service.clone();
    child.subject = CapabilitySubject::Actor(candidate.actor_id.clone());
    child.issuer_authority_refs = vec![
        IssuerAuthorityRef::Grant {
            grant_id: p1.clone(),
        },
        IssuerAuthorityRef::Grant {
            grant_id: p2.clone(),
        },
    ];
    for constraint in &mut child.constraints {
        if constraint.constraint_subkind == Some(GrantConstraintSubkind::AppletAuthority) {
            constraint.executed_by = Some(candidate.actor_id.clone());
        } else if constraint.constraint_kind == GrantConstraintKind::AuthorityControl
            && constraint.constraint_subkind.is_none()
        {
            constraint.allowed_managed_actor_roles.clear();
            constraint.max_authority_depth = Some(0);
            constraint.authority_regrant_allowed = Some(false);
        }
    }
    child.issued_at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let child_event = realm_actor_mls_fixture::signed_event(
        package,
        service.clone(),
        scope.clone(),
        EventKind::CapabilityGrant,
        json!(CapabilityGrantPayload {
            grant: child.clone()
        }),
        Some(&p1),
        &signer,
    );
    let (status, value) =
        boxed_step(|| realm_actor_mls_fixture::grant_boundary_send(fixture, package, &child_event))
            .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "two contributing R1/R2 parents at one epoch/I: {value}"
    );
    boxed_step(|| {
        realm_actor_mls_fixture::grant_boundary_assert_accepted(fixture, &child_event, value)
    })
    .await;
    let accepted_child = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&child_event.event_id)
        .await
        .unwrap()
        .unwrap();
    let fact = fixture
        .state
        .test_persistence()
        .authority_commits()
        .producer_signer_fact(&child_event, &accepted_child.commit)
        .await
        .unwrap()
        .unwrap();
    let accepted_child = arkret_wire::CommittedEventFullView {
        event: accepted_child.event,
        commit: accepted_child.commit,
    };
    let arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact::Service(
        current_signer,
    ) = &fact
    else {
        panic!("actual terminal child retains its native Service producer fact");
    };
    assert_eq!(
        current_signer.key.registration_ref.event_id,
        second_outcome.registration_event_ref
    );
    assert_eq!(
        current_signer.key.authorization_ref.event_id,
        EventId::from_token_bytes(p1.token_bytes()).unwrap()
    );
    fact.validate_commit_binding(
        &accepted_child,
        child_event.realm_id.digest_suite_code().digest_suite(),
    )
    .unwrap();
    arkret_identity::account_device_signer_evidence::verify_historical_producer_event_signature(
        &child_event,
        &fact,
        child_event.realm_id.digest_suite_code().digest_suite(),
    )
    .unwrap();
    #[derive(diesel::QueryableByName)]
    struct Frozen {
        #[diesel(sql_type=diesel::sql_types::Text)]
        grant_id: String,
        #[diesel(sql_type=diesel::sql_types::Text)]
        registration_event_ref: String,
        #[diesel(sql_type=diesel::sql_types::Nullable<diesel::sql_types::Text>)]
        install_id: Option<String>,
    }
    use diesel_async::RunQueryDsl as _;
    let mut conn = fixture.pool.get().await.unwrap();
    let sources=diesel::sql_query("SELECT grant_id,registration_event_ref,install_id FROM applet_grant_registration_sources WHERE realm_id=$1 AND (grant_id=$2 OR grant_id=$3)")
        .bind::<diesel::sql_types::Text,_>(fixture.realm.as_str()).bind::<diesel::sql_types::Text,_>(p1.as_str())
        .bind::<diesel::sql_types::Text,_>(p2.as_str()).load::<Frozen>(&mut conn).await.unwrap();
    assert_eq!(sources.len(), 2);
    for row in sources {
        assert_eq!(
            row.install_id.as_deref(),
            Some(first_outcome.install_id.as_str())
        );
        let expected = if row.grant_id == p1.as_str() {
            &first_outcome.registration_event_ref
        } else {
            assert_eq!(row.grant_id, p2.as_str());
            &second_outcome.registration_event_ref
        };
        assert_eq!(row.registration_event_ref, expected.as_str());
    }
    drop(conn);

    // The exact originals may be mixed under a new delivery even after the
    // first business parent is revoked. No original is re-signed/re-authorized.
    let rows = fixture
        .state
        .test_persistence()
        .capability_grant_current_states()
        .snapshot_for_realm(&fixture.realm)
        .await
        .unwrap();
    let row = rows.iter().find(|r| r.grant_id == bridge1_grant).unwrap();
    let close = fixture.admin_event(
        EventKind::CapabilityRevoke,
        scope.clone(),
        json!({"grant_id":bridge1_grant,"expected_commit_id":row.revision.commit_id}),
    );
    accepted_admin_domain_event(fixture, close).await;
    let before = boxed_step(|| native_business_footprint(fixture)).await;
    let transaction = AppletEventTransactionRequestBody {
        applet_id: applet.clone(),
        source_id: package.service_id.clone(),
        events: vec![e1, e2],
        committed_events: vec![],
        signals: vec![],
    };
    let body = json!(transaction);
    let (status, value) = boxed_step(|| {
        fixture.service_post(
            package,
            "/_arkret/edge/applet/transactions",
            arkret_wire::ServiceOperationId::EDGE_APPLET_COMMAND_TRANSACTION_V1,
            &body,
            "continuous-R1-R2-mixed-originals",
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "same epoch/I mixed original recovery: {value}"
    );
    let mixed: AppletTransactionResponseBody = serde_json::from_value(value).unwrap();
    let expected = e1_outcome
        .committed_event_refs()
        .iter()
        .chain(e2_outcome.committed_event_refs())
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(mixed.committed_event_refs(), expected);
    assert_eq!(mixed.status(), AppletTransactionStatus::Accepted);
    assert_eq!(
        boxed_step(|| native_business_footprint(fixture)).await,
        before,
        "new delivery receipt may be retained, but no Event/Commit/current/quota is repeated"
    );

    let keeper =
        boxed_step(|| factory.prepare_install(&applet, "continuous-source-keeper:scope-right"))
            .await;
    boxed_step(|| commit_install_http(fixture, &keeper)).await;
    let store = PgAppletStore { pool: pool.clone() };
    let key = coland_storage::applet_effective_scope_key(&scope).unwrap();
    let record = store
        .get(applet.as_str(), package.service_id.as_str(), &key)
        .await
        .unwrap()
        .unwrap();
    let mut closed = record.clone();
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    closed["status"] = json!("revoked");
    closed["revoked_at"] = json!(arkret_canonical::format_timestamp_canonical(at));
    let fence = store
        .fence_installation(
            applet.as_str(),
            package.service_id.as_str(),
            &key,
            fixture.state.service_id(),
            &record,
            closed,
            at,
        )
        .await
        .unwrap();
    assert!(fence.updated);
    assert!(!fence.globally_fenced);
    let third = boxed_step(|| factory.prepare_install(&applet, "continuous-source-realm")).await;
    let third_outcome = boxed_step(|| commit_install_http(fixture, &third)).await;
    assert_eq!(
        third_outcome.registration_epoch,
        first_outcome.registration_epoch
    );
    assert_ne!(third_outcome.install_id, first_outcome.install_id);
    let p3 = boxed_step(|| {
        realm_actor_mls_fixture::business_parent(fixture, package, &candidate.actor_id, &scope)
    })
    .await;
    child.issuer_authority_refs = vec![
        IssuerAuthorityRef::Grant {
            grant_id: p2.clone(),
        },
        IssuerAuthorityRef::Grant { grant_id: p3 },
    ];
    child.issued_at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let refused = realm_actor_mls_fixture::signed_event(
        package,
        service,
        scope,
        EventKind::CapabilityGrant,
        json!(CapabilityGrantPayload { grant: child }),
        Some(&p2),
        &signer,
    );
    let before = boxed_step(|| source_tuple_footprint(fixture)).await;
    let (status, problem) =
        boxed_step(|| realm_actor_mls_fixture::grant_boundary_send(fixture, package, &refused))
            .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "same epoch cannot join old/new true instances: {problem}"
    );
    assert_eq!(
        problem["type"],
        "https://arkret.org/problems/failed_precondition"
    );
    assert_eq!(
        boxed_step(|| source_tuple_footprint(fixture)).await,
        before,
        "instance/source failure precedes replay reservation and all effects"
    );
    assert!(
        fixture
            .state
            .test_persistence()
            .authority_commits()
            .committed_event(&refused.event_id)
            .await
            .unwrap()
            .is_none()
    );
}
