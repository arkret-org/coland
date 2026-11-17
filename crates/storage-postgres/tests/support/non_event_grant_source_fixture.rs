// Included in realm_native_fixture. Installation and grant authority come from
// the original signed aggregate and real authenticated HTTP admissions.
async fn non_event_grant_source_footprint(fixture: &Fixture) -> Value {
    use diesel::sql_types::Jsonb;
    use diesel_async::RunQueryDsl as _;
    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type = Jsonb)]
        value: Value,
    }
    let mut footprint = boxed_step(|| install_admission_footprint(fixture)).await;
    let mut conn = fixture.pool.get().await.unwrap();
    for table in [
        "capability_grant_current_states",
        "applet_grant_registration_sources",
        "current_state_heads",
        "event_federation_outbox",
        "federation_outbox",
        "event_approval_private_audit",
    ] {
        let row = diesel::sql_query(format!(
            "SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb) AS value FROM {table} r"
        ))
        .get_result::<Row>(&mut conn)
        .await
        .unwrap();
        footprint
            .as_object_mut()
            .unwrap()
            .insert(table.into(), row.value);
    }
    footprint
}

fn non_event_grant_original(
    fixture: &Fixture,
    installation: &AppletFormalCommitUnit,
    action: &str,
    resources: Vec<arkret_wire::WireResourceSelector>,
) -> Event {
    let coland_storage::AppletAdmissionRequest::Install(body) = &installation.input.request;
    let original = body
        .authoring_request_basis
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
    let mut payload: CapabilityGrantPayload =
        serde_json::from_value(json!(original.payload)).unwrap();
    payload.grant.resources = resources;
    payload.grant.issued_at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    fixture.admin_event(
        EventKind::CapabilityGrant,
        ScopeRef::realm(fixture.realm.clone()),
        json!(payload),
    )
}

fn non_event_exact_resource(scope: &ScopeRef) -> arkret_wire::WireResourceSelector {
    match scope {
        ScopeRef::Realm { realm_id } => arkret_wire::WireResourceSelector::realm(realm_id.clone()),
        ScopeRef::Circle {
            realm_id,
            circle_id,
        } => arkret_wire::WireResourceSelector::circle(realm_id.clone(), circle_id.clone()),
        _ => unreachable!("the real installation fixture admits Realm or Circle scope"),
    }
}

async fn non_event_grant_send(fixture: &Fixture, event: &Event, key: &str) -> (StatusCode, Value) {
    let request =
        arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequestBody::Event(
            arkret_wire::EventAdmissionSubmission::new(event.clone()),
        );
    let body = json!(request);
    boxed_step(|| {
        fixture.admin_post_network(
            "/_arkret/self/events",
            arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
            &body,
            key,
        )
    })
    .await
}

fn non_event_grant_accepted_response(
    event: &Event,
    value: Value,
    expected_status: arkret_wire::AuthorityCommitStatus,
) -> arkret_wire::RealmCommit {
    use arkret_models_collaboration::authority_commit::{
        SelfAuthoritySubmitRequestBody, SelfAuthoritySubmitResponseBody,
    };
    let request = SelfAuthoritySubmitRequestBody::Event(
        arkret_wire::EventAdmissionSubmission::new(event.clone()),
    );
    let response: SelfAuthoritySubmitResponseBody = serde_json::from_value(value).unwrap();
    response.validate_for_request(&request).unwrap();
    let SelfAuthoritySubmitResponseBody::Ordinary(
        arkret_wire::AuthoritySubmitResponseBody::Accepted { status, commit },
    ) = response
    else {
        panic!("a real ordinary grant must retain its accepted Commit");
    };
    assert_eq!(status, expected_status);
    commit
}

async fn non_event_grant_source_id(fixture: &Fixture, event: &Event) -> Option<String> {
    use diesel::sql_types::{Nullable, Text};
    use diesel_async::RunQueryDsl as _;
    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type = Nullable<Text>)]
        install_id: Option<String>,
    }
    let mut conn = fixture.pool.get().await.unwrap();
    diesel::sql_query("SELECT install_id FROM applet_grant_registration_sources WHERE realm_id=$1 AND grant_id=$2")
        .bind::<Text, _>(fixture.realm.as_str())
        .bind::<Text, _>(arkret_wire::GrantId::from_event_id(&event.event_id).as_str())
        .get_result::<Row>(&mut conn).await.unwrap().install_id
}

async fn non_event_grant_refused(fixture: &Fixture, event: &Event, label: &str) {
    let before = boxed_step(|| non_event_grant_source_footprint(fixture)).await;
    let (status, problem) = boxed_step(|| non_event_grant_send(fixture, event, label)).await;
    assert_eq!(status, StatusCode::CONFLICT, "{label}: {problem}");
    assert_eq!(
        problem["type"], "https://arkret.org/problems/failed_precondition",
        "{label}: {problem}"
    );
    assert_eq!(
        problem["reason_code"],
        arkret_wire::ReasonCode::GRANT_EXCEEDS_ISSUER_AUTHORITY,
        "{label}: {problem}"
    );
    assert_eq!(
        boxed_step(|| non_event_grant_source_footprint(fixture)).await,
        before,
        "{label}: refusal must roll back the whole unit"
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
}

async fn non_event_grant_revoke_installation(fixture: &Fixture, unit: &AppletFormalCommitUnit) {
    let coland_storage::AppletAdmissionRequest::Install(body) = &unit.input.request;
    let mode = arkret_wire::AppletRevokeMode::RevokeAll;
    let reason = arkret_wire::ReasonCode::from_wire("applet_revoked");
    let path = format!(
        "/_arkret/self/applets/{}/revoke",
        body.applet_package.applet_id
    );
    let preview_path = format!("{path}/preview");
    let preview_request = AppletRevokePreviewRequestBody {
        service_id: body.applet_package.service_id.clone(),
        effective_scope: unit.effective_scope.clone(),
        reason_code: reason.clone(),
        revoke_mode: mode,
    };
    let preview_body = json!(preview_request);
    let (status, value) = boxed_step(|| {
        fixture.admin_post(
            &preview_path,
            arkret_wire::ServiceOperationId::SELF_APPLET_REVOKE_COMMAND_PREVIEW_V1,
            &preview_body,
            None,
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "real installation revoke preview: {value}"
    );
    let preview: AppletRevokePreviewResponseBody = serde_json::from_value(value).unwrap();
    assert!(
        preview.revoke_plan.membership_removals.is_empty(),
        "this fixture creates no managed actor or member"
    );
    let request = AppletRevokeRequestBody {
        service_id: body.applet_package.service_id.clone(),
        revoke_plan_digest: Hash::new(arkret_canonical::canonical_sha256(&preview.revoke_plan).unwrap()).unwrap(),
        effective_scope: unit.effective_scope.clone(), reason_code: reason, revoke_mode: mode,
        capability_revoke_events: preview.revoke_plan.capability_revocations.iter().map(|intent| {
            arkret_wire::EventAdmissionSubmission::new(fixture.admin_event(EventKind::CapabilityRevoke,
                unit.effective_scope.clone(), json!({"grant_id":intent.grant_id,"expected_commit_id":intent.expected_commit_id,"reason":intent.reason_code})))
        }).collect(),
        membership_state_events: vec![],
    };
    let key = format!("non-event-scope-revoke-{}", uuid::Uuid::now_v7());
    let request_body = json!(request);
    let (status, value) = boxed_step(|| {
        fixture.admin_post(
            &path,
            arkret_wire::ServiceOperationId::SELF_APPLET_COMMAND_REVOKE_V1,
            &request_body,
            Some(&key),
        )
    })
    .await;
    assert_eq!(status, StatusCode::OK, "real installation revoke: {value}");
    let outcome: AppletRevokeResponseBody = serde_json::from_value(value).unwrap();
    assert_eq!(outcome.status, AppletRevokeSagaStatus::Complete);
    assert!(outcome.rejections.is_empty());
    let record = fixture
        .state
        .test_persistence()
        .applets()
        .get(
            body.applet_package.applet_id.as_str(),
            body.applet_package.service_id.as_str(),
            &coland_storage::applet_effective_scope_key(&unit.effective_scope).unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record["status"], "revoked");
    assert!(record["revoked_at"].is_string());
}

pub(super) async fn run_non_event_grant_sources(pool: PgPool) {
    let (fixture, _station) = boxed_step(|| network_fixture(pool)).await;
    let factory = AppletAuthoringFactory {
        fixture,
        packages: Default::default(),
        scopes: Default::default(),
    };
    let fixture = &factory.fixture;
    let applet = AppletId::new(format!("ak:applet:{}", uuid::Uuid::now_v7())).unwrap();
    let first = boxed_step(|| async {
        Box::new(
            factory
                .prepare_install(&applet, "non-event-first:scope-right")
                .await,
        )
    })
    .await;
    let first_outcome = boxed_step(|| commit_install_http(fixture, &first)).await;
    let first_scope = first.effective_scope.clone();
    let missing_scope = boxed_step(|| fixture.new_circle_scope()).await;
    assert_ne!(missing_scope, first_scope);
    let first_registration = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&first_outcome.registration_event_ref)
        .await
        .unwrap()
        .unwrap();
    let actions = ["ak.applet.bot.provision", "ak.applet.ghost.provision"];

    for action in actions {
        let event = non_event_grant_original(
            fixture,
            &first,
            action,
            vec![non_event_exact_resource(&first_scope)],
        );
        let key = format!("exact-live-source-{action}");
        let (status, value) = boxed_step(|| non_event_grant_send(fixture, &event, &key)).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "exact active installation source: {value}"
        );
        assert_eq!(
            boxed_step(|| non_event_grant_source_id(fixture, &event))
                .await
                .as_deref(),
            Some(first_outcome.install_id.as_str())
        );
        assert_eq!(
            fixture
                .state
                .test_persistence()
                .authority_commits()
                .committed_event(&event.event_id)
                .await
                .unwrap()
                .unwrap()
                .commit,
            non_event_grant_accepted_response(
                &event,
                value,
                arkret_wire::AuthorityCommitStatus::Committed
            )
        );
        for (label, resources) in [
            (
                "missing-exact-installation",
                vec![non_event_exact_resource(&missing_scope)],
            ),
            (
                "realm-is-not-circle-installation",
                vec![arkret_wire::WireResourceSelector::realm(
                    fixture.realm.clone(),
                )],
            ),
            (
                "multiple-effective-scopes",
                vec![
                    non_event_exact_resource(&first_scope),
                    non_event_exact_resource(&missing_scope),
                ],
            ),
        ] {
            let event = non_event_grant_original(fixture, &first, action, resources);
            let key = format!("{label}-{action}");
            boxed_step(|| non_event_grant_refused(fixture, &event, &key)).await;
        }
    }

    // Unrelated generic authority still has registration-only provenance.
    let generic = boxed_step(|| factory.registration_only_parent(&first, &missing_scope)).await;
    let generic_event = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&EventId::from_token_bytes(generic.token_bytes()).unwrap())
        .await
        .unwrap()
        .unwrap()
        .event;
    assert_eq!(
        boxed_step(|| non_event_grant_source_id(fixture, &generic_event)).await,
        None
    );

    let coland_storage::AppletAdmissionRequest::Install(first_body) = &first.input.request;
    let mut changed_package = first_body.applet_package.clone();
    changed_package
        .requested_scopes
        .push("ak.applet.bridge_error".into());
    changed_package.requested_scopes.sort();
    install_admission_resign_package(&mut changed_package);
    assert_ne!(
        changed_package.registration_epoch,
        first_body.applet_package.registration_epoch
    );
    factory
        .packages
        .lock()
        .await
        .insert(applet.to_string(), changed_package);
    let second = boxed_step(|| async {
        Box::new(
            factory
                .prepare_install(&applet, "non-event-second:scope-right")
                .await,
        )
    })
    .await;
    let second_outcome = boxed_step(|| commit_install_http(fixture, &second)).await;
    assert_ne!(second.effective_scope, first_scope);
    assert_ne!(
        second_outcome.registration_epoch,
        first_outcome.registration_epoch
    );
    let mut retained = Vec::new();
    for action in actions {
        let old_epoch = non_event_grant_original(
            fixture,
            &first,
            action,
            vec![non_event_exact_resource(&first_scope)],
        );
        let key = format!("old-registration-epoch-{action}");
        boxed_step(|| non_event_grant_refused(fixture, &old_epoch, &key)).await;
        let old_installation = non_event_grant_original(
            fixture,
            &second,
            action,
            vec![non_event_exact_resource(&first_scope)],
        );
        let key = format!("old-installation-instance-{action}");
        boxed_step(|| non_event_grant_refused(fixture, &old_installation, &key)).await;
        let event = non_event_grant_original(
            fixture,
            &second,
            action,
            vec![non_event_exact_resource(&second.effective_scope)],
        );
        let key = format!("new-active-source-{action}");
        let (status, value) = boxed_step(|| non_event_grant_send(fixture, &event, &key)).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "new exact installation source: {value}"
        );
        assert_eq!(
            boxed_step(|| non_event_grant_source_id(fixture, &event))
                .await
                .as_deref(),
            Some(second_outcome.install_id.as_str())
        );
        let commit = non_event_grant_accepted_response(
            &event,
            value,
            arkret_wire::AuthorityCommitStatus::Committed,
        );
        assert_eq!(
            fixture
                .state
                .test_persistence()
                .authority_commits()
                .committed_event(&event.event_id)
                .await
                .unwrap()
                .unwrap()
                .commit,
            commit
        );
        retained.push((event, key, commit));
    }
    boxed_step(|| non_event_grant_revoke_installation(fixture, &second)).await;
    for (accepted, key, original_commit) in retained {
        let before = boxed_step(|| non_event_grant_source_footprint(fixture)).await;
        let (status, value) = boxed_step(|| non_event_grant_send(fixture, &accepted, &key)).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "exact accepted replay after revoke: {value}"
        );
        assert_eq!(
            non_event_grant_accepted_response(
                &accepted,
                value,
                arkret_wire::AuthorityCommitStatus::Duplicate
            ),
            original_commit
        );
        let original = fixture
            .state
            .test_persistence()
            .authority_commits()
            .committed_event(&accepted.event_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(original.event, accepted);
        assert_eq!(original.commit, original_commit);
        assert_eq!(
            boxed_step(|| non_event_grant_source_footprint(fixture)).await,
            before
        );
        let action = accepted.payload["grant"]["actions"][0].as_str().unwrap();
        let new_original = non_event_grant_original(
            fixture,
            &second,
            action,
            vec![non_event_exact_resource(&second.effective_scope)],
        );
        assert_ne!(new_original.event_id, accepted.event_id);
        let key = format!("revoked-installation-{action}");
        boxed_step(|| non_event_grant_refused(fixture, &new_original, &key)).await;
    }
    assert_eq!(
        fixture
            .state
            .test_persistence()
            .authority_commits()
            .committed_event(&first_outcome.registration_event_ref)
            .await
            .unwrap()
            .unwrap(),
        first_registration,
        "a new security epoch and revoke must preserve the accepted registration original"
    );
}
