// Included in realm_actor_mls_fixture; current RealmActor authority only.

async fn grant_boundary_send(
    fixture: &Fixture,
    package: &AppletPackage,
    event: &Event,
) -> (StatusCode, Value) {
    fixture
        .service_post(
            package,
            "/_arkret/edge/applet/transactions",
            ServiceOperationId::EdgeAppletCommandTransactionV1.as_str(),
            &json!(AppletEventTransactionRequestBody {
                applet_id: package.applet_id.clone(),
                source_id: package.service_id.clone(),
                events: vec![event.clone()],
                committed_events: vec![],
                signals: vec![],
            }),
            &format!("grant-boundary-{}", uuid::Uuid::now_v7()),
        )
        .await
}

async fn grant_boundary_assert_rejected(
    fixture: &Fixture,
    event: &Event,
    status: StatusCode,
    value: Value,
    reason: &str,
) {
    assert_eq!(
        status,
        StatusCode::OK,
        "per-Event business refusal: {value}"
    );
    assert!(value.get("committed_event_refs").is_none());
    let outcome: AppletTransactionOutcome = serde_json::from_value(value).unwrap();
    assert_eq!(
        outcome,
        AppletTransactionOutcome::Rejected {
            rejections: vec![arkret_models_integration::AppletEventRejection {
                event_id: Some(event.event_id.clone()),
                reason_code: arkret_wire::ReasonCode::from_wire(reason),
                retry_after_ms: None,
            }],
            retry_after_ms: None,
        },
    );
    assert!(
        fixture
            .state
            .test_persistence()
            .authority_commits()
            .committed_event(&event.event_id)
            .await
            .unwrap()
            .is_none(),
        "a rejected Event must not acquire a Commit"
    );
}

async fn grant_boundary_assert_accepted(
    fixture: &Fixture,
    event: &Event,
    value: Value,
) -> AppletTransactionOutcome {
    let outcome: AppletTransactionOutcome = serde_json::from_value(value).unwrap();
    let original = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&event.event_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&original.event, event);
    assert_eq!(
        outcome,
        AppletTransactionOutcome::Accepted {
            committed_event_refs: vec![arkret_wire::CommittedEventRef {
                event_id: event.event_id.clone(),
                commit_id: original.commit.commit_id,
                stream_ref: original.commit.stream_ref,
                stream_position: original.commit.stream_position,
            }],
            rejections: Vec::new(),
            retry_after_ms: None,
        },
        "acceptance must disclose exactly the original Event and covering Commit"
    );
    outcome
}

async fn grant_boundary_historical_source(
    fixture: &Fixture,
    package: &AppletPackage,
    event: &Event,
    registration: &EventId,
) -> arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact {
    use arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact;
    let store = fixture.state.test_persistence();
    let original = store
        .authority_commits()
        .committed_event(&event.event_id)
        .await
        .unwrap()
        .unwrap();
    let fact = store
        .authority_commits()
        .producer_signer_fact(event, &original.commit)
        .await
        .unwrap()
        .unwrap();
    let HistoricalProducerSignerFact::Service(source) = &fact else {
        panic!("BridgeError must retain an actual Service producer fact");
    };
    assert_eq!(source.actor, event.actor_id);
    assert_eq!(source.key.applet_id, package.applet_id);
    assert_eq!(source.key.registration_epoch, package.registration_epoch);
    assert_eq!(&source.key.registration_ref.event_id, registration);
    assert_eq!(source.key.effective_scope, event.scope_ref);
    let suite = event.realm_id.digest_suite_code().digest_suite();
    fact.validate_commit_binding(
        &arkret_wire::CommittedEventFullView {
            event: event.clone(),
            commit: original.commit.clone(),
        },
        suite,
    )
    .unwrap();
    arkret_identity::account_device_signer_evidence::verify_historical_producer_event_signature(
        event, &fact, suite,
    )
    .unwrap();
    let selector = arkret_models_identity::SignerKeyQuerySelector::HistoricalEvent {
        sender: arkret_models_identity::HistoricalSignerKeyQuerySender::Service {
            actor: source.actor.clone(),
            verification_method: source.verification_method.clone(),
            committed_event_ref: arkret_wire::CommittedEventRef {
                event_id: event.event_id.clone(),
                commit_id: original.commit.commit_id,
                stream_ref: original.commit.stream_ref,
                stream_position: original.commit.stream_position,
            },
        },
    };
    let expected = store
        .authority_commits()
        .historical_producer_signer_key(&fixture.realm, &selector)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(expected.service_key(), Some(&source.key));
    let query = arkret_models_identity::SignerKeysQueryRequestBody {
        request_id: arkret_wire::RequestId::new(format!("ak:request:{}", uuid::Uuid::now_v7()))
            .unwrap(),
        realm_id: fixture.realm.clone(),
        recipient_account_id: Some(fixture.pcr.history.account.clone()),
        recipient_actor_id: None,
        queries: vec![selector],
    };
    let (status, value) = fixture
        .admin_post(
            "/_arkret/self/signer-keys/query",
            ServiceOperationId::SelfSignerKeysReadResolveV1.as_str(),
            &json!(query),
            None,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "historical Service signer source: {value}"
    );
    let result: arkret_models_identity::SignerKeysQueryOutcome =
        serde_json::from_value(value).unwrap();
    assert_eq!(result.results, vec![expected]);
    fact
}

pub(super) async fn grant_authority_boundaries(
    fixture: &Fixture,
    package: &AppletPackage,
    actor: &ActorId,
    registration: &EventId,
    bridge_grant: &GrantId,
) {
    let child = boxed_step(|| business_grant(fixture, package, actor)).await;
    let rows = fixture
        .state
        .test_persistence()
        .capability_grant_current_results()
        .snapshot_for_realm(&fixture.realm)
        .await
        .unwrap();
    let child_current = rows.iter().find(|row| row.grant_id == child).unwrap();
    let [IssuerAuthorityRef::Grant { grant_id: parent }] =
        child_current.value.issuer_authority_refs.as_slice()
    else {
        panic!("terminal child must retain its exact Service parent");
    };
    let parent = parent.clone();
    let child_revision = child_current.revision.clone();
    let source = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&EventId::from_token_bytes(child.token_bytes()).unwrap())
        .await
        .unwrap()
        .unwrap();
    let mut wrong: CapabilityGrantCreateBody =
        serde_json::from_value(source.event.payload["grant"].clone()).unwrap();
    wrong.issuer_id = ActorId::account(fixture.pcr.history.account.clone());
    wrong.issuer_authority_refs = vec![IssuerAuthorityRef::RealmRoot {
        realm_id: fixture.realm.clone(),
        authority_event_ref: fixture.authority_event_ref.clone().unwrap(),
        authority_generation: 0,
    }];
    for constraint in &mut wrong.constraints {
        if constraint.constraint_subkind == Some(GrantConstraintSubkind::AppletAuthority) {
            constraint.executed_by = Some(ActorId::service(package.service_id.clone()));
        }
    }
    wrong.issued_at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let event = fixture.admin_event(
        EventKind::CapabilityGrant,
        ScopeRef::Realm {
            realm_id: fixture.realm.clone(),
        },
        json!(CapabilityGrantPayload { grant: wrong }),
    );
    let before = boxed_step(|| obligation_mls_footprint(fixture)).await;
    let (status, problem) = fixture
        .admin_post(
            "/_arkret/self/events",
            ServiceOperationId::SelfEventsCommandSubmitV1.as_str(),
            &json!(SelfAuthoritySubmitRequest::Event(
                arkret_wire::EventAdmissionSubmission::new(event)
            )),
            None,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "wrong current managed issuer/source: {problem}"
    );
    assert_eq!(
        problem["type"],
        "https://arkret.org/problems/failed_precondition"
    );
    assert_eq!(
        boxed_step(|| obligation_mls_footprint(fixture)).await,
        before
    );

    let signer = Ed25519PayloadSigner::new(
        applet_service_signing_key(&package.webhook_auth.key_ref),
        applet_service_did(package),
        package.webhook_auth.key_ref.clone(),
    );
    let service = ActorId::service(package.service_id.clone());
    let scope = ScopeRef::Realm {
        realm_id: fixture.realm.clone(),
    };
    let relinquish = signed_event(
        package,
        service.clone(),
        scope.clone(),
        EventKind::CapabilityRelinquish,
        json!({"grant_id":child,"expected_revision":child_revision,"reason":"subject_request"}),
        Some(&parent),
        &signer,
    );
    let before = boxed_step(|| obligation_mls_footprint(fixture)).await;
    let (status, problem) = boxed_step(|| grant_boundary_send(fixture, package, &relinquish)).await;
    boxed_step(|| {
        grant_boundary_assert_rejected(
            fixture,
            &relinquish,
            status,
            problem,
            arkret_wire::ReasonCode::GRANT_RELINQUISH_NOT_SUBJECT,
        )
    })
    .await;
    assert_eq!(
        boxed_step(|| obligation_mls_footprint(fixture)).await,
        before
    );

    boxed_step(|| obligation_close_grant(fixture, &parent)).await;
    let revoke = signed_event(
        package,
        service.clone(),
        scope.clone(),
        EventKind::CapabilityRevoke,
        json!({"grant_id":child,"expected_revision":child_revision,"reason":"issuer_request"}),
        Some(&parent),
        &signer,
    );
    let (status, value) = boxed_step(|| grant_boundary_send(fixture, package, &revoke)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "original issuer cleanup after parent revocation: {value}"
    );
    let accepted_revoke =
        boxed_step(|| grant_boundary_assert_accepted(fixture, &revoke, value)).await;
    let rows = fixture
        .state
        .test_persistence()
        .capability_grant_current_results()
        .snapshot_for_realm(&fixture.realm)
        .await
        .unwrap();
    for id in [&parent, &child] {
        assert_eq!(
            rows.iter().find(|row| &row.grant_id == id).unwrap().status,
            coland_storage::CapabilityGrantCurrentStatus::Revoked
        );
    }
    let before = boxed_step(|| obligation_mls_footprint(fixture)).await;
    let (status, replay) = boxed_step(|| grant_boundary_send(fixture, package, &revoke)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "exact issuer cleanup retry: {replay}"
    );
    let replay: AppletTransactionOutcome = serde_json::from_value(replay).unwrap();
    assert_eq!(
        replay, accepted_revoke,
        "exact retry must recover the original Commit refs"
    );
    assert_eq!(
        boxed_step(|| obligation_mls_footprint(fixture)).await,
        before
    );
    let stale = signed_event(
        package,
        service.clone(),
        scope.clone(),
        EventKind::CapabilityRevoke,
        json!({"grant_id":child,"expected_revision":child_revision,"reason":"new original with stale revision"}),
        Some(&parent),
        &signer,
    );
    let (status, problem) = boxed_step(|| grant_boundary_send(fixture, package, &stale)).await;
    boxed_step(|| {
        grant_boundary_assert_rejected(
            fixture,
            &stale,
            status,
            problem,
            arkret_wire::ErrorCode::CAS_CONFLICT,
        )
    })
    .await;
    assert_eq!(
        boxed_step(|| obligation_mls_footprint(fixture)).await,
        before
    );

    let payload = json!({"applet_id":package.applet_id,"realm_id":fixture.realm,
        "failed_transaction_ref":registration,"error_class":"external_network",
        "error_code":"external_unavailable","retriable":true,"visibility_scope":"realm_members"});
    let mut wrong_applet = payload.clone();
    wrong_applet["applet_id"] = json!(format!("ak:applet:{}", uuid::Uuid::now_v7()));
    for event in [
        signed_event(
            package,
            service.clone(),
            scope.clone(),
            EventKind::AppletBridgeError,
            payload.clone(),
            Some(&child),
            &signer,
        ),
        signed_event(
            package,
            service.clone(),
            scope.clone(),
            EventKind::AppletBridgeError,
            wrong_applet,
            Some(bridge_grant),
            &signer,
        ),
    ] {
        let before = boxed_step(|| obligation_mls_footprint(fixture)).await;
        let (status, problem) = boxed_step(|| grant_boundary_send(fixture, package, &event)).await;
        boxed_step(|| {
            grant_boundary_assert_rejected(
                fixture,
                &event,
                status,
                problem,
                arkret_wire::ErrorCode::FAILED_PRECONDITION,
            )
        })
        .await;
        assert_eq!(
            boxed_step(|| obligation_mls_footprint(fixture)).await,
            before
        );
    }
    let event = signed_event(
        package,
        service.clone(),
        scope.clone(),
        EventKind::AppletBridgeError,
        payload.clone(),
        Some(bridge_grant),
        &signer,
    );
    let (status, value) = boxed_step(|| grant_boundary_send(fixture, package, &event)).await;
    assert_eq!(status, StatusCode::OK, "real Service BridgeError: {value}");
    let accepted_audit =
        boxed_step(|| grant_boundary_assert_accepted(fixture, &event, value)).await;
    let original = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&event.event_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(original.event, event);
    let historical =
        boxed_step(|| grant_boundary_historical_source(fixture, package, &event, registration))
            .await;
    let before = boxed_step(|| obligation_mls_footprint(fixture)).await;
    let (status, replay) = boxed_step(|| grant_boundary_send(fixture, package, &event)).await;
    assert_eq!(status, StatusCode::OK, "BridgeError exact retry: {replay}");
    let replay: AppletTransactionOutcome = serde_json::from_value(replay).unwrap();
    assert_eq!(
        replay, accepted_audit,
        "exact audit retry must retain its original Commit refs"
    );
    assert_eq!(
        boxed_step(|| obligation_mls_footprint(fixture)).await,
        before
    );
    boxed_step(|| obligation_close_grant(fixture, bridge_grant)).await;
    let audit =
        boxed_step(|| grant_boundary_historical_source(fixture, package, &event, registration))
            .await;
    assert_eq!(
        audit, historical,
        "closed current grant cannot rewrite the accepted Service signer fact"
    );
    let mut fresh_payload = payload;
    fresh_payload["error_code"] = json!("external_unavailable_after_exact_grant_closed");
    let fresh = signed_event(
        package,
        service,
        scope,
        EventKind::AppletBridgeError,
        fresh_payload,
        Some(bridge_grant),
        &signer,
    );
    let before = boxed_step(|| obligation_mls_footprint(fixture)).await;
    let (status, problem) = boxed_step(|| grant_boundary_send(fixture, package, &fresh)).await;
    boxed_step(|| {
        grant_boundary_assert_rejected(
            fixture,
            &fresh,
            status,
            problem,
            arkret_wire::ErrorCode::FAILED_PRECONDITION,
        )
    })
    .await;
    assert_eq!(
        boxed_step(|| obligation_mls_footprint(fixture)).await,
        before
    );
    let retained = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&event.event_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retained.event, original.event);
    assert_eq!(retained.commit, original.commit);
}
