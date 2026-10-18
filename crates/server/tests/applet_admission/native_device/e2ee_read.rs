//! Existing E2EE consent must be consumed by the native final read barrier.
use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bot_and_ghost_read_accepted_encrypted_scope_events_without_session() {
    tokio::spawn(native_phase(|| async {
        let fixture = native_phase(Fixture::new).await;
        let scope = ScopeRef::Realm {
            realm_id: fixture.realm.clone(),
        };
        native_phase(|| activate_mls(&fixture, scope.clone())).await;
        let namespace = format!("bridge.{}", uuid::Uuid::now_v7().simple());
        let native = mls_service(&fixture, &namespace);
        let install =
            native_phase(|| fixture.install_package(true, native.package.clone(), &namespace))
                .await;
        let ghost =
            native_phase(|| fixture.ghost_body(&install, &namespace, "encrypted-read")).await;
        assert_eq!(
            native_phase(|| fixture.ghost_commit(&install, &ghost, "encrypted-read"))
                .await
                .0,
            StatusCode::CREATED
        );
        let _read_parent = native_phase(|| {
            native_business_parent(
                &fixture,
                &install,
                vec![],
                vec!["ak.event.read".into()],
                None,
            )
        })
        .await;
        let mut actors = Vec::new();
        for bundle in [
            &install.bot_body["managed_actor_bundle"],
            &ghost["managed_actor_bundle"],
        ] {
            let key = SigningKey::from_bytes(&[175; 32]);
            let device = DeviceId::new(format!("ak:device:{}", uuid::Uuid::now_v7())).unwrap();
            let authority = native_phase(|| {
                authorize(&fixture, &install, bundle, &namespace, &key, device, true)
            })
            .await;
            let event = join_event(
                &fixture,
                &install,
                &authority,
                &key,
                &install.bot_outcome.authorization_ref,
            );
            let (status, outcome) =
                native_phase(|| post(&fixture, &authority, &key, &event, vec![])).await;
            assert_eq!(
                status,
                StatusCode::OK,
                "real accepted encrypted membership: {outcome}"
            );
            native_phase(|| reads_ok(&fixture, &authority, &key, &scope, &event)).await;
            for operation in ["read", "deliver"] {
                native_phase(|| unwired_policy_refused(&fixture, &install, &scope, operation))
                    .await;
            }
            let authority = native_phase(|| {
                keypackage::circle_membership(
                    &fixture, &install, &namespace, bundle, &authority, &key, true,
                )
            })
            .await;
            let circle = authority
                .scopes
                .entries()
                .iter()
                .find(|entry| matches!(entry.effective_scope, ScopeRef::Circle { .. }))
                .unwrap()
                .effective_scope
                .clone();
            let _circle_parent = native_phase(|| {
                native_business_parent_in_scope(
                    &fixture,
                    &install,
                    vec![],
                    vec!["ak.event.read".into()],
                    None,
                    circle.clone(),
                )
            })
            .await;
            let circle_event = native_phase(|| circle_join(&fixture, &authority, &circle)).await;
            native_phase(|| reads_ok(&fixture, &authority, &key, &scope, &event)).await;
            native_phase(|| reads_ok(&fixture, &authority, &key, &circle, &circle_event)).await;
            for (wrong_scope, original) in [(&scope, &circle_event), (&circle, &event)] {
                let before = business(&fixture).await;
                let mut response = native_phase(|| {
                    get(&fixture, &authority, &key, wrong_scope, &original.event_id)
                })
                .await;
                assert_eq!(response.status_code, Some(StatusCode::NOT_FOUND));
                let _: Value = response.take_json().await.unwrap();
                assert_eq!(before, business(&fixture).await);
            }
            actors.push((authority, key, event, circle, circle_event));
        }
        native_phase(|| fixture.revoke(&install)).await;
        for (authority, key, event, circle, circle_event) in actors {
            native_phase(|| reads_refused(&fixture, &authority, &key, &scope, &event)).await;
            native_phase(|| reads_ok(&fixture, &authority, &key, &circle, &circle_event)).await;
        }
    }))
    .await
    .unwrap();
}

async fn get(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    scope: &ScopeRef,
    event: &EventId,
) -> salvo::Response {
    let mut metadata = managed_device_metadata(authority);
    metadata.effective_scope = scope.clone();
    let path = format!("/_arkret/self/committed-events/{event}");
    managed_device_http_request_at(
        &fixture.state,
        authority,
        &metadata,
        ServiceOperationId::SelfCommittedEventResourceGetV1,
        key,
        None,
        Some(&path),
    )
    .send(&service(fixture.state.clone()))
    .await
}

async fn signer(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    scope: &ScopeRef,
    event: &Event,
) -> salvo::Response {
    let mut metadata = managed_device_metadata(authority);
    metadata.effective_scope = scope.clone();
    let body = arkret_models_identity::SignerKeysQueryRequestBody {
        request_id: arkret_wire::RequestId::new(format!("ak:request:{}", uuid::Uuid::now_v7()))
            .unwrap(),
        realm_id: fixture.realm.clone(),
        recipient_account_id: authority.account_id.clone(),
        queries: vec![native_historical_selector(fixture, event).await],
    };
    managed_device_http_request_body(
        &fixture.state,
        authority,
        &metadata,
        ServiceOperationId::SelfSignerKeysReadResolveV1,
        key,
        Some(arkret_canonical::canonical_json_bytes(&body).unwrap()),
    )
    .add_header("content-type", "application/json", true)
    .send(&service(fixture.state.clone()))
    .await
}

fn scan_request(scope: &ScopeRef) -> arkret_wire::StreamScanRequest {
    let stream_ref = match scope {
        ScopeRef::Realm { realm_id } => arkret_wire::CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        },
        ScopeRef::Circle {
            realm_id,
            circle_id,
        } => arkret_wire::CommitStreamRef::Circle {
            realm_id: realm_id.clone(),
            circle_id: circle_id.clone(),
        },
        _ => unreachable!(),
    };
    arkret_wire::StreamScanRequest {
        realm_id: scope.realm_id().clone(),
        stream_ref,
        direction: arkret_wire::StreamScanDirection::After(None),
        limit: 1000,
    }
}

async fn scan(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    scope: &ScopeRef,
    body: &arkret_wire::StreamScanRequest,
) -> salvo::Response {
    let mut metadata = managed_device_metadata(authority);
    metadata.effective_scope = scope.clone();
    managed_device_http_request_body(
        &fixture.state,
        authority,
        &metadata,
        ServiceOperationId::SelfCommittedEventReadScanV1,
        key,
        Some(arkret_canonical::canonical_json_bytes(body).unwrap()),
    )
    .add_header("content-type", "application/json", true)
    .send(&service(fixture.state.clone()))
    .await
}

async fn reads_ok(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    scope: &ScopeRef,
    event: &Event,
) {
    let before = business(fixture).await;
    let mut response = native_phase(|| get(fixture, authority, key, scope, &event.event_id)).await;
    let status = response.status_code;
    let raw: Value = response.take_json().await.unwrap();
    assert_eq!(
        status,
        Some(StatusCode::OK),
        "real consent-bound Event read: {raw}"
    );
    let read: arkret_wire::CommittedEventView = serde_json::from_value(raw).unwrap();
    assert_eq!(read.reducer_input(), Some(event));
    let mut response = native_phase(|| signer(fixture, authority, key, scope, event)).await;
    let status = response.status_code;
    let raw: Value = response.take_json().await.unwrap();
    assert_eq!(
        status,
        Some(StatusCode::OK),
        "same original signer source: {raw}"
    );
    let result: arkret_models_identity::SignerKeysQueryOutcome =
        serde_json::from_value(raw).unwrap();
    assert_eq!(result.results.len(), 1);
    assert!(result.results[0].key().is_some());
    let request = scan_request(scope);
    let mut response = native_phase(|| scan(fixture, authority, key, scope, &request)).await;
    let status = response.status_code;
    let raw: Value = response.take_json().await.unwrap();
    assert_eq!(
        status,
        Some(StatusCode::OK),
        "exact encrypted stream: {raw}"
    );
    let result: arkret_wire::StreamScanOutcome = serde_json::from_value(raw).unwrap();
    result.validate_for_request(&request).unwrap();
    assert!(
        result
            .committed_events
            .iter()
            .any(|row| row.commit().event_ref == event.event_id)
    );
    assert_eq!(before, business(fixture).await);
}

async fn reads_refused(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    scope: &ScopeRef,
    event: &Event,
) {
    let before = business(fixture).await;
    let mut response = native_phase(|| get(fixture, authority, key, scope, &event.event_id)).await;
    assert_eq!(response.status_code, Some(StatusCode::NOT_FOUND));
    let _: Value = response.take_json().await.unwrap();
    let mut response = native_phase(|| signer(fixture, authority, key, scope, event)).await;
    assert_eq!(response.status_code, Some(StatusCode::NOT_FOUND));
    let _: Value = response.take_json().await.unwrap();
    let request = scan_request(scope);
    let mut response = native_phase(|| scan(fixture, authority, key, scope, &request)).await;
    assert_eq!(response.status_code, Some(StatusCode::FORBIDDEN));
    let _: Value = response.take_json().await.unwrap();
    assert_eq!(before, business(fixture).await);
}

async fn circle_join(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    scope: &ScopeRef,
) -> Event {
    #[derive(diesel::QueryableByName)]
    struct Original {
        #[diesel(sql_type=diesel::sql_types::Jsonb)]
        envelope: Value,
    }
    let mut conn = fixture.pool.get().await.unwrap();
    let row=diesel::sql_query("SELECT e.envelope FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE e.state='committed' AND e.kind='ak.circle.member.state' AND e.envelope->'scope_ref'=$1 AND e.envelope#>'{payload,member_id}'=$2 AND e.envelope#>>'{payload,membership}'='join' ORDER BY c.stream_position DESC LIMIT 1")
        .bind::<diesel::sql_types::Jsonb,_>(json!(scope)).bind::<diesel::sql_types::Jsonb,_>(json!(ActorId::account(authority.account_id.clone())))
        .get_result::<Original>(&mut conn).await.unwrap();
    serde_json::from_value(row.envelope).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn encrypted_consent_expiry_blocks_already_prepared_bytes_at_handoff() {
    tokio::spawn(native_phase(|| async {
        use arkret_models_collaboration::governance::grant_constraint::{GrantConstraintEffect,GrantConstraintKind};
        let fixture=native_phase(Fixture::new).await;
        let scope=ScopeRef::Realm{realm_id:fixture.realm.clone()};
        native_phase(||activate_mls(&fixture,scope.clone())).await;
        let namespace=format!("bridge.{}",uuid::Uuid::now_v7().simple());
        let native=mls_service(&fixture,&namespace);
        let deadline=arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()+chrono::Duration::seconds(15));
        let mut temporal=GrantConstraint::new(GrantConstraintKind::Temporal,GrantConstraintEffect::Allow);
        temporal.expires_at=Some(deadline);
        let extras=["ak.message.create","ak.applet.bot.provision","ak.applet.ghost.provision"].into_iter().map(|action|(action.to_owned(),vec![temporal.clone()])).collect();
        let (package,outcome,body,install_key)=native_phase(||fixture.install_service_with_constraints(true,native.package.clone(),scope.clone(),extras)).await;
        let (bot_outcome,bot_body)=native_phase(||fixture.provision_bot_in_scope(&package,&namespace,outcome.registration_event_ref.clone(),scope.clone())).await;
        let install=Installed { package, outcome, bot_outcome, bot_body, body, key:install_key };
        let key=SigningKey::from_bytes(&[176;32]);
        let device=DeviceId::new(format!("ak:device:{}",uuid::Uuid::now_v7())).unwrap();
        let authority=native_phase(||authorize(&fixture,&install,&install.bot_body["managed_actor_bundle"],&namespace,&key,device,true)).await;
        let event=join_event(&fixture,&install,&authority,&key,&install.bot_outcome.authorization_ref);
        let (status,outcome)=native_phase(||post(&fixture,&authority,&key,&event,vec![])).await;
        assert_eq!(status,StatusCode::OK,"original finite consent is initially live: {outcome}");
        let _read_parent=native_phase(||native_business_parent(&fixture,&install,vec![],vec!["ak.event.read".into()],None)).await;
        let mut response=native_phase(||get(&fixture,&authority,&key,&scope,&event.event_id)).await;
        assert_eq!(response.status_code,Some(StatusCode::OK));
        let before=business(&fixture).await;
        let remaining=(deadline-chrono::Utc::now()).to_std().unwrap_or_default();
        tokio::time::sleep(remaining+std::time::Duration::from_millis(100)).await;
        assert!(response.take_json::<Value>().await.is_err(),"expired original E2EE consent cannot hand off prepared bytes while a separate read parent remains active");
        assert_eq!(before,business(&fixture).await);
        native_phase(||reads_refused(&fixture,&authority,&key,&scope,&event)).await;
    })).await.unwrap();
}

async fn unwired_policy_refused(
    fixture: &Fixture,
    install: &Installed,
    scope: &ScopeRef,
    operation: &str,
) {
    use coland_storage::EventCommitUnitOfWork as _;
    let id = format!("ak:policy:{}", uuid::Uuid::now_v7());
    let actor = ActorId::account(fixture.pcr.history.account.clone());
    let event=fixture.admin_event(EventKind::PolicySet,scope.clone(),json!({
        "policy_id":id,"expected_revision":null,"value":{
            "schema":"ak.schema.policy.v1","id":id,"realm_id":fixture.realm,
            "policy_kind":"applet","default_effect":"allow","created_by":actor,
            "created_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now()),
            "rules":[{"rule_id":"unwired_operation","kind":"applet","effect":"deny",
                "applet_target":{"kind":"installation","applet_id":install.package.applet_id,"effective_scope":scope},
                "applet_operations":[operation]}]
        }
    }));
    let request = native_phase(|| admin_domain_request(fixture, event)).await;
    let before = business(fixture).await;
    let result = coland_storage_postgres::PgEventCommitUnitOfWork::new(fixture.pool.clone())
        .commit_event(request)
        .await;
    assert!(
        matches!(result,Err(coland_storage::PersistenceError::Conflict(ref detail)) if detail.contains("Applet Policy requires established consumers")),
        "unwired consumers must keep their configuration guard: {result:?}"
    );
    assert_eq!(before, business(fixture).await);
}
