//! Signed native snapshots preserve exact streams, original references and live gates.
use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bot_and_ghost_read_exact_scope_snapshots_and_original_refs_without_session() {
    for ghost in [false, true] {
        for circle in [false, true] {
            tokio::spawn(native_phase(|| {
                originate(ghost, Case::SnapshotReads, circle)
            }))
            .await
            .unwrap();
        }
    }
}

async fn read(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    scope: &ScopeRef,
    reference: Option<&arkret_wire::RealmSnapshotId>,
) -> salvo::Response {
    let operation = arkret_wire::ServiceOperationId::from_wire(if reference.is_some() {
        "ak.self.realm_state_snapshot.read.by_ref.v1"
    } else {
        "ak.self.realm_state_snapshot.read.manifest_head.v1"
    })
    .unwrap();
    let path = operation.descriptor().http_path.replace(
        "{snapshot_id}",
        reference.map(|id| id.as_str()).unwrap_or(""),
    );
    let path = format!("{path}?realm_id={}", scope.realm_id());
    let mut metadata = managed_device_metadata(authority);
    metadata.effective_scope = scope.clone();
    managed_device_http_request_at(
        &fixture.state,
        authority,
        &metadata,
        operation,
        key,
        None,
        Some(&path),
    )
    .send(&service(fixture.state.clone()))
    .await
}

async fn refused(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    scope: &ScopeRef,
    reference: Option<&arkret_wire::RealmSnapshotId>,
) {
    let mut response = native_phase(|| read(fixture, authority, key, scope, reference)).await;
    let status = response.status_code;
    let body: Value = response.take_json().await.unwrap();
    assert!(
        !status.unwrap().is_success(),
        "unexpected snapshot disclosure: {body}"
    );
    assert!(body.get("current_state_entries").is_none(), "{body}");
}

pub(super) async fn exercise(
    fixture: &Fixture,
    install: &Installed,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    scope: &ScopeRef,
    (strand, source): (arkret_wire::StrandId, EventId),
) {
    native_phase(|| refused(fixture, authority, key, scope, None)).await;
    let parent = native_phase(|| {
        native_business_parent_in_scope(
            fixture,
            install,
            vec![],
            vec!["ak.event.read".into()],
            None,
            scope.clone(),
        )
    })
    .await;
    let before = native_phase(|| business(fixture)).await;
    let mut response = native_phase(|| read(fixture, authority, key, scope, None)).await;
    let status = response.status_code;
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(status, Some(StatusCode::OK), "native snapshot head: {body}");
    let snapshot: arkret_wire::RealmStateSnapshot = serde_json::from_value(body).unwrap();
    let expected = arkret_wire::CommitStreamRef::from_scope(scope, None).unwrap();
    assert_eq!(snapshot.visible_stream_heads.len(), 1);
    assert_eq!(snapshot.visible_stream_heads[0].stream_ref, expected);
    assert_eq!(snapshot.retention_and_history_floor.stream_floors.len(), 1);
    assert_eq!(
        snapshot.retention_and_history_floor.stream_floors[0].stream_ref,
        expected
    );
    assert!(snapshot.current_state_entries.iter().all(|row| match row {
        arkret_wire::TypedCurrentRow::Value {
            source_stream_ref, ..
        } => source_stream_ref == &expected,
    }));
    assert!(
        snapshot.current_state_entries.iter().any(|row| match row {
            arkret_wire::TypedCurrentRow::Value {
                selector: arkret_wire::CurrentSelector::Strand { strand_id },
                ..
            } => strand_id == &strand,
            _ => false,
        }),
        "state before membership must remain visible below the history floor"
    );
    // Current metadata must not make its unavailable original Event readable.
    let mut metadata = managed_device_metadata(authority);
    metadata.effective_scope = scope.clone();
    let path = format!("/_arkret/self/committed-events/{source}");
    let mut original = native_phase(|| async {
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
    })
    .await;
    assert!(!original.status_code.unwrap().is_success());
    let _: Value = original.take_json().await.unwrap();
    let mut response =
        native_phase(|| read(fixture, authority, key, scope, Some(&snapshot.snapshot_id))).await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    assert_eq!(
        response
            .take_json::<arkret_wire::RealmStateSnapshot>()
            .await
            .unwrap(),
        snapshot
    );
    assert_eq!(before, native_phase(|| business(fixture)).await);
    if matches!(scope, ScopeRef::Circle { .. }) {
        let realm = ScopeRef::Realm {
            realm_id: fixture.realm.clone(),
        };
        let realm_parent = native_phase(|| {
            native_business_parent_in_scope(
                fixture,
                install,
                vec![],
                vec!["ak.event.read".into()],
                None,
                realm.clone(),
            )
        })
        .await;
        let mut response = native_phase(|| read(fixture, authority, key, &realm, None)).await;
        let status = response.status_code;
        let body: Value = response.take_json().await.unwrap();
        assert_eq!(
            status,
            Some(StatusCode::OK),
            "separate authorized Realm cut: {body}"
        );
        let realm_snapshot: arkret_wire::RealmStateSnapshot = serde_json::from_value(body).unwrap();
        assert!(
            realm_snapshot
                .current_state_entries
                .iter()
                .all(|row| !matches!(
                    row,
                    arkret_wire::TypedCurrentRow::Value {
                        selector: arkret_wire::CurrentSelector::Circle { .. },
                        ..
                    }
                )),
            "Circle membership must not leak Circle data through a Realm Device cut"
        );
        native_phase(|| refused(fixture, authority, key, &realm, Some(&snapshot.snapshot_id)))
            .await;
        native_phase(|| native_current_revoke(fixture, &realm_parent)).await;
    }
    let other = if matches!(scope, ScopeRef::Circle { .. }) {
        ScopeRef::Realm {
            realm_id: fixture.realm.clone(),
        }
    } else {
        native_phase(|| fixture.new_circle_scope()).await
    };
    native_phase(|| refused(fixture, authority, key, &other, Some(&snapshot.snapshot_id))).await;
    let latest = native_phase(|| current_read::prepare_source(fixture, scope)).await;
    let mut response = native_phase(|| read(fixture, authority, key, scope, None)).await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    let next = response
        .take_json::<arkret_wire::RealmStateSnapshot>()
        .await
        .unwrap();
    assert_ne!(next.snapshot_id, snapshot.snapshot_id);
    assert!(next.current_state_entries.iter().any(|row| match row {
        arkret_wire::TypedCurrentRow::Value {
            selector: arkret_wire::CurrentSelector::Strand { strand_id },
            ..
        } => strand_id == &latest.0,
        _ => false,
    }));
    let mut response =
        native_phase(|| read(fixture, authority, key, scope, Some(&snapshot.snapshot_id))).await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    assert_eq!(
        response
            .take_json::<arkret_wire::RealmStateSnapshot>()
            .await
            .unwrap(),
        snapshot,
        "by-ref must return the original rather than silently substitute current"
    );
    native_phase(|| native_current_revoke(fixture, &parent)).await;
    native_phase(|| refused(fixture, authority, key, scope, None)).await;
    native_phase(|| refused(fixture, authority, key, scope, Some(&snapshot.snapshot_id))).await;
    // Publication retains the same finite Service grant proof as issuance.
    use arkret_models_collaboration::governance::grant_constraint::{
        GrantConstraintEffect, GrantConstraintKind,
    };
    let deadline = arkret_canonical::normalize_timestamp_canonical(
        chrono::Utc::now() + chrono::Duration::seconds(15),
    );
    let mut temporal =
        GrantConstraint::new(GrantConstraintKind::Temporal, GrantConstraintEffect::Allow);
    temporal.expires_at = Some(deadline);
    let _finite = native_phase(|| {
        native_business_parent_in_scope(
            fixture,
            install,
            vec![temporal],
            vec!["ak.event.read".into()],
            None,
            scope.clone(),
        )
    })
    .await;
    let before_delivery = native_phase(|| business(fixture)).await;
    let mut response = native_phase(|| read(fixture, authority, key, scope, None)).await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    tokio::time::sleep(
        (deadline - chrono::Utc::now()).to_std().unwrap_or_default()
            + std::time::Duration::from_millis(100),
    )
    .await;
    assert!(
        response.take_json::<Value>().await.is_err(),
        "expired prepared snapshot was published"
    );
    assert_eq!(before_delivery, native_phase(|| business(fixture)).await);
    // Restore the actual read source before testing operation separation and
    // the still-required guard for consumers not yet implemented.
    let _fresh = native_phase(|| {
        native_business_parent_in_scope(
            fixture,
            install,
            vec![],
            vec!["ak.event.read".into()],
            None,
            scope.clone(),
        )
    })
    .await;
    let mut response = native_phase(|| read(fixture, authority, key, scope, None)).await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    let _: arkret_wire::RealmStateSnapshot = response.take_json().await.unwrap();
    let mut response =
        native_phase(|| read(fixture, authority, key, scope, Some(&snapshot.snapshot_id))).await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    assert_eq!(
        response
            .take_json::<arkret_wire::RealmStateSnapshot>()
            .await
            .unwrap(),
        snapshot
    );
    let id = format!("ak:policy:{}", uuid::Uuid::now_v7());
    let admin = ActorId::account(fixture.pcr.history.account.clone());
    let mut payload = json!({
        "policy_id":id,"expected_revision":null,"value":{
            "schema":"ak.schema.policy.v1","id":id,"realm_id":fixture.realm,
            "policy_kind":"applet","default_effect":"allow","created_by":admin,
            "created_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now()),
            "rules":[{"rule_id":"target_strand_operation","kind":"applet","effect":"deny",
                "applet_operations":["deliver"],"applet_target":{"kind":"installation",
                    "applet_id":install.package.applet_id,"effective_scope":scope},
                "resources":[{"kind":"strand","realm_id":fixture.realm,"resource_ref":strand}]}]
        }
    });
    for operation in ["read", "deliver"] {
        payload["value"]["rules"][0]["applet_operations"] = json!([operation]);
        let event = fixture.admin_event(EventKind::PolicySet, scope.clone(), payload.clone());
        let request = native_phase(|| admin_domain_request(fixture, event)).await;
        let before = native_phase(|| business(fixture)).await;
        let store = coland_storage_postgres::PgEventCommitUnitOfWork::new(fixture.pool.clone());
        let result =
            native_phase(|| coland_storage::EventCommitUnitOfWork::commit_event(&store, request))
                .await;
        assert!(
            matches!(result, Err(coland_storage::PersistenceError::Conflict(ref detail))
            if detail.contains("Applet Policy requires established consumers")),
            "other unfinished consumers must retain the configuration guard: {result:?}"
        );
        assert_eq!(before, native_phase(|| business(fixture)).await);
    }
    payload["value"]["rules"][0]["applet_operations"] = json!(["execute"]);
    let event = fixture.admin_event(EventKind::PolicySet, scope.clone(), payload);
    native_phase(|| accepted_admin_domain_event(fixture, event)).await;
    let before = native_phase(|| business(fixture)).await;
    let mut response = native_phase(|| read(fixture, authority, key, scope, None)).await;
    assert_eq!(
        response.status_code,
        Some(StatusCode::OK),
        "execute denial must not substitute for the separate read/deliver gates"
    );
    let current: arkret_wire::RealmStateSnapshot = response.take_json().await.unwrap();
    assert!(
        !current.current_state_entries.iter().any(|row| matches!(
            row,
            arkret_wire::TypedCurrentRow::Value {
                selector: arkret_wire::CurrentSelector::Policy { .. },
                ..
            }
        )),
        "ordinary Device snapshots must not enumerate private management Policy"
    );
    let mut response =
        native_phase(|| read(fixture, authority, key, scope, Some(&snapshot.snapshot_id))).await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    assert_eq!(
        response
            .take_json::<arkret_wire::RealmStateSnapshot>()
            .await
            .unwrap(),
        snapshot
    );
    assert_eq!(before, native_phase(|| business(fixture)).await);
}
