#[path = "../support/terminal_rows.rs"]
mod terminal_rows;
use terminal_rows::terminal_persistent_rows;

use super::*;

#[inline(never)]
fn lifecycle_future<F: std::future::Future>(make: impl FnOnce() -> F) -> std::pin::Pin<Box<F>> {
    Box::pin(make())
}

async fn lifecycle_write_counts(
    pool: &coland_storage_postgres::PgPool,
    _realm: &arkret_wire::RealmId,
) -> serde_json::Value {
    terminal_persistent_rows(pool).await
}
#[tokio::test]
async fn archive_and_freeze_are_reversible_without_reopening_a_terminal_realm() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let unit = lifecycle_future(|| unit_with_plaintext_service(&pool)).await;
    let at = unit.transactions[0].commit.committed_at;
    lifecycle_future(|| {
        human_profile::admit(
            &pool,
            &unit.transactions[0].expected_authority.service_id,
            "bootstrap-actor",
        )
    })
    .await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    store
        .admit_ordinary_realm_bootstrap_unit(&unit, at)
        .await
        .unwrap();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let strand = strand_create_request(&unit);
    let strand = lifecycle_future(|| source_if_human(&pool, strand)).await;
    lifecycle_future(|| uow.commit_event(strand.clone()))
        .await
        .unwrap();
    let actor = creator_account(&unit);
    let mut head = lifecycle_future(|| {
        invite_grant_request(
            &pool,
            &strand,
            &unit,
            unit.transactions[0].event.event_id.as_str(),
            &actor,
            &["ak.realm.archive", "ak.realm.freeze"],
        )
    })
    .await;
    lifecycle_future(|| uow.commit_event(head.clone()))
        .await
        .unwrap();
    for (close, reopen, selector, field) in [
        (
            arkret_wire::EventKind::RealmFreeze,
            arkret_wire::EventKind::RealmUnfreeze,
            arkret_wire::CurrentSelector::RealmFreeze,
            "frozen",
        ),
        (
            arkret_wire::EventKind::RealmArchive,
            arkret_wire::EventKind::RealmRestore,
            arkret_wire::CurrentSelector::RealmArchive,
            "archived",
        ),
    ] {
        head = realm_event_request_as(&head, &actor, close, serde_json::json!({}));
        head = lifecycle_future(|| source_if_human(&pool, head)).await;
        lifecycle_future(|| uow.commit_event(head.clone()))
            .await
            .unwrap();
        let blocked = realm_event_request_as(
            &head,
            &actor,
            arkret_wire::EventKind::RealmProfile,
            serde_json::json!({"schema":"ak.schema.realm_profile.v1","title":"blocked ordinary write"}),
        );
        let blocked = lifecycle_future(|| source_if_human(&pool, blocked)).await;
        let before_refusal = terminal_persistent_rows(&pool).await;
        let error = lifecycle_future(|| uow.commit_event(blocked.clone()))
            .await
            .unwrap_err();
        assert_eq!(terminal_persistent_rows(&pool).await, before_refusal);
        assert!(error.to_string().contains("realm_frozen"), "{error}");
        assert_eq!(
            event_row_count(&pool, blocked.authority_commit.event.event_id.as_str()).await,
            0
        );
        head = realm_event_request_as(&head, &actor, reopen, serde_json::json!({}));
        head = lifecycle_future(|| source_if_human(&pool, head)).await;
        lifecycle_future(|| uow.commit_event(head.clone()))
            .await
            .unwrap();
        let material = store
            .realm_state_snapshot_material(&head.authority_commit.event.realm_id)
            .await
            .unwrap()
            .unwrap();
        assert!(material.current_state_entries.iter().any(|entry| matches!(entry,
            arkret_wire::CurrentState::Value { selector: actual, revision, value, .. }
            if actual == &selector && revision.commit_id == head.authority_commit.commit.commit_id
                && value.get(field) == Some(&serde_json::Value::Bool(false))
        )));
        head = realm_event_request_as(
            &head,
            &actor,
            arkret_wire::EventKind::RealmProfile,
            serde_json::json!({"schema":"ak.schema.realm_profile.v1","title":format!("reopened after {field}")}),
        );
        head = lifecycle_future(|| source_if_human(&pool, head)).await;
        lifecycle_future(|| uow.commit_event(head.clone()))
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn tombstone_commits_current_and_fences_fresh_writes_without_destroy_bypass() {
    lifecycle_future(terminal_child_consumer_case).await;
}

async fn terminal_child_consumer_case() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let unit = lifecycle_future(|| unit_with_plaintext_service(&pool)).await;
    let at = unit.transactions[0].commit.committed_at;
    lifecycle_future(|| {
        human_profile::admit(
            &pool,
            &unit.transactions[0].expected_authority.service_id,
            "bootstrap-actor",
        )
    })
    .await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    store
        .admit_ordinary_realm_bootstrap_unit(&unit, at)
        .await
        .unwrap();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let strand = strand_create_request(&unit);
    let strand = lifecycle_future(|| source_if_human(&pool, strand)).await;
    lifecycle_future(|| uow.commit_event(strand.clone()))
        .await
        .unwrap();
    let actor = creator_account(&unit);
    let grant = lifecycle_future(|| {
        invite_grant_request(
            &pool,
            &strand,
            &unit,
            unit.transactions[0].event.event_id.as_str(),
            &actor,
            &["ak.realm.archive", "ak.realm.freeze"],
        )
    })
    .await;
    lifecycle_future(|| uow.commit_event(grant.clone()))
        .await
        .unwrap();
    let public_strand =
        arkret_wire::StrandId::from_event_id(&strand.authority_commit.event.event_id);
    let grant_id = arkret_wire::GrantId::from_event_id(&grant.authority_commit.event.event_id);
    let mut grant_payload = serde_json::to_value(&grant.authority_commit.event.payload).unwrap();
    grant_payload["grant"]["actions"] = serde_json::json!(["ak.message.create"]);
    let grant_revision = serde_json::json!({"commit_id":grant.authority_commit.commit.commit_id,
        "stream_position":grant.authority_commit.commit.stream_position});
    let mut strand = grant;
    let realm = strand.authority_commit.event.realm_id.clone();
    let initial_policy = store
        .realm_state_snapshot_material(&realm)
        .await
        .unwrap()
        .unwrap()
        .current_state_entries
        .into_iter()
        .find_map(|row| match row {
            arkret_wire::CurrentState::Value {
                selector: arkret_wire::CurrentSelector::RealmPlaintextVisibleServices,
                value,
                ..
            } => Some(value),
            _ => None,
        })
        .unwrap();
    let mut restored_policy = initial_policy;
    for service in restored_policy["services"].as_array_mut().unwrap() {
        service["purposes"] = serde_json::json!(["restored signed policy"]);
    }
    for policy in [serde_json::json!({"services":[]}), restored_policy] {
        let change = realm_event_request_as(
            &strand,
            &actor,
            arkret_wire::EventKind::RealmPlaintextVisibleServices,
            policy.clone(),
        );
        let change = lifecycle_future(|| source_if_human(&pool, change)).await;
        lifecycle_future(|| uow.commit_event(change.clone()))
            .await
            .unwrap();
        let material = store
            .realm_state_snapshot_material(&realm)
            .await
            .unwrap()
            .unwrap();
        assert!(material.current_state_entries.iter().any(|row| matches!(row,
            arkret_wire::CurrentState::Value { selector:arkret_wire::CurrentSelector::RealmPlaintextVisibleServices, revision, value, .. }
                if value == &policy && revision.commit_id == change.authority_commit.commit.commit_id)));
        strand = change;
    }
    let mut spaces = Vec::new();
    for kind in ["board", "list"] {
        let create = realm_event_request_as(
            &strand,
            &actor,
            arkret_wire::EventKind::SpaceCreate,
            serde_json::json!({"object":{"schema":"ak.schema.space.v1","realm_id":realm,
                "kind":kind,"title":kind,"created_by":arkret_wire::ActorId::account(actor.clone()),"created_at":arkret_canonical::format_timestamp_canonical(at)}}),
        );
        let create = lifecycle_future(|| source_if_human(&pool, create)).await;
        lifecycle_future(|| uow.commit_event(create.clone()))
            .await
            .unwrap();
        spaces.push(arkret_wire::SpaceId::from_event_id(
            &create.authority_commit.event.event_id,
        ));
        strand = create;
    }
    let parent = realm_event_request_as(
        &strand,
        &actor,
        arkret_wire::EventKind::SpaceParent,
        serde_json::json!({"space_id":spaces[1],"parent_space_id":spaces[0],"expected_parent_space_id":null}),
    );
    let parent = lifecycle_future(|| source_if_human(&pool, parent)).await;
    lifecycle_future(|| uow.commit_event(parent.clone()))
        .await
        .unwrap();
    let placement = realm_event_request_as(
        &parent,
        &actor,
        arkret_wire::EventKind::StrandMove,
        serde_json::json!({"board_space_id":spaces[0],"strand_id":public_strand,
            "target_space_id":spaces[1],"rank":"a"}),
    );
    let placement = lifecycle_future(|| source_if_human(&pool, placement)).await;
    let before_placement = terminal_persistent_rows(&pool).await;
    for table in [
        "space_parent_current_states",
    ] {
        let original = before_placement[table]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["space_id"] == spaces[1].as_str())
            .unwrap()["current_commit_id"]
            .as_str()
            .unwrap();
        let mut conn = pool.get().await.unwrap();
        let query = format!("UPDATE {table} SET current_commit_id=$1 WHERE space_id=$2");
        diesel::sql_query(&query)
            .bind::<Text, _>(unit.transactions[0].commit.commit_id.as_str())
            .bind::<Text, _>(spaces[1].as_str())
            .execute(&mut conn)
            .await
            .unwrap();
        drop(conn);
        let corrupted = terminal_persistent_rows(&pool).await;
        let error = lifecycle_future(|| uow.commit_event(placement.clone()))
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("placement List is absent or incomplete"),
            "{error}"
        );
        assert_eq!(terminal_persistent_rows(&pool).await, corrupted);
        let mut conn = pool.get().await.unwrap();
        diesel::sql_query(&query)
            .bind::<Text, _>(original)
            .bind::<Text, _>(spaces[1].as_str())
            .execute(&mut conn)
            .await
            .unwrap();
        drop(conn);
        assert_eq!(terminal_persistent_rows(&pool).await, before_placement);
    }
    lifecycle_future(|| uow.commit_event(placement.clone()))
        .await
        .unwrap();
    let nav = store
        .object_projection_lists_for_actor(
            &realm,
            &arkret_wire::ActorId::account(actor.clone()),
            false,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(nav.0.spaces.len(), 2);
    assert_eq!(nav.1.strands.len(), 1);
    assert!(
        nav.1
            .strands
            .iter()
            .any(|row| row.board_space_id.as_ref() == Some(&spaces[0])
                && row.list_space_id.as_ref() == Some(&spaces[1]))
    );
    strand = placement;
    let baseline = store
        .realm_state_snapshot_material(&realm)
        .await
        .unwrap()
        .unwrap();
    let baseline_counts = lifecycle_write_counts(&pool, &realm).await;
    for (kind, payload) in [
        (
            arkret_wire::EventKind::RealmDestroy,
            serde_json::json!({"reason":"close"}),
        ),
        (
            arkret_wire::EventKind::RealmTombstone,
            serde_json::json!({"reason":"migrate"}),
        ),
        (
            arkret_wire::EventKind::RealmTombstone,
            serde_json::json!({"reason":"self", "successor_realm_id":realm}),
        ),
    ] {
        let is_destroy = kind == arkret_wire::EventKind::RealmDestroy;
        let missing_successor = !is_destroy && payload.get("successor_realm_id").is_none();
        let request = realm_event_request_as(&strand, &actor, kind, payload);
        let request = lifecycle_future(|| source_if_human(&pool, request)).await;
        let error = lifecycle_future(|| uow.commit_event(request.clone()))
            .await
            .unwrap_err();
        assert!(
            !error.to_string().contains("realm_terminal_state"),
            "{error}"
        );
        if is_destroy {
            assert!(error.to_string().contains("failed_precondition"), "{error}");
            assert!(
                !error.to_string().contains("realm_terminal_state"),
                "{error}"
            );
        }
        if missing_successor {
            assert!(
                matches!(error, coland_storage::PersistenceError::SchemaViolation(_)),
                "{error}"
            );
        } else {
            assert_eq!(
                error.conflict_code(),
                Some(coland_storage::ConflictCode::FailedPrecondition),
                "{error}"
            );
        }
        assert_eq!(
            event_row_count(&pool, request.authority_commit.event.event_id.as_str()).await,
            0
        );
        assert_eq!(
            store
                .realm_state_snapshot_material(&realm)
                .await
                .unwrap()
                .unwrap()
                .current_state_entries,
            baseline.current_state_entries
        );
        assert_eq!(lifecycle_write_counts(&pool, &realm).await, baseline_counts);
        assert!(
            store
                .committed_event(&request.authority_commit.event.event_id)
                .await
                .unwrap()
                .is_none()
        );
    }
    let payload = serde_json::json!({
        "reason":"migrate", "successor_realm_id":"ak:realm:ASR8x2N1qyfyy6I-eob3l-FNhx4FPBTyMJrIfifkksgW"
    });
    let terminal = realm_event_request_as(
        &strand,
        &actor,
        arkret_wire::EventKind::RealmTombstone,
        payload.clone(),
    );
    let terminal = lifecycle_future(|| source_if_human(&pool, terminal)).await;
    lifecycle_future(|| uow.commit_event(terminal.clone()))
        .await
        .unwrap();
    let material = store
        .realm_state_snapshot_material(&realm)
        .await
        .unwrap()
        .unwrap();
    assert!(material.current_state_entries.iter().any(|entry| matches!(entry,
        arkret_wire::CurrentState::Value {selector: arkret_wire::CurrentSelector::RealmTombstone, revision, value, ..}
        if revision.commit_id == terminal.authority_commit.commit.commit_id && value == &payload
    )));
    let navigation = store
        .object_projection_lists_for_actor(
            &realm,
            &arkret_wire::ActorId::account(actor.clone()),
            true,
        )
        .await
        .unwrap()
        .unwrap();
    assert!(navigation.0.spaces.is_empty());
    assert!(navigation.1.strands.is_empty());
    assert!(material.current_state_entries.iter().any(|entry| matches!(
        entry,
        arkret_wire::CurrentState::Value {
            selector: arkret_wire::CurrentSelector::Strand { .. },
            ..
        }
    )));
    let families = message_families(&pool, &realm).await;
    let terminal_counts = lifecycle_write_counts(&pool, &realm).await;
    for (kind, payload) in [
        (
            arkret_wire::EventKind::RealmProfile,
            serde_json::json!({"schema":"ak.schema.realm_profile.v1","title":"reopen"}),
        ),
        (
            arkret_wire::EventKind::RealmTombstone,
            serde_json::json!({"reason":"again", "successor_realm_id":"ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb"}),
        ),
        (arkret_wire::EventKind::RealmRestore, serde_json::json!({})),
        (arkret_wire::EventKind::RealmUnfreeze, serde_json::json!({})),
        (
            arkret_wire::EventKind::RealmPolicyBundle,
            serde_json::json!({"policy_revision":2,"federation_policy":"open"}),
        ),
        (arkret_wire::EventKind::CapabilityGrant, grant_payload),
        (
            arkret_wire::EventKind::RealmPlaintextVisibleServices,
            serde_json::json!({"services":[{
            "service_id":actor.station_id,"service_kind":"station","purposes":["post terminal"],
            "data_classes":["message_content"],"visibility":"private_plaintext"}]}),
        ),
        (
            arkret_wire::EventKind::CapabilityRevoke,
            serde_json::json!({"grant_id":grant_id,"expected_commit_id":grant_revision}),
        ),
        (
            arkret_wire::EventKind::MemberState,
            serde_json::json!({"member_id":arkret_wire::ActorId::account(actor.clone()),"membership":"leave"}),
        ),
        (
            arkret_wire::EventKind::SpaceParent,
            serde_json::json!({"space_id":spaces[1],"parent_space_id":null,"expected_parent_space_id":spaces[0]}),
        ),
        (
            arkret_wire::EventKind::SpaceUpdate,
            serde_json::json!({"space_id":spaces[0],"patch":{"title":"terminal update"}}),
        ),
        (
            arkret_wire::EventKind::SpaceArchive,
            serde_json::json!({"space_id":spaces[0]}),
        ),
        (
            arkret_wire::EventKind::SpaceRestore,
            serde_json::json!({"space_id":spaces[0]}),
        ),
        (
            arkret_wire::EventKind::StrandMove,
            serde_json::json!({"board_space_id":spaces[0],"strand_id":public_strand,"target_space_id":spaces[1],"rank":"b","expected_position":{"list_space_id":spaces[1],"rank":"a"}}),
        ),
        (
            arkret_wire::EventKind::StrandRestore,
            serde_json::json!({"target_ref":public_strand}),
        ),
        (arkret_wire::EventKind::StrandCreate, serde_json::to_value(&strand_create_request(&unit).authority_commit.event.payload).unwrap()),
    ] {
        let request = realm_event_request_as(&terminal, &actor, kind, payload);
        let request = lifecycle_future(|| source_if_human(&pool, request)).await;
        arkret_schema::validate_event_for_submit(&request.authority_commit.event).unwrap();
        let error = lifecycle_future(|| uow.commit_event(request.clone()))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("failed_precondition"), "{error}");
        assert!(
            error.to_string().contains("the Realm is terminal"),
            "{error}"
        );
        assert!(
            !error.to_string().contains("realm_terminal_state"),
            "{error}"
        );
        assert_eq!(
            event_row_count(&pool, request.authority_commit.event.event_id.as_str()).await,
            0
        );
        assert_eq!(message_families(&pool, &realm).await, families);
        assert_eq!(lifecycle_write_counts(&pool, &realm).await, terminal_counts);
        assert_eq!(
            store
                .realm_state_snapshot_material(&realm)
                .await
                .unwrap()
                .unwrap()
                .current_state_entries,
            material.current_state_entries
        );
        assert!(
            store
                .committed_event(&request.authority_commit.event.event_id)
                .await
                .unwrap()
                .is_none()
        );
    }
    assert!(
        !lifecycle_future(|| uow.commit_event(terminal.clone()))
            .await
            .unwrap()
            .event_inserted
    );
    assert_eq!(lifecycle_write_counts(&pool, &realm).await, terminal_counts);
    assert!(
        store
            .committed_event(&strand.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_some()
    );
}
