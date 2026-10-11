use super::*;

async fn terminal_persistent_rows(pool: &coland_storage_postgres::PgPool) -> serde_json::Value {
    use diesel_async::RunQueryDsl as _;
    #[derive(diesel::QueryableByName)]
    struct Table {
        #[diesel(sql_type = diesel::sql_types::Text)]
        tablename: String,
    }
    #[derive(diesel::QueryableByName)]
    struct Rows {
        #[diesel(sql_type = diesel::sql_types::Jsonb)]
        value: serde_json::Value,
    }
    let mut conn = pool.get().await.unwrap();
    let tables = diesel::sql_query("SELECT tablename::text AS tablename FROM pg_tables WHERE schemaname='public' AND (tablename LIKE '%current_results' OR tablename IN ('canonical_events','realm_commits','realm_authorities','federation_outbox','event_federation_outbox','replica_stream_anchors','replica_authorization_rows','replica_authorization_cuts','account_summary_current','account_summary_versions','account_summary_clock','current_result_heads','current_result_versions','direct_conversation_founding_slots')) ORDER BY tablename")
        .load::<Table>(&mut *conn).await.unwrap();
    let mut snapshot = serde_json::Map::new();
    for table in tables {
        assert!(
            table
                .tablename
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        );
        let query = format!(
            "SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb) AS value FROM public.{} r",
            table.tablename
        );
        let rows = diesel::sql_query(query)
            .get_result::<Rows>(&mut *conn)
            .await
            .unwrap();
        snapshot.insert(table.tablename, rows.value);
    }
    for table in [
        "canonical_events",
        "realm_commits",
        "realm_authorities",
        "federation_outbox",
        "event_federation_outbox",
        "realm_bootstrap_current_results",
        "replica_stream_anchors",
        "replica_authorization_rows",
        "replica_authorization_cuts",
        "account_summary_current",
        "account_summary_versions",
        "account_summary_clock",
    ] {
        assert!(
            snapshot.contains_key(table),
            "missing acceptance footprint table: {table}"
        );
    }
    serde_json::Value::Object(snapshot)
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
    let unit = Box::pin(unit_with_plaintext_service(&pool)).await;
    let at = unit.transactions[0].commit.committed_at;
    Box::pin(human_profile::admit(
        &pool,
        &unit.transactions[0].expected_authority.service_id,
        "bootstrap-actor",
    ))
    .await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    store
        .admit_ordinary_realm_bootstrap_unit(&unit, at)
        .await
        .unwrap();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let strand = strand_create_request(&unit);
    let strand = Box::pin(source_if_human(&pool, strand)).await;
    uow.commit_event(strand.clone()).await.unwrap();
    let actor = creator_account(&unit);
    let mut head = Box::pin(invite_grant_request(
        &pool,
        &strand,
        &unit,
        unit.transactions[0].event.event_id.as_str(),
        &actor,
        &["ak.realm.archive", "ak.realm.freeze"],
    ))
    .await;
    uow.commit_event(head.clone()).await.unwrap();
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
        head = Box::pin(source_if_human(&pool, head)).await;
        uow.commit_event(head.clone()).await.unwrap();
        let blocked = realm_event_request_as(
            &head,
            &actor,
            arkret_wire::EventKind::RealmProfile,
            serde_json::json!({"schema":"ak.schema.realm_profile.v1","title":"blocked ordinary write"}),
        );
        let blocked = Box::pin(source_if_human(&pool, blocked)).await;
        let before_refusal = terminal_persistent_rows(&pool).await;
        let error = uow.commit_event(blocked.clone()).await.unwrap_err();
        assert_eq!(terminal_persistent_rows(&pool).await, before_refusal);
        assert!(error.to_string().contains("realm_frozen"), "{error}");
        assert_eq!(
            event_row_count(&pool, blocked.authority_commit.event.event_id.as_str()).await,
            0
        );
        head = realm_event_request_as(&head, &actor, reopen, serde_json::json!({}));
        head = Box::pin(source_if_human(&pool, head)).await;
        uow.commit_event(head.clone()).await.unwrap();
        let material = store
            .realm_state_snapshot_material(&head.authority_commit.event.realm_id)
            .await
            .unwrap()
            .unwrap();
        assert!(material.current_state_entries.iter().any(|entry| matches!(entry,
            arkret_wire::TypedCurrentRow::Value { selector: actual, revision, value, .. }
            if actual == &selector && revision.commit_id == head.authority_commit.commit.commit_id
                && value.get(field) == Some(&serde_json::Value::Bool(false))
        )));
        head = realm_event_request_as(
            &head,
            &actor,
            arkret_wire::EventKind::RealmProfile,
            serde_json::json!({"schema":"ak.schema.realm_profile.v1","title":format!("reopened after {field}")}),
        );
        head = Box::pin(source_if_human(&pool, head)).await;
        uow.commit_event(head.clone()).await.unwrap();
    }
}

#[tokio::test]
async fn tombstone_commits_current_and_fences_fresh_writes_without_destroy_bypass() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let unit = Box::pin(unit_with_plaintext_service(&pool)).await;
    let at = unit.transactions[0].commit.committed_at;
    Box::pin(human_profile::admit(
        &pool,
        &unit.transactions[0].expected_authority.service_id,
        "bootstrap-actor",
    ))
    .await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    store
        .admit_ordinary_realm_bootstrap_unit(&unit, at)
        .await
        .unwrap();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let strand = strand_create_request(&unit);
    let strand = Box::pin(source_if_human(&pool, strand)).await;
    uow.commit_event(strand.clone()).await.unwrap();
    let actor = creator_account(&unit);
    let grant = Box::pin(invite_grant_request(
        &pool,
        &strand,
        &unit,
        unit.transactions[0].event.event_id.as_str(),
        &actor,
        &["ak.realm.archive", "ak.realm.freeze"],
    ))
    .await;
    uow.commit_event(grant.clone()).await.unwrap();
    let strand = grant;
    let realm = strand.authority_commit.event.realm_id.clone();
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
        let request = realm_event_request_as(&strand, &actor, kind, payload);
        let request = Box::pin(source_if_human(&pool, request)).await;
        let error = uow.commit_event(request.clone()).await.unwrap_err();
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
    let terminal = Box::pin(source_if_human(&pool, terminal)).await;
    uow.commit_event(terminal.clone()).await.unwrap();
    let material = store
        .realm_state_snapshot_material(&realm)
        .await
        .unwrap()
        .unwrap();
    assert!(material.current_state_entries.iter().any(|entry| matches!(entry,
        arkret_wire::TypedCurrentRow::Value {selector: arkret_wire::CurrentSelector::RealmTombstone, revision, value, ..}
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
        arkret_wire::TypedCurrentRow::Value {
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
    ] {
        let request = realm_event_request_as(&terminal, &actor, kind, payload);
        let request = Box::pin(source_if_human(&pool, request)).await;
        let error = uow.commit_event(request.clone()).await.unwrap_err();
        assert!(error.to_string().contains("failed_precondition"), "{error}");
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
        !uow.commit_event(terminal.clone())
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
