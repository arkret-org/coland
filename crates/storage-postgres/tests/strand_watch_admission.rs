//! Whole-value self watch CAS, durable read and rollback through the production UOW.
#[path = "support/ordinary_realm.rs"]
#[allow(dead_code)]
mod ordinary_realm;
use arkret_models_collaboration::strand_watch_operations::{
    StrandWatchCurrentOutcome, StrandWatchCurrentRequestBody,
};
use coland_storage::{
    AuthorityCommitStore, EventCommitRequest, EventCommitUnitOfWork, SelfExactCurrentRead,
};
use coland_storage_postgres::test_database::TestDatabase;
use coland_storage_postgres::{PgAuthorityCommitStore, PgEventCommitUnitOfWork, PgPool};
use diesel::sql_types::{Jsonb, Text};
use diesel_async::{RunQueryDsl, SimpleAsyncConnection};
use serde_json::{Value, json};

#[derive(diesel::QueryableByName)]
struct Footprint {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}
async fn footprint(pool: &PgPool) -> Value {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT jsonb_build_object('events',(SELECT count(*) FROM canonical_events),'commits',(SELECT count(*) FROM realm_commits),'watches',(SELECT count(*) FROM strand_watch_current_results),'outbox',(SELECT count(*) FROM federation_outbox)) AS value")
        .get_result::<Footprint>(&mut *conn).await.unwrap().value
}
async fn write(
    pool: &PgPool,
    discussion: &ordinary_realm::Discussion,
    previous: &coland_storage::AuthorityCommitTransaction,
    level: Value,
    public: Option<bool>,
    expected: Option<Value>,
    offset: i64,
) -> EventCommitRequest {
    let mut payload = json!({"strand_id":discussion.strand_id,"watcher_actor_id":discussion.head.authority_commit.event.actor_id,"level":level});
    if let Some(public) = public {
        payload["level_public"] = json!(public);
    }
    if let Some(expected) = expected {
        payload["expected_value"] = expected;
    }
    let request = ordinary_realm::next_request(
        previous,
        arkret_wire::EventKind::StrandWatchSet,
        discussion
            .head
            .authority_commit
            .event
            .actor_id
            .signing_principal_id(),
        payload,
        discussion.committed_at() + chrono::Duration::seconds(offset),
    );
    Box::pin(ordinary_realm::source_request(pool, request)).await
}
fn read_request(discussion: &ordinary_realm::Discussion) -> StrandWatchCurrentRequestBody {
    StrandWatchCurrentRequestBody {
        realm_id: discussion.realm_id(),
        strand_id: discussion.strand_id.clone(),
        watcher_actor_id: discussion.head.authority_commit.event.actor_id.clone(),
    }
}
async fn read(
    pool: &PgPool,
    discussion: &ordinary_realm::Discussion,
) -> SelfExactCurrentRead<StrandWatchCurrentOutcome> {
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let account = discussion
        .head
        .authority_commit
        .event
        .actor_id
        .as_account_id()
        .unwrap();
    store
        .strand_watch_current_for_account(
            &read_request(discussion),
            account,
            &ordinary_realm::station(),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn realm_watch_current_remains_provable_after_private_sidecar_history() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let discussion = ordinary_realm::open_human_discussion(&pool, "watch-with-sidecar").await;
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let previous = &discussion.head.authority_commit;
    let create = ordinary_realm::next_request(
        previous,
        arkret_wire::EventKind::SidecarCreate,
        previous.event.actor_id.signing_principal_id(),
        json!({}),
        discussion.committed_at(),
    );
    let create = Box::pin(ordinary_realm::source_request(&pool, create)).await;
    uow.commit_event(create.clone()).await.unwrap();
    let sidecar = arkret_wire::SidecarId::from_event_id(&create.authority_commit.event.event_id);
    let scope = arkret_wire::ScopeRef::Sidecar {
        realm_id: discussion.realm_id(),
        sidecar_id: sidecar.clone(),
    };
    let mut event = ordinary_realm::event_for_actor(
        arkret_wire::EventKind::SidecarContextAttach,
        scope.clone(),
        previous.event.actor_id.clone(),
        json!({"sidecar_id":sidecar,"source_context_ref":{"kind":"strand","strand_id":discussion.strand_id},"version":1}),
        discussion.committed_at(),
    );
    event.semantic_refs = vec![arkret_wire::SemanticRef::new(
        create.authority_commit.event.event_id.to_string(),
        "after",
    )];
    ordinary_realm::reseal(&mut event);
    let mut attach = ordinary_realm::request_for_event(
        &create.authority_commit,
        event,
        discussion.committed_at(),
    );
    attach.authority_commit.commit.stream_ref = arkret_wire::CommitStreamRef::Sidecar {
        realm_id: discussion.realm_id(),
        sidecar_id: sidecar,
    };
    attach.authority_commit.commit.stream_position = 0;
    attach.authority_commit.commit.previous_commit_ref = None;
    let attach = Box::pin(ordinary_realm::source_request(&pool, attach)).await;
    uow.commit_event(attach).await.unwrap();
    assert!(matches!(
        read(&pool, &discussion).await,
        SelfExactCurrentRead::Answer(StrandWatchCurrentOutcome::NeverWritten { .. })
    ));
    let watch = ordinary_realm::next_request(
        &create.authority_commit,
        arkret_wire::EventKind::StrandWatchSet,
        previous.event.actor_id.signing_principal_id(),
        json!({"strand_id":discussion.strand_id,"watcher_actor_id":previous.event.actor_id,"level":"all"}),
        discussion.committed_at() + chrono::Duration::seconds(30),
    );
    let watch = Box::pin(ordinary_realm::source_request(&pool, watch)).await;
    uow.commit_event(watch).await.unwrap();
    assert!(matches!(
        read(&pool, &discussion).await,
        SelfExactCurrentRead::Answer(StrandWatchCurrentOutcome::Current { .. })
    ));
}

#[tokio::test]
async fn current_read_distinguishes_never_written_cleared_and_complete_cas() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let discussion = ordinary_realm::open_discussion(&pool, "watch-cas").await;
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    assert!(matches!(
        read(&pool, &discussion).await,
        SelfExactCurrentRead::Answer(StrandWatchCurrentOutcome::NeverWritten { .. })
    ));
    let first = write(
        &pool,
        &discussion,
        &discussion.head.authority_commit,
        json!("all"),
        Some(true),
        None,
        30,
    )
    .await;
    uow.commit_event(first.clone()).await.unwrap();
    let baseline = footprint(&pool).await;
    uow.commit_event(first.clone()).await.unwrap();
    assert_eq!(
        footprint(&pool).await,
        baseline,
        "exact retry does not write a second preference"
    );
    for expected in [
        None,
        Some(json!({"level":"all"})),
        Some(json!({"level":"all","level_public":false})),
    ] {
        let refused = write(
            &pool,
            &discussion,
            &first.authority_commit,
            json!("muted"),
            None,
            expected,
            31,
        )
        .await;
        let error = uow.commit_event(refused).await.unwrap_err();
        assert_eq!(
            error.conflict_code(),
            Some(coland_storage::ConflictCode::FailedPrecondition)
        );
        assert_eq!(footprint(&pool).await, baseline);
    }
    let clear = write(
        &pool,
        &discussion,
        &first.authority_commit,
        Value::Null,
        None,
        Some(json!({"level":"all","level_public":true})),
        32,
    )
    .await;
    uow.commit_event(clear.clone()).await.unwrap();
    let SelfExactCurrentRead::Answer(StrandWatchCurrentOutcome::Current { result, .. }) =
        read(&pool, &discussion).await
    else {
        panic!("clear must retain a current revision")
    };
    assert_eq!(serde_json::to_value(result.value).unwrap(), Value::Null);
    assert_eq!(
        result.revision.commit_id,
        clear.authority_commit.commit.commit_id
    );
    let baseline = footprint(&pool).await;
    assert!(
        uow.commit_event(
            write(
                &pool,
                &discussion,
                &clear.authority_commit,
                json!("all"),
                None,
                None,
                33
            )
            .await
        )
        .await
        .is_err()
    );
    assert_eq!(footprint(&pool).await, baseline);
    let restore = write(
        &pool,
        &discussion,
        &clear.authority_commit,
        json!("participating"),
        None,
        Some(Value::Null),
        34,
    )
    .await;
    uow.commit_event(restore.clone()).await.unwrap();
    let SelfExactCurrentRead::Answer(StrandWatchCurrentOutcome::Current { result, .. }) =
        read(&pool, &discussion).await
    else {
        panic!("a fresh storage adapter must reopen the durable row")
    };
    assert_eq!(
        serde_json::to_value(result.value).unwrap(),
        json!({"level":"participating"})
    );
    assert_eq!(
        result.revision.commit_id,
        restore.authority_commit.commit.commit_id
    );
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("DELETE FROM strand_watch_current_results WHERE realm_id=$1")
        .bind::<Text, _>(discussion.realm_id().as_str())
        .execute(&mut *conn)
        .await
        .unwrap();
    drop(conn);
    assert!(
        matches!(
            read(&pool, &discussion).await,
            SelfExactCurrentRead::Unresolved(_)
        ),
        "lost materialization cannot become never_written"
    );
    let baseline = footprint(&pool).await;
    let result = uow
        .commit_event(
            write(
                &pool,
                &discussion,
                &restore.authority_commit,
                json!("all"),
                None,
                None,
                35,
            )
            .await,
        )
        .await
        .unwrap_err();
    assert!(result.to_string().contains("revision_unavailable"));
    assert_eq!(
        footprint(&pool).await,
        baseline,
        "a producer cannot bypass lost current by omitting its CAS"
    );
}

#[tokio::test]
async fn unproved_tenure_import_cannot_treat_missing_watch_as_never_written() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let discussion = ordinary_realm::open_discussion(&pool, "watch-import").await;
    let mut previous = discussion.head.authority_commit.clone();
    // This fault fixture represents an incomplete imported tenure. It is not
    // evidence of a formally accepted handoff: only the accepting storage cut
    // is advanced, while no watch current or never-written import proof exists.
    let handoff_id = arkret_wire::RealmAuthorityHandoffId::from_digest([0x67; 32]);
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "UPDATE realm_authorities SET generation=1,last_handoff_ref=$2 WHERE realm_id=$1",
    )
    .bind::<Text, _>(discussion.realm_id().as_str())
    .bind::<Text, _>(handoff_id.as_str())
    .execute(&mut *conn)
    .await
    .unwrap();
    drop(conn);
    previous.expected_authority.generation = 1;
    previous.expected_authority.last_handoff_ref = Some(handoff_id);
    let request = write(&pool, &discussion, &previous, json!("all"), None, None, 30).await;
    assert_eq!(request.authority_commit.commit.governance_generation, 1);
    assert!(matches!(
        read(&pool, &discussion).await,
        SelfExactCurrentRead::Unresolved(_)
    ));
    let baseline = footprint(&pool).await;
    let error = PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event(request)
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("watch never-written state has no confirmed tenure import")
    );
    assert_eq!(footprint(&pool).await, baseline);
}

#[tokio::test]
async fn watch_projection_fault_rolls_back_event_commit_and_outbox() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let discussion = ordinary_realm::open_discussion(&pool, "watch-fault").await;
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let baseline = footprint(&pool).await;
    let mut conn = pool.get().await.unwrap();
    conn.batch_execute("CREATE FUNCTION watch_projection_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'watch projection fault'; END $$; CREATE TRIGGER watch_projection_fault BEFORE INSERT ON strand_watch_current_results FOR EACH ROW EXECUTE FUNCTION watch_projection_fault();").await.unwrap();
    drop(conn);
    let request = write(
        &pool,
        &discussion,
        &discussion.head.authority_commit,
        json!("all"),
        None,
        None,
        30,
    )
    .await;
    let result = uow.commit_event(request.clone()).await;
    let mut conn = pool.get().await.unwrap();
    conn.batch_execute("DROP TRIGGER watch_projection_fault ON strand_watch_current_results; DROP FUNCTION watch_projection_fault();").await.unwrap();
    drop(conn);
    assert!(result.is_err());
    assert_eq!(footprint(&pool).await, baseline);
    uow.commit_event(request).await.unwrap();
    assert!(matches!(
        read(&pool, &discussion).await,
        SelfExactCurrentRead::Answer(StrandWatchCurrentOutcome::Current { .. })
    ));
}

fn scoped_request(
    previous: &coland_storage::AuthorityCommitTransaction,
    scope: arkret_wire::ScopeRef,
    kind: arkret_wire::EventKind,
    payload: Value,
    at: chrono::DateTime<chrono::Utc>,
) -> EventCommitRequest {
    let event = ordinary_realm::event_for_actor(
        kind,
        scope.clone(),
        previous.event.actor_id.clone(),
        payload,
        at,
    );
    let stream = arkret_wire::CommitStreamRef::from_scope(&scope, None).unwrap();
    let mut request = ordinary_realm::request_for_event(previous, event, at);
    if previous.commit.stream_ref != stream {
        request.authority_commit.commit.stream_position = 0;
        request.authority_commit.commit.previous_commit_ref = None;
    }
    request.authority_commit.commit.stream_ref = stream;
    request
}

#[tokio::test]
async fn circle_watch_uses_its_exact_namespace_and_loses_disclosure_on_circle_leave() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let discussion = Box::pin(ordinary_realm::open_human_discussion(&pool, "circle-watch")).await;
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let realm = discussion.realm_id();
    let actor = discussion.head.authority_commit.event.actor_id.clone();
    let at = discussion.committed_at() + chrono::Duration::seconds(20);
    let create = ordinary_realm::next_request_for_actor(
        &discussion.head.authority_commit,
        arkret_wire::EventKind::CircleCreate,
        actor.clone(),
        json!({"object":{
            "schema":"ak.schema.circle.v1","realm_id":realm,"title":"Private Watch",
            "display":{"short_name":"Watch","color_token":"blue","symbol":{"glyph":"lock"}},
            "directory_visibility":"members","join_rule":"public","history_access":"since_join",
            "state":"active","created_by":actor,"created_at":arkret_canonical::format_timestamp_canonical(at)
        }}),
        at,
    );
    let create = Box::pin(ordinary_realm::source_request(&pool, create)).await;
    uow.commit_event(create.clone()).await.unwrap();
    let circle = arkret_wire::CircleId::from_event_id(&create.authority_commit.event.event_id);
    let scope = arkret_wire::ScopeRef::Circle {
        realm_id: realm.clone(),
        circle_id: circle.clone(),
    };
    let parent = ordinary_realm::parent_membership_revision(&pool, &realm, &actor).await;
    let join = scoped_request(
        &create.authority_commit,
        scope.clone(),
        arkret_wire::EventKind::CircleMemberState,
        json!({"circle_id":circle,"member_id":actor,"membership":"join","expected_membership":null,"parent_membership_revision":parent}),
        at,
    );
    let join = Box::pin(ordinary_realm::source_request(&pool, join)).await;
    uow.commit_event(join.clone()).await.unwrap();
    let strand = scoped_request(
        &join.authority_commit,
        scope.clone(),
        arkret_wire::EventKind::StrandCreate,
        json!({"object":{"schema":"ak.schema.strand.v1","realm_id":realm,"scope_circle_id":circle,
        "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},"metadata":{"title":"Circle Watch"},
        "state":"active","created_by":actor,"created_at":arkret_canonical::format_timestamp_canonical(at)}}),
        at,
    );
    let strand = Box::pin(ordinary_realm::source_request(&pool, strand)).await;
    uow.commit_event(strand.clone()).await.unwrap();
    let strand_id = arkret_wire::StrandId::from_event_id(&strand.authority_commit.event.event_id);
    let request = StrandWatchCurrentRequestBody {
        realm_id: realm.clone(),
        strand_id: strand_id.clone(),
        watcher_actor_id: actor.clone(),
    };
    let account = actor.as_account_id().unwrap();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let first_read = store
        .strand_watch_current_for_account(&request, account, &ordinary_realm::station())
        .await
        .unwrap();
    let SelfExactCurrentRead::Answer(StrandWatchCurrentOutcome::NeverWritten {
        stream_head, ..
    }) = first_read
    else {
        panic!("complete Circle namespace proves never-written");
    };
    assert_eq!(
        stream_head.stream_ref,
        strand.authority_commit.commit.stream_ref
    );
    let watch = scoped_request(
        &strand.authority_commit,
        scope.clone(),
        arkret_wire::EventKind::StrandWatchSet,
        json!({"strand_id":strand_id,"watcher_actor_id":actor,"level":"all","level_public":true}),
        at + chrono::Duration::seconds(1),
    );
    let watch = Box::pin(ordinary_realm::source_request(&pool, watch)).await;
    uow.commit_event(watch.clone()).await.unwrap();
    let baseline = footprint(&pool).await;
    let losing = scoped_request(
        &watch.authority_commit,
        scope.clone(),
        arkret_wire::EventKind::StrandWatchSet,
        json!({"strand_id":strand_id,"watcher_actor_id":actor,"level":"muted","expected_value":{"level":"all"}}),
        at + chrono::Duration::seconds(2),
    );
    let losing = Box::pin(ordinary_realm::source_request(&pool, losing)).await;
    assert_eq!(
        uow.commit_event(losing).await.unwrap_err().conflict_code(),
        Some(coland_storage::ConflictCode::FailedPrecondition)
    );
    assert_eq!(footprint(&pool).await, baseline);
    let clear = scoped_request(
        &watch.authority_commit,
        scope.clone(),
        arkret_wire::EventKind::StrandWatchSet,
        json!({"strand_id":strand_id,"watcher_actor_id":actor,"level":null,"expected_value":{"level":"all","level_public":true}}),
        at + chrono::Duration::seconds(3),
    );
    let clear = Box::pin(ordinary_realm::source_request(&pool, clear)).await;
    uow.commit_event(clear.clone()).await.unwrap();
    let SelfExactCurrentRead::Answer(StrandWatchCurrentOutcome::Current {
        result,
        stream_head,
        ..
    }) = store
        .strand_watch_current_for_account(&request, account, &ordinary_realm::station())
        .await
        .unwrap()
    else {
        panic!("Circle clear retains its revision");
    };
    assert_eq!(result.source_stream_ref, stream_head.stream_ref);
    assert_eq!(
        result.revision.commit_id,
        clear.authority_commit.commit.commit_id
    );
    assert_eq!(serde_json::to_value(result.value).unwrap(), Value::Null);
    let snapshot = store
        .realm_state_snapshot_material_for_account(&realm, account)
        .await
        .unwrap()
        .unwrap();
    assert!(snapshot.current_state_entries.iter().any(|row| matches!(row,
        arkret_wire::TypedCurrentRow::Value {
            selector: arkret_wire::CurrentSelector::StrandWatch { strand_id: id, watcher_actor_id },
            source_stream_ref, value, ..
        } if id == &strand_id && watcher_actor_id == &actor
            && source_stream_ref == &clear.authority_commit.commit.stream_ref && value.is_null()
    )));
    let leave = scoped_request(
        &clear.authority_commit,
        scope,
        arkret_wire::EventKind::CircleMemberState,
        json!({"circle_id":circle,"member_id":actor,"membership":"leave","expected_membership":"join"}),
        at + chrono::Duration::seconds(4),
    );
    let leave = Box::pin(ordinary_realm::source_request(&pool, leave)).await;
    uow.commit_event(leave).await.unwrap();
    assert!(matches!(
        store
            .strand_watch_current_for_account(&request, account, &ordinary_realm::station())
            .await
            .unwrap(),
        SelfExactCurrentRead::NotFound
    ));
}

#[tokio::test]
async fn original_author_does_not_replace_the_full_watcher_selector_when_current_is_lost() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let discussion = Box::pin(ordinary_realm::open_human_discussion(&pool, "watch-source")).await;
    let author = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new("ak:did_core:web:imported-watch-writer.example").unwrap(),
        ordinary_realm::station(),
    ));
    let event = ordinary_realm::event_for_actor(
        arkret_wire::EventKind::StrandWatchSet,
        arkret_wire::ScopeRef::Realm {
            realm_id: discussion.realm_id(),
        },
        author,
        json!({"strand_id":discussion.strand_id,"watcher_actor_id":discussion.head.authority_commit.event.actor_id,"level":"all"}),
        discussion.committed_at() + chrono::Duration::seconds(30),
    );
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    store
        .queue_event(&event, discussion.committed_at())
        .await
        .unwrap();
    // Fault injection models imported history without a covering Commit or
    // current. It never claims an accepted .others production positive.
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "UPDATE canonical_events SET state='committed',committed_at=now() WHERE envelope->>'event_id'=$1",
    )
    .bind::<Text, _>(event.event_id.as_str())
    .execute(&mut *conn)
    .await
    .unwrap();
    drop(conn);
    assert!(matches!(
        read(&pool, &discussion).await,
        SelfExactCurrentRead::Unresolved(_)
    ));
}

#[tokio::test]
async fn remote_watch_delivery_uses_the_verified_peer_cut_without_local_reducer_material() {
    use coland_storage::AccountContentDeliveryInput;
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let _local_identity = Box::pin(ordinary_realm::open_human_discussion(
        &pool,
        "watch-delivery-station",
    ))
    .await;
    let local = ordinary_realm::station();
    let fixture = ordinary_realm::human_profile::fixture(&local, "watch-delivery");
    let device = Box::pin(fixture.admit_founding_device(
        &coland_storage_postgres::PgPersistenceStore::new(pool.clone()),
    ))
    .await
    .unwrap();
    let account = fixture.history.account.clone();
    let foreign = arkret_wire::DidCoreId::new("ak:did_core:web:watch-governor.example").unwrap();
    let realm = arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [53; 32],
    ));
    let strand = arkret_wire::StrandId::from_event_id(&arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [54; 32],
    ));
    let request = StrandWatchCurrentRequestBody {
        realm_id: realm.clone(),
        strand_id: strand.clone(),
        watcher_actor_id: arkret_wire::ActorId::account(account.clone()),
    };
    // This contract test injects an already authenticated read witness at the
    // production storage port; it does not claim real S2S authentication.
    let outcome = StrandWatchCurrentOutcome::NeverWritten {
        realm_id: realm.clone(), governance_generation: 4,
        stream_head: arkret_wire::CommitStreamHead {
            stream_ref: arkret_wire::CommitStreamRef::Realm { realm_id: realm.clone() },
            commit_id: arkret_wire::RealmCommitId::from_digest([55;32]), stream_position: 17,
        },
        selector: arkret_models_collaboration::strand_watch_operations::StrandWatchCurrentSelector {
            kind: arkret_models_collaboration::strand_watch_operations::StrandWatchSelectorKind::StrandWatch,
            strand_id: strand, watcher_actor_id: request.watcher_actor_id.clone(),
        },
    };
    let authority = coland_storage::CurrentRealmAuthority {
        realm_id: realm.clone(),
        generation: 4,
        service_id: foreign,
        authority_ref: arkret_wire::RealmCommitAuthorityRef::Handoff(
            arkret_wire::RealmAuthorityHandoffId::from_digest([56; 32]),
        ),
        last_handoff_ref: Some(arkret_wire::RealmAuthorityHandoffId::from_digest([56; 32])),
    };
    let expires_at = chrono::DateTime::from_timestamp_millis(
        (chrono::Utc::now() + chrono::Duration::minutes(1)).timestamp_millis(),
    )
    .unwrap();
    #[derive(diesel::QueryableByName)]
    struct LocalAccount {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        pk: i64,
    }
    let mut conn = pool.get().await.unwrap();
    let account_pk = diesel::sql_query(
        "INSERT INTO accounts (principal_id,station_id) VALUES ($1,$2) RETURNING pk",
    )
    .bind::<Text, _>(account.principal_id.as_str())
    .bind::<Text, _>(local.as_str())
    .get_result::<LocalAccount>(&mut *conn)
    .await
    .unwrap()
    .pk;
    diesel::sql_query("INSERT INTO sessions (id,account_pk,actor_id,device_id,audience,expires_at) VALUES ($1,$2,$3,$4,$5,$6)")
        .bind::<Text, _>("watch-live-session")
        .bind::<diesel::sql_types::BigInt, _>(account_pk)
        .bind::<Text, _>(account.principal_id.as_str())
        .bind::<Text, _>(&device.device_id)
        .bind::<Text, _>(local.as_str())
        .bind::<diesel::sql_types::Timestamptz, _>(expires_at)
        .execute(&mut *conn).await.unwrap();
    drop(conn);
    let input = AccountContentDeliveryInput {
        remote_watch_read: Some((request, outcome, authority)),
        watch_delivery_device: Some(device.clone()),
        watch_local_session: Some((
            "watch-live-session".to_owned(),
            coland_storage::AccountPk(account_pk),
        )),
        credential_expires_at: Some(expires_at),
        ..Default::default()
    };
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let baseline = footprint(&pool).await;
    let guard = store
        .acquire_committed_content_delivery(&account, &local, &input)
        .await
        .unwrap()
        .expect("remote Watch keeps its local final guard");
    assert!(guard.permits_handoff());
    guard.finish().await.unwrap();
    assert_eq!(footprint(&pool).await, baseline);
    for branch in [
        "expired",
        "device_replaced",
        "other_account",
        "unverified_generation",
        "withdrawn_local_session",
    ] {
        let mut rejected = input.clone();
        match branch {
            "expired" => {
                rejected.credential_expires_at =
                    Some(chrono::Utc::now() - chrono::Duration::seconds(1))
            }
            "device_replaced" => {
                rejected
                    .watch_delivery_device
                    .as_mut()
                    .unwrap()
                    .authorization_ref
                    .commit_id = arkret_wire::RealmCommitId::from_digest([57; 32])
            }
            "other_account" => {
                rejected
                    .remote_watch_read
                    .as_mut()
                    .unwrap()
                    .0
                    .watcher_actor_id = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                    account.principal_id.clone(),
                    arkret_wire::DidCoreId::new("ak:did_core:web:other-account-station.example")
                        .unwrap(),
                ))
            }
            "unverified_generation" => {
                rejected.remote_watch_read.as_mut().unwrap().2.generation += 1
            }
            "withdrawn_local_session" => {
                rejected.watch_local_session = Some((
                    "withdrawn-watch-session".to_owned(),
                    coland_storage::AccountPk(1),
                ));
            }
            _ => unreachable!(),
        }
        assert!(
            store
                .acquire_committed_content_delivery(&account, &local, &rejected)
                .await
                .is_err(),
            "{branch}"
        );
        assert_eq!(footprint(&pool).await, baseline, "{branch} is read-only");
    }
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("UPDATE sessions SET revoked_at=now() WHERE id=$1")
        .bind::<Text, _>("watch-live-session")
        .execute(&mut *conn)
        .await
        .unwrap();
    drop(conn);
    assert!(
        store
            .acquire_committed_content_delivery(&account, &local, &input)
            .await
            .is_err()
    );
    assert_eq!(footprint(&pool).await, baseline);
}

#[tokio::test]
async fn a_missing_original_in_the_effective_namespace_never_proves_never_written() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let discussion = Box::pin(ordinary_realm::open_human_discussion(
        &pool,
        "watch-incomplete-chain",
    ))
    .await;
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "UPDATE realm_commits SET event_pk=NULL WHERE realm_id=$1 AND stream_position=0",
    )
    .bind::<Text, _>(discussion.realm_id().as_str())
    .execute(&mut *conn)
    .await
    .unwrap();
    drop(conn);
    assert!(matches!(
        read(&pool, &discussion).await,
        SelfExactCurrentRead::Unresolved(_)
    ));
}

#[tokio::test]
async fn circle_self_knock_and_cancel_have_durable_current_without_join_access() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let discussion = Box::pin(ordinary_realm::open_human_discussion(
        &pool,
        "circle-knock-current",
    ))
    .await;
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let realm = discussion.realm_id();
    let actor = discussion.head.authority_commit.event.actor_id.clone();
    let at = discussion.committed_at() + chrono::Duration::seconds(20);
    let create = ordinary_realm::next_request_for_actor(
        &discussion.head.authority_commit,
        arkret_wire::EventKind::CircleCreate,
        actor.clone(),
        json!({"object":{
            "schema":"ak.schema.circle.v1","realm_id":realm,"title":"Knock Current",
            "display":{"short_name":"Knock","color_token":"blue","symbol":{"glyph":"lock"}},
            "directory_visibility":"members","join_rule":"knock","history_access":"since_join",
            "state":"active","created_by":actor,"created_at":arkret_canonical::format_timestamp_canonical(at)
        }}),
        at,
    );
    let create = Box::pin(ordinary_realm::source_request(&pool, create)).await;
    uow.commit_event(create.clone()).await.unwrap();
    let circle = arkret_wire::CircleId::from_event_id(&create.authority_commit.event.event_id);
    let scope = arkret_wire::ScopeRef::Circle {
        realm_id: realm,
        circle_id: circle.clone(),
    };
    let knock = scoped_request(
        &create.authority_commit,
        scope.clone(),
        arkret_wire::EventKind::CircleMemberState,
        json!({"circle_id":circle,"member_id":actor,"membership":"knock","expected_membership":null}),
        at + chrono::Duration::seconds(1),
    );
    let knock = Box::pin(ordinary_realm::source_request(&pool, knock)).await;
    uow.commit_event(knock.clone()).await.unwrap();
    let mut conn = pool.get().await.unwrap();
    #[derive(diesel::QueryableByName)]
    struct Member {
        #[diesel(sql_type=Text)]
        membership: String,
        #[diesel(sql_type=Text)]
        current_commit_id: String,
        #[diesel(sql_type=diesel::sql_types::Bool)]
        effective: bool,
    }
    let current = diesel::sql_query("SELECT membership,current_commit_id,circle_member_parent_join_current(realm_id,member_id,value) AS effective FROM circle_member_state_current_results WHERE circle_id=$1 AND member_id=$2")
        .bind::<Text,_>(circle.as_str()).bind::<Text,_>(actor.to_string()).get_result::<Member>(&mut *conn).await.unwrap();
    assert_eq!(current.membership, "knock");
    assert_eq!(
        current.current_commit_id,
        knock.authority_commit.commit.commit_id.as_str()
    );
    assert!(
        !current.effective,
        "knock cannot substitute for joined membership"
    );
    drop(conn);
    let baseline = footprint(&pool).await;
    let stale = scoped_request(
        &knock.authority_commit,
        scope.clone(),
        arkret_wire::EventKind::CircleMemberState,
        json!({"circle_id":circle,"member_id":actor,"membership":"leave","expected_membership":null}),
        at + chrono::Duration::seconds(2),
    );
    let stale = Box::pin(ordinary_realm::source_request(&pool, stale)).await;
    assert_eq!(
        uow.commit_event(stale).await.unwrap_err().conflict_code(),
        Some(coland_storage::ConflictCode::FailedPrecondition)
    );
    assert_eq!(footprint(&pool).await, baseline);
    let cancel = scoped_request(
        &knock.authority_commit,
        scope,
        arkret_wire::EventKind::CircleMemberState,
        json!({"circle_id":circle,"member_id":actor,"membership":"leave","expected_membership":"knock"}),
        at + chrono::Duration::seconds(3),
    );
    let cancel = Box::pin(ordinary_realm::source_request(&pool, cancel)).await;
    uow.commit_event(cancel.clone()).await.unwrap();
    let mut conn = pool.get().await.unwrap();
    let current = diesel::sql_query("SELECT membership,current_commit_id,circle_member_parent_join_current(realm_id,member_id,value) AS effective FROM circle_member_state_current_results WHERE circle_id=$1 AND member_id=$2")
        .bind::<Text,_>(circle.as_str()).bind::<Text,_>(actor.to_string()).get_result::<Member>(&mut *conn).await.unwrap();
    assert_eq!(current.membership, "leave");
    assert_eq!(
        current.current_commit_id,
        cancel.authority_commit.commit.commit_id.as_str()
    );
    assert!(!current.effective);
}
