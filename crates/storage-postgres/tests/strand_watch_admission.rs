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
