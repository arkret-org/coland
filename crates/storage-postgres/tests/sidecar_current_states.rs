//! Native Sidecar genesis current is accepted with its RealmCommit, under
//! the same private singleton reservation at the owner Station.

#[path = "support/ordinary_realm.rs"]
#[expect(
    dead_code,
    reason = "This integration binary uses only its subset of the shared Realm fixture."
)]
mod ordinary_realm;

use std::future::Future;
use std::pin::Pin;

use coland_storage::{
    AuthorityCommitStore, ConflictCode, EventBatchCommitRequest, EventCommitRequest,
    EventCommitUnitOfWork,
};
use coland_storage_postgres::test_database::TestDatabase;
use coland_storage_postgres::{PgAuthorityCommitStore, PgEventCommitUnitOfWork};
use diesel::sql_types::{BigInt, Jsonb, Text};
use diesel_async::RunQueryDsl;
use ordinary_realm::next_request;

// Keep large shared fixture futures out of their caller's poll frame.
#[inline(never)]
fn heap_future<'a, T: 'a, F: Future<Output = T> + 'a>(
    make: impl FnOnce() -> F,
) -> Pin<Box<dyn Future<Output = T> + 'a>> {
    Box::pin(make())
}

#[derive(diesel::QueryableByName)]
struct SidecarRow {
    #[diesel(sql_type = Text)]
    sidecar_id: String,
    #[diesel(sql_type = Jsonb)]
    controller_account_id: serde_json::Value,
    #[diesel(sql_type = Text)]
    create_event_id: String,
    #[diesel(sql_type = Text)]
    current_commit_id: String,
    #[diesel(sql_type = BigInt)]
    current_stream_position: i64,
    #[diesel(sql_type = Jsonb)]
    value: serde_json::Value,
}

async fn rows(pool: &coland_storage_postgres::PgPool) -> Vec<SidecarRow> {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "SELECT sidecar_id,controller_account_id,create_event_id,current_commit_id,current_stream_position,value \
         FROM sidecar_current_states ORDER BY sidecar_id",
    )
    .load::<SidecarRow>(&mut *conn)
    .await
    .unwrap()
}

#[derive(diesel::QueryableByName)]
struct ContextRow {
    #[diesel(sql_type = Text)]
    sidecar_id: String,
    #[diesel(sql_type = Jsonb)]
    context_ref: serde_json::Value,
    #[diesel(sql_type = BigInt)]
    version: i64,
    #[diesel(sql_type = Text)]
    attach_event_id: String,
    #[diesel(sql_type = Text)]
    current_commit_id: String,
    #[diesel(sql_type = Jsonb)]
    value: serde_json::Value,
}

async fn contexts(pool: &coland_storage_postgres::PgPool) -> Vec<ContextRow> {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "SELECT sidecar_id,context_ref,version,attach_event_id,current_commit_id,value \
         FROM sidecar_context_current_states ORDER BY sidecar_id,context_ref_digest",
    )
    .load::<ContextRow>(&mut *conn)
    .await
    .unwrap()
}

use ordinary_realm::{attach_request, private_create, sidecar_batch as batch};

#[tokio::test]
async fn sidecar_genesis_reserves_exact_controller_and_current_in_one_commit() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let controller = ordinary_realm::human_profile::admit(
        &pool,
        &ordinary_realm::station(),
        "sidecar-current-controller",
    )
    .await;
    let unit = ordinary_realm::bootstrap_unit_for_account(
        "sidecar-current",
        &controller,
        &ordinary_realm::human_profile::station_did(&ordinary_realm::station()),
    );
    let unit = ordinary_realm::source_bootstrap(&pool, unit).await;
    PgAuthorityCommitStore { pool: pool.clone() }
        .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let last = unit.transactions.last().unwrap();
    let at = last.commit.committed_at;
    let create = private_create(&pool, last, &controller).await;
    let create = ordinary_realm::source_pcr_request(&pool, create).await;
    uow.commit_event(create.clone()).await.unwrap();
    let stored = rows(&pool).await;
    assert_eq!(stored.len(), 1);
    let row = &stored[0];
    assert_eq!(
        row.sidecar_id,
        arkret_wire::SidecarId::from_event_id(&create.authority_commit.event.event_id).as_str()
    );
    assert_eq!(
        row.controller_account_id,
        serde_json::json!(
            create
                .authority_commit
                .event
                .actor_id
                .as_account_id()
                .unwrap()
        )
    );
    assert_eq!(
        row.create_event_id,
        create.authority_commit.event.event_id.as_str()
    );
    assert_eq!(
        row.current_commit_id,
        create.authority_commit.commit.commit_id.as_str()
    );
    assert_eq!(
        row.current_stream_position,
        create.authority_commit.commit.stream_position as i64
    );
    assert_eq!(row.value["id"], row.sidecar_id);
    assert_eq!(row.value["schema"], "ak.schema.agent_sidecar.v1");
    assert_eq!(
        row.value["realm_id"],
        create.authority_commit.event.realm_id.as_str()
    );
    assert_eq!(
        row.value["controller_account_id"],
        row.controller_account_id
    );
    assert_eq!(row.value["source_realm_id"], last.event.realm_id.as_str());
    assert_ne!(row.value["source_realm_id"], row.value["realm_id"]);
    assert_eq!(row.value["state"], "active");
    assert_eq!(row.value["created_at"], row.value["updated_at"]);

    let second = next_request(
        &create.authority_commit,
        arkret_wire::EventKind::SidecarCreate,
        &controller.principal_id,
        serde_json::json!({"source_realm_id": last.event.realm_id}),
        create.authority_commit.commit.committed_at + chrono::Duration::seconds(1),
    );
    let second = ordinary_realm::source_pcr_request(&pool, second).await;
    assert_ne!(second.authority_commit.event.event_id, create.authority_commit.event.event_id);
    let error = uow.commit_event(second.clone()).await.unwrap_err();
    assert_eq!(
        error.conflict_code(),
        Some(ConflictCode::FailedPrecondition)
    );
    assert_eq!(rows(&pool).await.len(), 1);
    assert!(
        PgAuthorityCommitStore { pool: pool.clone() }
            .committed_event(&second.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );

    // A service actor cannot become the controller by presenting a Realm
    // Event with the same syntactic kind. Refusal preserves the whole cut.
    let service = arkret_wire::ActorId::service(
        arkret_wire::DidCoreId::new("ak:did_core:web:sidecar-service.example").unwrap(),
    );
    let wrong_actor = ordinary_realm::next_request_for_actor(
        &create.authority_commit,
        arkret_wire::EventKind::SidecarCreate,
        service,
        serde_json::json!({"source_realm_id": last.event.realm_id}),
        at,
    );
    let error = uow.commit_event(wrong_actor.clone()).await.unwrap_err();
    assert_eq!(error.conflict_code(), Some(ConflictCode::CapabilityDenied));
    assert_eq!(rows(&pool).await.len(), 1);
    assert!(
        PgAuthorityCommitStore { pool: pool.clone() }
            .committed_event(&wrong_actor.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn sidecar_create_and_context_attach_commit_atomically_or_write_nothing() {
    heap_future(sidecar_create_and_context_attach_case).await;
}

async fn sidecar_create_and_context_attach_case() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let discussion =
        heap_future(|| ordinary_realm::open_human_discussion(&pool, "sidecar-attach-cut")).await;
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let previous = &discussion.head.authority_commit;
    let create = private_create(
        &pool,
        previous,
        previous.event.actor_id.as_account_id().unwrap(),
    )
    .await;
    let create = heap_future(|| ordinary_realm::source_pcr_request(&pool, create)).await;
    let sidecar_id = arkret_wire::SidecarId::from_event_id(&create.authority_commit.event.event_id);
    let source = serde_json::json!({"kind":"strand","strand_id":discussion.strand_id});
    let attach = attach_request(
        &create,
        &sidecar_id,
        source.clone(),
        1,
        None,
        &create.authority_commit.event.event_id,
    );

    let mut attach = attach;
    attach.authority_commit.commit.authority_ref =
        create.authority_commit.commit.authority_ref.clone();
    let attach = heap_future(|| ordinary_realm::source_pcr_request(&pool, attach)).await;
    uow.commit_event_batch(batch(create.clone(), attach.clone()))
        .await
        .unwrap();
    assert_eq!(rows(&pool).await.len(), 1);
    let current = contexts(&pool).await;
    assert_eq!(current.len(), 1);
    assert_eq!(current[0].sidecar_id, sidecar_id.as_str());
    assert_eq!(current[0].context_ref, source);
    assert_eq!(current[0].version, 1);
    assert_eq!(
        current[0].attach_event_id,
        attach.authority_commit.event.event_id.as_str()
    );
    assert_eq!(
        current[0].current_commit_id,
        attach.authority_commit.commit.commit_id.as_str()
    );
    assert_eq!(current[0].value["sidecar_id"], sidecar_id.as_str());
    assert_eq!(current[0].value["version"], 1);

    let successor = attach_request(
        &attach,
        &sidecar_id,
        source.clone(),
        2,
        Some(&attach.authority_commit.event.event_id),
        &create.authority_commit.event.event_id,
    );
    let successor = heap_future(|| ordinary_realm::source_pcr_request(&pool, successor)).await;
    uow.commit_event(successor.clone()).await.unwrap();
    let current = contexts(&pool).await;
    assert_eq!(current.len(), 1);
    assert_eq!(current[0].version, 2);
    assert_eq!(
        current[0].attach_event_id,
        successor.authority_commit.event.event_id.as_str()
    );

    let stale = attach_request(
        &successor,
        &sidecar_id,
        serde_json::json!({"kind":"strand","strand_id":discussion.strand_id}),
        4,
        Some(&successor.authority_commit.event.event_id),
        &create.authority_commit.event.event_id,
    );
    let stale = heap_future(|| ordinary_realm::source_pcr_request(&pool, stale)).await;
    let error = uow.commit_event(stale.clone()).await.unwrap_err();
    assert_eq!(error.conflict_code(), Some(ConflictCode::CasConflict));
    assert_eq!(contexts(&pool).await[0].version, 2);
    assert!(
        PgAuthorityCommitStore { pool: pool.clone() }
            .committed_event(&stale.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );

    let another = TestDatabase::lease().await;
    let other_pool = another.pool();
    let other_discussion = heap_future(|| {
        ordinary_realm::open_human_discussion(&other_pool, "sidecar-attach-rollback")
    })
    .await;
    let other_uow = PgEventCommitUnitOfWork::new(other_pool.clone());
    let previous = &other_discussion.head.authority_commit;
    let other_create = private_create(
        &other_pool,
        previous,
        previous.event.actor_id.as_account_id().unwrap(),
    )
    .await;
    let other_create =
        heap_future(|| ordinary_realm::source_pcr_request(&other_pool, other_create)).await;
    let other_id =
        arkret_wire::SidecarId::from_event_id(&other_create.authority_commit.event.event_id);
    let absent_strand =
        arkret_wire::StrandId::from_event_id(&other_create.authority_commit.event.event_id);
    let invalid_attach = attach_request(
        &other_create,
        &other_id,
        serde_json::json!({"kind":"strand","strand_id":absent_strand}),
        1,
        None,
        &other_create.authority_commit.event.event_id,
    );

    let invalid_attach =
        heap_future(|| ordinary_realm::source_pcr_request(&other_pool, invalid_attach)).await;
    let error = other_uow
        .commit_event_batch(batch(other_create.clone(), invalid_attach.clone()))
        .await
        .unwrap_err();
    assert_eq!(error.conflict_code(), Some(ConflictCode::CapabilityDenied));
    assert!(rows(&other_pool).await.is_empty());
    assert!(contexts(&other_pool).await.is_empty());
    let store = PgAuthorityCommitStore {
        pool: other_pool.clone(),
    };
    for event_id in [
        &other_create.authority_commit.event.event_id,
        &invalid_attach.authority_commit.event.event_id,
    ] {
        assert!(store.committed_event(event_id).await.unwrap().is_none());
    }
}
