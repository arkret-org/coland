//! The ordinary notification fanout basis is one consistent read of the
//! committed typed current results (private-objects.md sections 3.3-3.6,
//! push-notifications.md section 4.3.2), never of a reducer cache.
#[path = "support/ordinary_realm.rs"]
#[allow(dead_code)]
mod ordinary_realm;

use coland_storage::{EventCommitUnitOfWork, NotificationStore};
use coland_storage_postgres::test_database::TestDatabase;
use coland_storage_postgres::{PgEventCommitUnitOfWork, PgNotificationStore, PgPool};
use diesel::sql_types::{BigInt, Jsonb, Text};
use diesel_async::RunQueryDsl;
use serde_json::{Value, json};

fn member(principal: &str) -> arkret_wire::ActorId {
    arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new(principal).unwrap(),
        ordinary_realm::station(),
    ))
}

/// Seed one member current covered by an existing Realm Commit. Membership
/// admission has its own units; this case pins only the basis read.
async fn seed_member(
    pool: &PgPool,
    discussion: &ordinary_realm::Discussion,
    actor: &arkret_wire::ActorId,
    membership: &str,
) {
    let commit = &discussion.head.authority_commit.commit;
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "INSERT INTO member_state_current_states \
         (realm_id,member_id,membership,current_commit_id,current_stream_position,value,updated_at) \
         VALUES($1,$2,$3,$4,$5,$6,NOW())",
    )
    .bind::<Text, _>(discussion.realm_id().as_str())
    .bind::<Text, _>(actor.to_string())
    .bind::<Text, _>(membership)
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<BigInt, _>(commit.stream_position as i64)
    .bind::<Jsonb, _>(json!({ "membership": membership }))
    .execute(&mut *conn)
    .await
    .unwrap();
}

fn watch(
    discussion: &ordinary_realm::Discussion,
    previous: &coland_storage::AuthorityCommitTransaction,
    level: Value,
    expected: Option<Value>,
    offset: i64,
) -> coland_storage::EventCommitRequest {
    let mut payload = json!({
        "strand_id": discussion.strand_id,
        "watcher_actor_id": discussion.head.authority_commit.event.actor_id,
        "level": level,
    });
    if let Some(expected) = expected {
        payload["expected_value"] = expected;
    }
    ordinary_realm::next_request(
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
    )
}

#[tokio::test]
async fn fanout_basis_reads_committed_membership_strand_and_watch_currents() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let discussion = ordinary_realm::open_discussion(&pool, "notification-fanout").await;
    let realm_id = discussion.realm_id();
    let founder = discussion.head.authority_commit.event.actor_id.clone();
    let store = PgNotificationStore { pool: pool.clone() };
    let uow = PgEventCommitUnitOfWork::new(pool.clone());

    let basis = store
        .fanout_basis(&realm_id, Some(&discussion.strand_id))
        .await
        .unwrap();
    assert_eq!(
        basis.joined_members,
        [founder.clone()].into_iter().collect(),
        "the founder's accepted join is the only member current"
    );
    let strand = basis
        .strand
        .as_ref()
        .expect("the discussion Strand has a committed current value");
    assert_eq!(strand.realm_id, realm_id);
    assert!(strand.active);
    assert!(strand.scope_circle_id.is_none());
    assert!(strand.circle_members.is_empty());
    assert!(basis.watch_levels.is_empty(), "no watch was ever written");
    assert!(basis.active_assignees.is_empty());

    let joined = member("ak:did_core:web:joined.example");
    let left = member("ak:did_core:web:left.example");
    seed_member(&pool, &discussion, &joined, "join").await;
    seed_member(&pool, &discussion, &left, "leave").await;
    let all = watch(
        &discussion,
        &discussion.head.authority_commit,
        json!("all"),
        None,
        30,
    );
    let all = Box::pin(ordinary_realm::source_request(&pool, all)).await;
    uow.commit_event(all.clone()).await.unwrap();
    let basis = store
        .fanout_basis(&realm_id, Some(&discussion.strand_id))
        .await
        .unwrap();
    assert_eq!(
        basis.joined_members,
        [founder.clone(), joined].into_iter().collect(),
        "a member whose current membership is not join is never a recipient"
    );
    assert_eq!(
        basis.watch_levels.get(&founder).map(String::as_str),
        Some("all"),
        "the accepted watch is visible at the next cut without any cache"
    );

    let cleared = watch(
        &discussion,
        &all.authority_commit,
        Value::Null,
        Some(json!({ "level": "all" })),
        31,
    );
    let cleared = Box::pin(ordinary_realm::source_request(&pool, cleared)).await;
    uow.commit_event(cleared).await.unwrap();
    let basis = store
        .fanout_basis(&realm_id, Some(&discussion.strand_id))
        .await
        .unwrap();
    assert!(
        basis.watch_levels.is_empty(),
        "a cleared watch is no longer an explicit level"
    );

    let unknown = arkret_wire::StrandId::from_event_id(&all.authority_commit.event.event_id);
    let basis = store.fanout_basis(&realm_id, Some(&unknown)).await.unwrap();
    assert!(
        basis.strand.is_none(),
        "a Strand without a current value has no scope to admit a recipient"
    );
    assert!(basis.watch_levels.is_empty());
}
