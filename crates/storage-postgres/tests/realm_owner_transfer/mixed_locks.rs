//! A real ordinary writer and Owner candidate must use the same PCR/R order.

use std::time::Duration;

use arkret_wire::{ActorId, EventKind};
use coland_storage::{ConflictCode, EventCommitUnitOfWork, PersistenceError};
use coland_storage_postgres::PgEventCommitUnitOfWork;
use coland_storage_postgres::test_database::TestDatabase;
use diesel::sql_types::Text;
use diesel_async::{RunQueryDsl as _, SimpleAsyncConnection as _};

use super::{Backend, JsonRow, Original, Pcr, native_owner, ordinary_realm, pcr, wait_for_blocked};

async fn ordered_fixture() -> (TestDatabase, native_owner::NativeOwnerTransfer) {
    for attempt in 0..32 {
        let database = TestDatabase::lease().await;
        let fixture =
            native_owner::prepared(&database.pool(), &format!("owner-mixed-order-{attempt}")).await;
        // This is the exact typed Ord used by the production BTreeSet. Only
        // this real lexical ordering can expose the previous R/PCR inversion.
        if pcr(&fixture.pool, &fixture.author).await < fixture.realm {
            return (database, fixture);
        }
    }
    panic!("could not construct the required real PCR-before-business-Realm ordering");
}

#[tokio::test]
async fn ordinary_message_and_owner_transfer_do_not_reverse_the_primary_source_lock_order() {
    ordinary_realm::case_future(|| async {
        let (_database, fixture) = ordered_fixture().await;
        let pool = fixture.pool.clone();
        let before = native_owner::root_value(&pool, &fixture.realm).await;
        let mut conn = pool.get().await.unwrap();
        let predecessor = diesel::sql_query("SELECT e.envelope,c.commit_json FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk WHERE c.commit_id=$1 AND e.state='committed'")
            .bind::<Text, _>(fixture.commit().previous_commit_ref.as_ref().unwrap().as_str())
            .get_result::<Original>(&mut conn).await.unwrap();
        let strand = diesel::sql_query("SELECT value FROM realm_set_default_strand_current_states WHERE realm_id=$1")
            .bind::<Text, _>(fixture.realm.as_str()).get_result::<JsonRow>(&mut conn).await.unwrap();
        drop(conn);
        let mut previous = fixture.request.authority_commit.clone();
        previous.event = serde_json::from_value(predecessor.envelope).unwrap();
        previous.commit = serde_json::from_value(predecessor.commit_json).unwrap();
        previous.commit.verify_commit_id_matches_content().unwrap();
        previous.producer_signer_fact = None;
        let strand = strand.value["default_strand_id"].as_str().unwrap().parse().unwrap();
        let ordinary = ordinary_realm::next_human_request_for_actor(
            &previous, EventKind::MessageCreate, ActorId::account(fixture.author.clone()),
            ordinary_realm::message_payload(&strand, "ordinary admission queued before Owner"),
            native_owner::now(),
        );
        let ordinary = ordinary_realm::case_future(|| ordinary_realm::source_request(&pool, ordinary)).await;
        let mut barrier = pool.get().await.unwrap();
        barrier.batch_execute("BEGIN").await.unwrap();
        let blocker = diesel::sql_query("SELECT pg_backend_pid() AS pid")
            .get_result::<Backend>(&mut barrier).await.unwrap().pid;
        diesel::sql_query("SELECT realm_id FROM realm_authorities WHERE realm_id=$1 FOR UPDATE")
            .bind::<Text, _>(fixture.realm.as_str()).get_result::<Pcr>(&mut barrier).await.unwrap();
        let ordinary_pool = pool.clone();
        let ordinary = tokio::spawn(async move {
            PgEventCommitUnitOfWork::new(ordinary_pool).commit_event(ordinary).await
        });
        // In the old code the ordinary operation waits at R without PCRA.
        // Owner then takes PCRA before joining R's queue. Releasing R creates
        // the actual two-transaction cycle, not a merely delayed operation.
        let first_waited = tokio::time::timeout(Duration::from_secs(5), wait_for_blocked(&pool, blocker, 1)).await;
        let owner_pool = pool.clone();
        let owner_request = fixture.request.clone();
        let owner = tokio::spawn(async move {
            PgEventCommitUnitOfWork::new(owner_pool).commit_event(owner_request).await
        });
        let second_waited = tokio::time::timeout(Duration::from_secs(5), wait_for_blocked(&pool, blocker, 2)).await;
        barrier.batch_execute("COMMIT").await.unwrap();
        let (ordinary, owner) = tokio::time::timeout(Duration::from_secs(10), async {
            (ordinary.await.unwrap(), owner.await.unwrap())
        }).await.expect("both real transactions must leave the lock queues");
        assert!(first_waited.is_ok() && second_waited.is_ok(), "both real native operations must reach the blocker");
        ordinary.expect("the first ordinary operation must commit");
        let error = owner.expect_err("the queued Owner candidate must observe the newly advanced stream head");
        assert!(matches!(error, PersistenceError::Conflict(ref detail)
            if ConflictCode::from_detail(detail)==Some(ConflictCode::TemporarilyUnavailable)),
            "a real stream retry is required; deadlock/database errors are not equivalent: {error:?}");
        assert_eq!(native_owner::root_value(&pool, &fixture.realm).await, before);
        let mut conn = pool.get().await.unwrap();
        let count = diesel::sql_query("SELECT COUNT(*) AS count FROM canonical_events WHERE envelope->>'event_id'=$1")
            .bind::<Text, _>(fixture.event().event_id.as_str()).get_result::<super::Count>(&mut conn).await.unwrap();
        assert_eq!(count.count, 0, "the retryable Owner candidate must publish no W1 slot");
    }).await;
}
