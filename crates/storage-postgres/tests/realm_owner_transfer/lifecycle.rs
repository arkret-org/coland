//! Intended child: tests/realm_owner_transfer/lifecycle.rs.
//! No authority is seeded: the trigger only pauses the real lifecycle writer.

use std::time::Duration;

use coland_storage::{
    AccountLifecycleRecord, AccountLifecycleStore, AccountStore, EventCommitUnitOfWork,
};
use coland_storage_postgres::test_database::TestDatabase;
use coland_storage_postgres::{PgAccountLifecycleStore, PgAccountStore, PgEventCommitUnitOfWork};
use diesel::sql_types::Text;
use diesel_async::{RunQueryDsl as _, SimpleAsyncConnection as _};

use super::{Count, native_owner, ordinary_realm, wait_for_blocked};

const BARRIER_CLEANUP: &str = "DROP TRIGGER pause_owner_lifecycle_writer ON account_lifecycle; \
                             DROP FUNCTION pause_owner_lifecycle_writer()";

#[tokio::test]
async fn real_lifecycle_writer_wins_before_owner_account_source_is_read() {
    ordinary_realm::case_future(|| async {
        let database = TestDatabase::lease().await;
        let pool = database.pool();
        let fixture = native_owner::prepared(&pool, "owner-lifecycle-race").await;
        let before = native_owner::root_value(&pool, &fixture.realm).await;
        let account = PgAccountStore { pool: pool.clone() }
            .get(&fixture.successor).await.unwrap().unwrap();
        let mut barrier = pool.get().await.unwrap();
        barrier.batch_execute(
            "CREATE OR REPLACE FUNCTION pause_owner_lifecycle_writer() RETURNS trigger LANGUAGE plpgsql AS $$ \
             BEGIN PERFORM pg_advisory_xact_lock(80641011); RETURN NEW; END $$; \
             CREATE OR REPLACE TRIGGER pause_owner_lifecycle_writer BEFORE INSERT OR UPDATE ON account_lifecycle \
             FOR EACH ROW EXECUTE FUNCTION pause_owner_lifecycle_writer(); \
             SELECT pg_advisory_lock(80641011)"
        ).await.unwrap();
        #[derive(diesel::QueryableByName)]
        struct Backend { #[diesel(sql_type=diesel::sql_types::Integer)] pid: i32 }
        let blocker = diesel::sql_query("SELECT pg_backend_pid() AS pid")
            .get_result::<Backend>(&mut barrier).await.unwrap().pid;
        let writer_pool = pool.clone();
        let writer = tokio::spawn(async move {
            PgAccountLifecycleStore { pool: writer_pool }.put(account.pk, &AccountLifecycleRecord {
                state: "deactivated".into(), reason: None, changed_by: None,
                changed_at: native_owner::now(),
            }).await
        });
        // The outer timeout expires before the observer's own panic deadline.
        // Always release the barrier before asserting a failed observation.
        let writer_waited = tokio::time::timeout(
            Duration::from_secs(5), wait_for_blocked(&pool, blocker, 1),
        ).await;
        if writer_waited.is_err() {
            barrier.batch_execute("SELECT pg_advisory_unlock(80641011)").await.unwrap();
            tokio::time::timeout(Duration::from_secs(5), writer).await.unwrap().unwrap().unwrap();
            barrier.batch_execute(BARRIER_CLEANUP).await.unwrap();
            panic!("the real lifecycle writer never acquired its account row before waiting");
        }
        let owner_pool = pool.clone();
        let owner_request = fixture.request.clone();
        let owner = tokio::spawn(async move {
            PgEventCommitUnitOfWork::new(owner_pool).commit_event(owner_request).await
        });
        let owner_waited = tokio::time::timeout(
            Duration::from_secs(5), wait_for_blocked(&pool, blocker, 2),
        ).await;
        barrier.batch_execute("SELECT pg_advisory_unlock(80641011)").await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), writer).await.unwrap().unwrap().unwrap();
        let owner_result = tokio::time::timeout(Duration::from_secs(5), owner).await.unwrap().unwrap();
        barrier.batch_execute(BARRIER_CLEANUP).await.unwrap();
        assert!(owner_waited.is_ok(), "Owner must actually wait for the product account writer");
        assert!(owner_result.is_err(), "a committed native deactivation refuses first acceptance");
        assert!(native_owner::now() < fixture.w1.device_projection_attestation.attestation.expires_at,
            "this negative must be a lifecycle refusal, not expiry of C's observation");
        assert_eq!(native_owner::root_value(&pool, &fixture.realm).await, before);
        let mut conn = pool.get().await.unwrap();
        let committed = diesel::sql_query("SELECT COUNT(*) AS count FROM canonical_events WHERE envelope->>'event_id'=$1")
            .bind::<Text, _>(fixture.event().event_id.as_str())
            .get_result::<Count>(&mut conn).await.unwrap();
        assert_eq!(committed.count, 0, "refusal must leave no Event or W1 slot");
    }).await;
}
