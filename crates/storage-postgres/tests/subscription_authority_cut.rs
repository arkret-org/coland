//! Accepted history policy provenance binds durable subscription progress.
#[path = "support/ordinary_realm.rs"]
#[expect(
    dead_code,
    reason = "Each integration binary uses only its subset of the shared Realm fixture."
)]
mod ordinary_realm;

use arkret_wire::{EventKind, RealmCommitId};
use coland_storage::{AccountRealmStreamList, AuthorityCommitStore, EventCommitUnitOfWork};
use coland_storage_postgres::test_database::TestDatabase;
use coland_storage_postgres::{PgAuthorityCommitStore, PgEventCommitUnitOfWork};
use diesel::sql_types::Text;
use diesel_async::RunQueryDsl;

#[tokio::test]
async fn accepted_append_preserves_digest_policy_change_rebinds_and_missing_source_closes() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let discussion = ordinary_realm::open_discussion_with_history(
        &pool,
        "subscription-source-cut",
        "all_history_for_current_members",
    )
    .await;
    let head = &discussion.head.authority_commit;
    let realm = &head.event.realm_id;
    let account = head.event.actor_id.as_account_id().unwrap();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let before = store
        .realm_stream_subscription_cut(realm, account, &ordinary_realm::station())
        .await
        .unwrap();
    assert!(matches!(&before.listing, AccountRealmStreamList::Listed(_)));
    assert!(before.history_digest.is_some());
    let message = ordinary_realm::next_request(
        head,
        EventKind::MessageCreate,
        head.event.actor_id.signing_principal_id(),
        ordinary_realm::message_payload(&discussion.strand_id, "only new accepted tail"),
        head.commit.committed_at,
    );
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let message = Box::pin(ordinary_realm::source_request(&pool, message)).await;
    uow.commit_event(message.clone()).await.unwrap();
    let after = store
        .realm_stream_subscription_cut(realm, account, &ordinary_realm::station())
        .await
        .unwrap();
    assert_eq!(before.history_digest, after.history_digest);
    assert_ne!(before.listing, after.listing);
    let policy = ordinary_realm::next_request(
        &message.authority_commit,
        EventKind::RealmHistoryAccess,
        head.event.actor_id.signing_principal_id(),
        serde_json::json!({"from":"all_history_for_current_members","to":"since_join"}),
        head.commit.committed_at,
    );
    let policy = Box::pin(ordinary_realm::source_request(&pool, policy)).await;
    uow.commit_event(policy.clone()).await.unwrap();
    let rebound = store
        .realm_stream_subscription_cut(realm, account, &ordinary_realm::station())
        .await
        .unwrap();
    assert!(rebound.history_digest.is_some());
    assert_ne!(rebound.history_digest, after.history_digest);
    let reversal = ordinary_realm::next_request(
        &policy.authority_commit,
        EventKind::RealmHistoryAccess,
        head.event.actor_id.signing_principal_id(),
        serde_json::json!({"from":"since_join","to":"all_history_for_current_members"}),
        head.commit.committed_at,
    );
    let reversal = Box::pin(ordinary_realm::source_request(&pool, reversal)).await;
    assert!(uow.commit_event(reversal.clone()).await.is_err());
    use coland_storage::EventStore as _;
    assert!(
        coland_storage_postgres::PgEventStore { pool: pool.clone() }
            .get(reversal.authority_commit.event.event_id.as_str())
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store
            .realm_stream_subscription_cut(realm, account, &ordinary_realm::station())
            .await
            .unwrap()
            .history_digest,
        rebound.history_digest
    );
    // Fault the stored source identity rather than inventing an accepted policy.
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("UPDATE realm_bootstrap_current_states SET current_commit_id=$2 WHERE realm_id=$1 AND state_family='realm_history_access'")
        .bind::<Text,_>(realm.as_str()).bind::<Text,_>(RealmCommitId::from_digest([91;32]).as_str())
        .execute(&mut *conn).await.unwrap();
    drop(conn);
    let unproved = store
        .realm_stream_subscription_cut(realm, account, &ordinary_realm::station())
        .await
        .unwrap();
    assert!(matches!(
        unproved.listing,
        AccountRealmStreamList::Unproved(_)
    ));
    assert!(unproved.history_digest.is_none());
}
