//! Scope policy admission, independent replacements and zero-write refusals.

#[path = "support/ordinary_realm.rs"]
#[allow(dead_code)]
mod ordinary_realm;
use arkret_wire::{CommitStreamRef, CurrentSelector, CurrentState, EventKind};
use coland_storage::{AuthorityCommitStore, EventCommitUnitOfWork};
use coland_storage_postgres::test_database::TestDatabase;
use coland_storage_postgres::{PgAuthorityCommitStore, PgEventCommitUnitOfWork};
use diesel::sql_types::BigInt;
use diesel_async::RunQueryDsl;
use serde_json::json;

#[derive(diesel::QueryableByName, PartialEq, Debug)]
struct Counts {
    #[diesel(sql_type=BigInt)]
    events: i64,
    #[diesel(sql_type=BigInt)]
    commits: i64,
    #[diesel(sql_type=BigInt)]
    policies: i64,
}
async fn counts(pool: &coland_storage_postgres::PgPool) -> Counts {
    diesel::sql_query("SELECT (SELECT count(*) FROM canonical_events) AS events,(SELECT count(*) FROM realm_commits) AS commits,(SELECT count(*) FROM scope_read_receipt_policy_current_states) AS policies")
        .get_result(&mut *pool.get().await.unwrap()).await.unwrap()
}
#[tokio::test]
async fn each_realm_replaces_one_policy_and_rejects_invalid_writes_atomically() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let first = ordinary_realm::open_discussion(&pool, &uuid::Uuid::now_v7().to_string()).await;
    let other = ordinary_realm::open_discussion(&pool, &uuid::Uuid::now_v7().to_string()).await;
    let mut heads = [first.head.authority_commit, other.head.authority_commit];
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    for (i, disclosure) in [(0, "required"), (1, "disabled"), (0, "optional")] {
        let head = &heads[i];
        let request = ordinary_realm::next_request_for_actor(
            head,
            EventKind::ScopeReadReceiptPolicy,
            head.event.actor_id.clone(),
            json!({"disclosure":disclosure}),
            head.commit.committed_at,
        );
        let request = ordinary_realm::source_request(&pool, request).await;
        uow.commit_event(request.clone()).await.unwrap();
        heads[i] = request.authority_commit;
    }
    for (head, disclosure) in heads.iter().zip(["optional", "disabled"]) {
        let realm = &head.event.realm_id;
        let snapshot = store
            .realm_state_snapshot_material_for_account(
                realm,
                head.event.actor_id.as_account_id().unwrap(),
            )
            .await
            .unwrap()
            .unwrap();
        let policies: Vec<_> = snapshot
            .current_state_entries
            .iter()
            .filter_map(|row| match row {
                CurrentState::Value {
                    selector: CurrentSelector::ScopeReadReceiptPolicy,
                    source_stream_ref,
                    revision,
                    value,
                } => Some((source_stream_ref, revision, value)),
                _ => None,
            })
            .collect();
        assert_eq!(policies.len(), 1);
        let (stream, revision, value) = policies[0];
        assert_eq!(stream, &head.commit.stream_ref);
        assert_eq!(revision.commit_id, head.commit.commit_id);
        assert_eq!(*value, json!({"disclosure":disclosure}));
    }
    let head = &heads[0];
    let candidate = |payload| {
        ordinary_realm::next_request_for_actor(
            head,
            EventKind::ScopeReadReceiptPolicy,
            head.event.actor_id.clone(),
            payload,
            head.commit.committed_at,
        )
    };
    let mut wrong = candidate(json!({"disclosure":"required"}));
    wrong.authority_commit.commit.realm_id = heads[1].event.realm_id.clone();
    wrong.authority_commit.commit.stream_ref = CommitStreamRef::Realm {
        realm_id: heads[1].event.realm_id.clone(),
    };
    ordinary_realm::seal_final_commit(&mut wrong.authority_commit.commit);
    for invalid in [
        wrong,
        candidate(json!({})),
        candidate(json!({"disclosure":null})),
        candidate(json!({"disclosure":"optional","scope_overrides":{}})),
    ] {
        let before = counts(&pool).await;
        assert!(uow.commit_event(invalid).await.is_err());
        assert_eq!(counts(&pool).await, before);
    }
}
