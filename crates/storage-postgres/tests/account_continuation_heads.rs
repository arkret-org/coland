#[path = "../../test-support/src/device_authorization_history.rs"]
#[allow(dead_code)]
mod device_authorization_history;
#[path = "support/ordinary_realm.rs"]
#[allow(dead_code)]
mod ordinary_realm;
#[path = "../../test-support/src/pcr_genesis.rs"]
#[allow(dead_code)]
mod pcr_genesis;

use coland_storage::AuthorityCommitStore as _;
use coland_storage_postgres::PgAuthorityCommitStore;
use coland_storage_postgres::test_database::TestDatabase;
use diesel::sql_types::{BigInt, Jsonb, Text};
use diesel_async::RunQueryDsl as _;

#[derive(diesel::QueryableByName)]
struct JsonRow {
    #[diesel(sql_type = Jsonb)]
    value: serde_json::Value,
}

#[derive(diesel::QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    value: i64,
}

#[tokio::test]
async fn continuation_checks_exact_and_ancestor_identities_without_issuing() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let discussion =
        ordinary_realm::open_human_discussion(&pool, &uuid::Uuid::now_v7().to_string()).await;
    let realm = discussion.realm_id();
    let account = discussion.unit.transactions[0]
        .event
        .actor_id
        .as_account_id()
        .unwrap();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let material = store
        .realm_state_snapshot_material_for_account(&realm, account)
        .await
        .unwrap()
        .unwrap();
    let exact = material.visible_stream_heads[0].clone();
    let first = &discussion.unit.transactions.last().unwrap().commit;
    let ancestor = arkret_wire::CommitStreamHead {
        stream_ref: first.stream_ref.clone(),
        commit_id: first.commit_id.clone(),
        stream_position: first.stream_position,
    };
    let mut conn = pool.get().await.unwrap();
    let before = diesel::sql_query("SELECT (SELECT count(*) FROM sync_cursor_handles)+(SELECT count(*) FROM realm_state_snapshot_issuances)+(SELECT count(*) FROM realm_state_snapshot_window_reservations) AS value")
        .get_result::<CountRow>(&mut conn).await.unwrap().value;
    for head in [&exact, &ancestor] {
        assert!(
            store
                .account_continuation_heads_covered(&realm, account, std::slice::from_ref(head))
                .await
                .unwrap()
        );
        let mut fork = head.clone();
        fork.commit_id = arkret_wire::RealmCommitId::from_digest([0x55; 32]);
        assert!(
            !store
                .account_continuation_heads_covered(&realm, account, &[fork])
                .await
                .unwrap()
        );
    }
    let mut ahead = exact.clone();
    ahead.stream_position += 1;
    assert!(
        !store
            .account_continuation_heads_covered(&realm, account, &[ahead])
            .await
            .unwrap()
    );
    let after = diesel::sql_query("SELECT (SELECT count(*) FROM sync_cursor_handles)+(SELECT count(*) FROM realm_state_snapshot_issuances)+(SELECT count(*) FROM realm_state_snapshot_window_reservations) AS value")
        .get_result::<CountRow>(&mut conn).await.unwrap().value;
    assert_eq!(before, after);
    let unknown = arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [0x44; 32],
    ));
    let mut unknown_head = exact;
    unknown_head.stream_ref = arkret_wire::CommitStreamRef::Realm {
        realm_id: unknown.clone(),
    };
    assert!(
        !store
            .account_continuation_heads_covered(&unknown, account, &[unknown_head])
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn inconsistent_actual_head_refuses_until_the_original_accepted_row_is_restored() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let discussion =
        ordinary_realm::open_human_discussion(&pool, &uuid::Uuid::now_v7().to_string()).await;
    let realm = discussion.realm_id();
    let account = discussion.unit.transactions[0]
        .event
        .actor_id
        .as_account_id()
        .unwrap();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let material = store
        .realm_state_snapshot_material_for_account(&realm, account)
        .await
        .unwrap()
        .unwrap();
    let head = material.visible_stream_heads[0].clone();
    let mut conn = pool.get().await.unwrap();
    let original =
        diesel::sql_query("SELECT to_jsonb(c) AS value FROM realm_commits c WHERE commit_id=$1")
            .bind::<Text, _>(head.commit_id.as_str())
            .get_result::<JsonRow>(&mut conn)
            .await
            .unwrap()
            .value;
    assert_eq!(
        diesel::sql_query("UPDATE realm_commits SET commit_json=jsonb_set(commit_json,'{event_ref}','null'::jsonb) WHERE commit_id=$1")
            .bind::<Text, _>(head.commit_id.as_str())
            .execute(&mut conn)
            .await
            .unwrap(),
        1
    );
    // This is inconsistent evidence, not a proved recoverable prefix. Both refusal
    // outcomes map to pre-NDJSON 503 and must not mint a replacement cut.
    assert!(!matches!(
        store
            .account_continuation_heads_covered(&realm, account, std::slice::from_ref(&head))
            .await,
        Ok(true)
    ));
    diesel::sql_query("UPDATE realm_commits SET commit_json=$2 WHERE commit_id=$1")
        .bind::<Text, _>(head.commit_id.as_str())
        .bind::<Jsonb, _>(original["commit_json"].clone())
        .execute(&mut conn)
        .await
        .unwrap();
    let reopened = PgAuthorityCommitStore {
        pool: database.pool(),
    };
    assert!(
        reopened
            .account_continuation_heads_covered(&realm, account, &[head])
            .await
            .unwrap()
    );
}
