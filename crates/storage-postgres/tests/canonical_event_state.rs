use coland_storage_postgres::test_database::TestDatabase;
use diesel::prelude::QueryableByName;
use diesel::sql_query;
use diesel::sql_types::{BigInt, Binary, Jsonb, Text};
use diesel_async::RunQueryDsl;
use serde_json::json;

#[derive(QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

async fn insert_event(
    conn: &mut diesel_async::AsyncPgConnection,
    seed: u8,
    realm: &str,
    kind: &str,
    state: &str,
) {
    let mut id = vec![1];
    id.extend([seed; 32]);
    let digest = vec![seed; 32];
    let committed_at = (state == "committed").then(chrono::Utc::now);
    let rejection_reason = (state == "rejected").then_some("test_rejection");
    sql_query(
        "INSERT INTO canonical_events \
         (id,digest_suite,digest,actor_id,realm_id,scope_ref,kind,canonical_bytes,envelope,state,committed_at,rejection_reason) \
         VALUES($1,1,$2,'ak:did_core:web:test.example',$3,$4,$5,$6,$7,$8,$9,$10)",
    )
    .bind::<Binary, _>(id)
    .bind::<Binary, _>(digest)
    .bind::<Text, _>(realm)
    .bind::<Jsonb, _>(json!({"kind":"realm","realm_id":realm}))
    .bind::<Text, _>(kind)
    .bind::<Binary, _>(vec![seed])
    .bind::<Jsonb, _>(json!({"event_id":format!("event-{seed}")}))
    .bind::<Text, _>(state)
    .bind::<diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>, _>(committed_at)
    .bind::<diesel::sql_types::Nullable<Text>, _>(rejection_reason)
    .execute(conn)
    .await
    .unwrap();
}

#[tokio::test]
async fn committed_view_excludes_queued_and_rejected_events() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let mut conn = pool.get().await.unwrap();
    // This storage-only coordinate represents no authority admission.
    let create_event_id = arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        arkret_canonical::sha256_bytes(b"canonical committed view fixture"),
    );
    let realm = arkret_wire::RealmId::from_event_id(&create_event_id).to_string();

    insert_event(&mut conn, 201, &realm, "ak.message", "queued").await;
    insert_event(&mut conn, 202, &realm, "ak.message", "committed").await;
    insert_event(&mut conn, 203, &realm, "ak.message", "rejected").await;

    let count = sql_query("SELECT count(*) AS count FROM committed_events WHERE realm_id=$1")
        .bind::<Text, _>(&realm)
        .get_result::<CountRow>(&mut conn)
        .await
        .unwrap()
        .count;
    assert_eq!(count, 1, "only committed Events enter the shared read view");
}

#[tokio::test]
async fn canonical_event_terminal_state_and_bytes_are_immutable() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let mut conn = pool.get().await.unwrap();
    // This storage-only coordinate represents no authority admission.
    let create_event_id = arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        arkret_canonical::sha256_bytes(b"canonical terminal state fixture"),
    );
    let realm = arkret_wire::RealmId::from_event_id(&create_event_id).to_string();
    insert_event(&mut conn, 204, &realm, "ak.message", "committed").await;

    let state_change = sql_query(
        "UPDATE canonical_events SET state='rejected',committed_at=NULL,rejection_reason='late' \
         WHERE realm_id=$1",
    )
    .bind::<Text, _>(&realm)
    .execute(&mut conn)
    .await;
    assert!(
        state_change.is_err(),
        "a committed Event cannot be withdrawn"
    );

    let byte_change = sql_query("UPDATE canonical_events SET canonical_bytes=$2 WHERE realm_id=$1")
        .bind::<Text, _>(&realm)
        .bind::<Binary, _>(vec![0])
        .execute(&mut conn)
        .await;
    assert!(
        byte_change.is_err(),
        "canonical Event bytes cannot be rewritten"
    );

    let derived_column_change = sql_query(
        "UPDATE canonical_events SET actor_id='ak:did_core:web:other.example' WHERE realm_id=$1",
    )
    .bind::<Text, _>(&realm)
    .execute(&mut conn)
    .await;
    assert!(
        derived_column_change.is_err(),
        "columns derived from canonical bytes cannot diverge from them"
    );

    let terminal_time_change = sql_query(
        "UPDATE canonical_events SET committed_at=committed_at + interval '1 second' WHERE realm_id=$1",
    )
    .bind::<Text, _>(&realm)
    .execute(&mut conn)
    .await;
    assert!(
        terminal_time_change.is_err(),
        "a terminal canonical Event result cannot be rewritten in place"
    );

    let quarantine = sql_query("UPDATE canonical_events SET state='quarantined' WHERE realm_id=$1")
        .bind::<Text, _>(&realm)
        .execute(&mut conn)
        .await;
    assert!(
        quarantine.is_err(),
        "quarantined is not a canonical Event admission state"
    );
}

#[tokio::test]
async fn initial_schema_creates_only_the_terminal_outcome_column() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let mut conn = pool.get().await.unwrap();

    let terminal_outcome = sql_query(
        "SELECT count(*) AS count FROM information_schema.columns \
         WHERE table_schema='public' AND table_name='security_transactions' \
           AND column_name='terminal_outcome'",
    )
    .get_result::<CountRow>(&mut conn)
    .await
    .unwrap()
    .count;
    let terminal_result = sql_query(
        "SELECT count(*) AS count FROM information_schema.columns \
         WHERE table_schema='public' AND table_name='security_transactions' \
           AND column_name='terminal_result'",
    )
    .get_result::<CountRow>(&mut conn)
    .await
    .unwrap()
    .count;

    assert_eq!(terminal_outcome, 1);
    assert_eq!(terminal_result, 0);
}
