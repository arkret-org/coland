use arkret_wire::{AccountId, ActorId, DidCoreId};

use super::*;

fn account(station: &str) -> AccountId {
    AccountId::new(
        DidCoreId::new("ak:did_core:web:preparation-owner.example").unwrap(),
        DidCoreId::new(format!("ak:did_core:web:{station}.example")).unwrap(),
    )
}

// These are private-cache fixtures, never PCR/issuer/accepted-event authority.
async fn seed_owner(pool: &PgPool, account: &AccountId) {
    let mut conn = pool.get().await.unwrap();
    sql_query("INSERT INTO accounts(principal_id,station_id,payload) VALUES($1,$2,'{}'::jsonb)")
        .bind::<Text, _>(account.principal_id.as_str())
        .bind::<Text, _>(account.station_id.as_str())
        .execute(&mut *conn)
        .await
        .unwrap();
}

fn record(owner: &AccountId, key: &str, handle: &str) -> IdempotencyRecord {
    let now = chrono::DateTime::from_timestamp_micros(Utc::now().timestamp_micros()).unwrap();
    IdempotencyRecord {
        authenticated_actor: ActorId::account(owner.clone()),
        operation_id: "org.arkret.coland.contact.prepare.v1".into(),
        idempotency_key: key.into(),
        request_hash: arkret_canonical::sha256_digest(b"request-one"),
        response_status: 200,
        response_body: serde_json::json!({"reservation_handle":handle}),
        created_at: now,
        expires_at: now + chrono::Duration::minutes(10),
    }
}

#[tokio::test]
async fn one_primary_concurrent_preparations_keep_only_the_first_matching_context() {
    let database = crate::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let owner = account("home");
    seed_owner(&pool, &owner).await;
    let store = PgIdempotencyStore { pool };
    let first = record(&owner, "same-wire-key", "handle-first");
    let second = record(&owner, "same-wire-key", "handle-second");
    let mut first_context = first.clone();
    first_context.idempotency_key = "handle-first".into();
    first_context.response_body["private_plan"] = serde_json::json!("first-full-plan");
    let mut second_context = second.clone();
    second_context.idempotency_key = "handle-second".into();
    second_context.response_body["private_plan"] = serde_json::json!("second-full-plan");
    let (left, right) = tokio::join!(
        store.record_preparation(&first, Some(&first_context)),
        store.record_preparation(&second, Some(&second_context)),
    );
    let left = left.unwrap();
    let right = right.unwrap();
    assert_eq!(left, right);
    let first_landed = store
        .get(
            &first.authenticated_actor,
            &first.operation_id,
            "handle-first",
        )
        .await
        .unwrap();
    let second_landed = store
        .get(
            &first.authenticated_actor,
            &first.operation_id,
            "handle-second",
        )
        .await
        .unwrap();
    assert_ne!(first_landed.is_some(), second_landed.is_some());
    let context = first_landed.or(second_landed).unwrap();
    assert_eq!(
        left.response_body["reservation_handle"],
        context.response_body["reservation_handle"]
    );
    let mut conflict = second.clone();
    conflict.request_hash = arkret_canonical::sha256_digest(b"changed-request");
    let mut context = second_context.clone();
    context.request_hash = conflict.request_hash.clone();
    context.idempotency_key = "unwanted-new-context".into();
    assert_eq!(
        store
            .record_preparation(&conflict, Some(&context))
            .await
            .unwrap_err()
            .conflict_code(),
        Some(coland_storage::ConflictCode::DuplicateConflict)
    );
    assert!(
        store
            .get(
                &conflict.authenticated_actor,
                &conflict.operation_id,
                "unwanted-new-context"
            )
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn same_principal_foreign_station_and_terminal_owner_keep_independent_preparations() {
    let database = crate::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let home = account("home");
    let foreign = account("foreign");
    seed_owner(&pool, &home).await;
    seed_owner(&pool, &foreign).await;
    let store = PgIdempotencyStore { pool: pool.clone() };
    let home_record = record(&home, "same-key", "home-handle");
    let foreign_record = record(&foreign, "same-key", "foreign-handle");
    assert_eq!(
        store.record_preparation(&home_record, None).await.unwrap(),
        home_record
    );
    assert_eq!(
        store
            .record_preparation(&foreign_record, None)
            .await
            .unwrap(),
        foreign_record
    );
    let mut conn = pool.get().await.unwrap();
    sql_query("WITH held AS MATERIALIZED(SELECT pk FROM accounts WHERE principal_id=$1 AND station_id=$2 FOR UPDATE) INSERT INTO account_lifecycle(account_pk,state,changed_at) SELECT pk,'erasure_pending',NOW() FROM held")
        .bind::<Text,_>(home.principal_id.as_str()).bind::<Text,_>(home.station_id.as_str()).execute(&mut *conn).await.unwrap();
    drop(conn);
    assert_eq!(
        store
            .record_preparation(&home_record, None)
            .await
            .unwrap_err()
            .conflict_code(),
        Some(coland_storage::ConflictCode::AccountErased)
    );
    let later = record(&home, "new-key", "unwanted-handle");
    assert_eq!(
        store
            .record_preparation(&later, None)
            .await
            .unwrap_err()
            .conflict_code(),
        Some(coland_storage::ConflictCode::AccountErased)
    );
    assert!(
        store
            .get(
                &later.authenticated_actor,
                &later.operation_id,
                &later.idempotency_key
            )
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store
            .record_preparation(&foreign_record, None)
            .await
            .unwrap(),
        foreign_record
    );
}

#[tokio::test]
async fn occupied_context_rolls_back_the_new_primary_in_the_same_transaction() {
    let database = crate::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let owner = account("home");
    seed_owner(&pool, &owner).await;
    let store = PgIdempotencyStore { pool };
    let occupied = record(&owner, "occupied-handle", "original");
    store.record(&occupied).await.unwrap();
    let primary = record(&owner, "new-primary", "new-handle");
    let mut context = primary.clone();
    context.idempotency_key = "occupied-handle".into();
    assert_eq!(
        store
            .record_preparation(&primary, Some(&context))
            .await
            .unwrap_err()
            .conflict_code(),
        Some(coland_storage::ConflictCode::DuplicateConflict)
    );
    assert!(
        store
            .get(
                &primary.authenticated_actor,
                &primary.operation_id,
                &primary.idempotency_key
            )
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store
            .get(
                &occupied.authenticated_actor,
                &occupied.operation_id,
                &occupied.idempotency_key
            )
            .await
            .unwrap(),
        Some(occupied)
    );
}
