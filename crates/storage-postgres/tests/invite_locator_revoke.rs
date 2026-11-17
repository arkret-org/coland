//! Owned-locator revocation across expiry, concurrency and adapter recreation.
use arkret_wire::{AccountId, DidCoreId};
use chrono::{Duration, Utc};
use coland_storage::{InviteLocatorRecord, InviteLocatorStore};
use coland_storage_postgres::PgInviteLocatorStore;
use coland_storage_postgres::test_database::TestDatabase;
use diesel::sql_query;
use diesel::sql_types::Text;
use horme::RunQueryDsl;

#[tokio::test]
async fn invite_revoke_is_owner_bound_idempotent_after_ttl_and_restart() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let store = PgInviteLocatorStore { pool: pool.clone() };
    let now = Utc::now();
    let owner = account("home");
    let foreign = account("foreign");
    seed_private_owner(&database, &owner).await;
    seed_private_owner(&database, &foreign).await;
    let record = InviteLocatorRecord {
        locator_id: format!("ak:invite_locator:{}", uuid::Uuid::now_v7()),
        token_digest: "sha256:owned-secret".into(),
        subject_id: owner.principal_id.to_string(),
        recipient_id: owner.station_id.to_string(),
        issued_at: now,
        expires_at: now + Duration::seconds(60),
        one_time_use: false,
        display_hint: None,
        revoked_at: None,
        consumed_at: None,
    };
    store.insert(&record, 16, now).await.unwrap();
    assert!(
        store
            .revoke(&foreign, &record.locator_id, now)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .revoke(&owner, "missing", now)
            .await
            .unwrap()
            .is_none()
    );
    let (one, two) = tokio::join!(
        store.revoke(&owner, &record.locator_id, now),
        store.revoke(&owner, &record.locator_id, now + Duration::seconds(1))
    );
    let first = one.unwrap().unwrap().revoked_at.unwrap();
    assert_eq!(two.unwrap().unwrap().revoked_at, Some(first));
    assert!(
        store
            .resolve_and_consume(&record.token_digest, now)
            .await
            .unwrap()
            .is_none()
    );
    drop(store);
    let restarted = PgInviteLocatorStore {
        pool: database.pool(),
    };
    assert_eq!(
        restarted
            .revoke(&owner, &record.locator_id, now + Duration::hours(1))
            .await
            .unwrap()
            .unwrap()
            .revoked_at,
        Some(first)
    );
    let mut consumed = record.clone();
    consumed.locator_id = format!("ak:invite_locator:{}", uuid::Uuid::now_v7());
    consumed.token_digest = "sha256:one-use-secret".into();
    consumed.one_time_use = true;
    restarted.insert(&consumed, 16, now).await.unwrap();
    restarted
        .resolve_and_consume(&consumed.token_digest, now)
        .await
        .unwrap()
        .unwrap();
    assert!(
        restarted
            .revoke(&owner, &consumed.locator_id, now)
            .await
            .unwrap()
            .is_none()
    );
    let mut expired = record.clone();
    expired.locator_id = format!("ak:invite_locator:{}", uuid::Uuid::now_v7());
    expired.token_digest = "sha256:expired-secret".into();
    restarted.insert(&expired, 16, now).await.unwrap();
    assert!(
        restarted
            .revoke(&owner, &expired.locator_id, now + Duration::hours(1))
            .await
            .unwrap()
            .unwrap()
            .revoked_at
            .is_some()
    );
}

fn account(station: &str) -> AccountId {
    AccountId::new(
        DidCoreId::new("ak:did_core:web:locator-holder.example").unwrap(),
        DidCoreId::new(format!("ak:did_core:web:locator-{station}.example")).unwrap(),
    )
}

// Cache fixtures prove only storage ownership, not signed lifecycle authority.
async fn seed_private_owner(database: &TestDatabase, owner: &AccountId) {
    let pool = database.pool();
    let mut conn = pool.get().await.unwrap();
    sql_query("INSERT INTO accounts(principal_id,station_id,payload) VALUES($1,$2,'{}'::jsonb)")
        .bind::<Text, _>(owner.principal_id.as_str())
        .bind::<Text, _>(owner.station_id.as_str())
        .execute(&mut *conn)
        .await
        .unwrap();
}

#[tokio::test]
async fn locator_full_account_quota_and_late_terminal_writes_are_isolated() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let store = PgInviteLocatorStore { pool: pool.clone() };
    let home = account("home");
    let foreign = account("foreign");
    seed_private_owner(&database, &home).await;
    seed_private_owner(&database, &foreign).await;
    let now = Utc::now();
    let make_record = |owner: &AccountId, label: &str| {
        InviteLocatorRecord {
        locator_id:format!("ak:invite_locator:{}",uuid::Uuid::now_v7()),
        token_digest:format!("sha256:{label}"),
        subject_id:owner.principal_id.to_string(),
        recipient_id:owner.station_id.to_string(),
        issued_at:now, expires_at:now+Duration::minutes(10), one_time_use:false,
        display_hint:Some(arkret_models_collaboration::governance::invite_addressing::PrincipalLocatorDisplayHint { display_name_hint:Some(label.into()),avatar_blob_ref:None }), revoked_at:None, consumed_at:None,
    }
    };
    let home_record = make_record(&home, "home-private");
    let foreign_record = make_record(&foreign, "foreign-private");
    assert_eq!(
        store.insert(&home_record, 1, now).await.unwrap(),
        coland_storage::InviteLocatorInsertOutcome::Inserted
    );
    assert_eq!(
        store.insert(&foreign_record, 1, now).await.unwrap(),
        coland_storage::InviteLocatorInsertOutcome::Inserted
    );
    assert!(
        store
            .revoke(&foreign, &home_record.locator_id, now)
            .await
            .unwrap()
            .is_none()
    );
    let mut conn = pool.get().await.unwrap();
    sql_query("WITH held AS MATERIALIZED(SELECT pk FROM accounts WHERE principal_id=$1 AND station_id=$2 FOR UPDATE) INSERT INTO account_lifecycle(account_pk,state,changed_at) SELECT pk,'erasure_pending',NOW() FROM held")
        .bind::<Text,_>(home.principal_id.as_str()).bind::<Text,_>(home.station_id.as_str()).execute(&mut *conn).await.unwrap();
    drop(conn);
    assert!(
        store
            .resolve_and_consume(&home_record.token_digest, now)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store
            .revoke(&home, &home_record.locator_id, now)
            .await
            .unwrap_err()
            .conflict_code(),
        Some(coland_storage::ConflictCode::AccountErased)
    );
    assert_eq!(
        store
            .insert(&make_record(&home, "late-private"), 2, now)
            .await
            .unwrap_err()
            .conflict_code(),
        Some(coland_storage::ConflictCode::AccountErased)
    );
    assert!(
        store
            .resolve_and_consume(&foreign_record.token_digest, now)
            .await
            .unwrap()
            .is_some()
    );
}
