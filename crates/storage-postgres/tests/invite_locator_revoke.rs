//! Owned-locator revocation across expiry, concurrency and adapter recreation.
use chrono::{Duration, Utc};
use coland_storage::{InviteLocatorRecord, InviteLocatorStore};
use coland_storage_postgres::PgInviteLocatorStore;
use coland_storage_postgres::test_database::TestDatabase;

#[tokio::test]
async fn invite_revoke_is_owner_bound_idempotent_after_ttl_and_restart() {
    let database = TestDatabase::lease().await;
    let store = PgInviteLocatorStore {
        pool: database.pool(),
    };
    let now = Utc::now();
    let record = InviteLocatorRecord {
        locator_id: format!("ak:invite_locator:{}", uuid::Uuid::now_v7()),
        token_digest: "sha256:owned-secret".into(),
        subject_id: "account-at-station-a".into(),
        recipient_id: "station-a".into(),
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
            .revoke("account-at-station-b", &record.locator_id, now)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .revoke(&record.subject_id, "missing", now)
            .await
            .unwrap()
            .is_none()
    );
    let (one, two) = tokio::join!(
        store.revoke(&record.subject_id, &record.locator_id, now),
        store.revoke(
            &record.subject_id,
            &record.locator_id,
            now + Duration::seconds(1)
        )
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
            .revoke(
                &record.subject_id,
                &record.locator_id,
                now + Duration::hours(1)
            )
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
            .revoke(&consumed.subject_id, &consumed.locator_id, now)
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
            .revoke(
                &expired.subject_id,
                &expired.locator_id,
                now + Duration::hours(1)
            )
            .await
            .unwrap()
            .unwrap()
            .revoked_at
            .is_some()
    );
}
