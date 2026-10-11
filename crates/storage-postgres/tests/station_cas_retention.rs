mod support;

use coland_storage::{AccountDataCasResult, AccountDataRecord, AccountDataStore};
use coland_storage_postgres::{Db, PgAccountDataStore, PgPool};
use deadpool::managed::Pool;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;

async fn test_pool() -> PgPool {
    let url = support::contract_database_url();
    support::ensure_contract_database(&url).await;
    Db::connect(Some(&url), Default::default())
        .await
        .expect("connect contract database");
    let manager = AsyncDieselConnectionManager::new(&url);
    Pool::builder(manager).build().expect("build postgres pool")
}

fn record(
    actor: &str,
    key: &str,
    revision: u64,
    value: serde_json::Value,
    tombstone: bool,
    updated_at: chrono::DateTime<chrono::Utc>,
) -> AccountDataRecord {
    AccountDataRecord {
        actor: actor.to_owned(),
        account_data_key: key.to_owned(),
        revision,
        payload: value,
        tombstone,
        updated_at,
    }
}

async fn apply(store: &PgAccountDataStore, row: AccountDataRecord, expected_revision: u64) {
    assert!(matches!(
        store.compare_and_set(&row, expected_revision).await.unwrap(),
        AccountDataCasResult::Applied(applied) if applied.revision == row.revision
    ));
}

#[tokio::test]
async fn station_cas_gc_preserves_current_private_rows_and_marks_old_cursors_unreplayable() {
    let pool = test_pool().await;
    let actor = format!("ak:did_core:station-cas-retention-{}", uuid::Uuid::now_v7());
    let invite_key = "ak.account.invite_delivery";
    let quarantine_key = "ak.account.holder_quarantine";
    let now = chrono::Utc::now();
    let old = now - chrono::Duration::days(100);
    let store = PgAccountDataStore { pool: pool.clone() };

    apply(
        &store,
        record(
            &actor,
            invite_key,
            1,
            serde_json::json!({"state": "old"}),
            false,
            old,
        ),
        0,
    )
    .await;
    let first_position = store.latest_change_position(&actor).await.unwrap();
    apply(
        &store,
        record(
            &actor,
            invite_key,
            2,
            serde_json::json!({"state": "current"}),
            false,
            now,
        ),
        1,
    )
    .await;
    apply(
        &store,
        record(
            &actor,
            quarantine_key,
            1,
            serde_json::json!({"surfaces": ["invite", "contact_request"]}),
            false,
            now,
        ),
        0,
    )
    .await;
    let latest_before_gc = store.latest_change_position(&actor).await.unwrap();

    assert_eq!(
        store
            .prune_changes_before(now - chrono::Duration::days(90))
            .await
            .unwrap(),
        1
    );
    assert!(
        !store
            .change_position_is_replayable(&actor, 0)
            .await
            .unwrap()
    );
    assert!(
        store
            .change_position_is_replayable(&actor, first_position)
            .await
            .unwrap()
    );
    let retained = store.changes_after(&actor, first_position).await.unwrap();
    assert_eq!(retained.len(), 2);
    assert_eq!(retained.last().unwrap().position, latest_before_gc);

    let reopened = PgAccountDataStore { pool };
    let (snapshot, reopened_position) = reopened.snapshot_for_actor(&actor).await.unwrap();
    assert_eq!(reopened_position, latest_before_gc);
    assert_eq!(snapshot.len(), 2);
    assert!(snapshot.iter().any(|row| {
        row.account_data_key == invite_key && row.payload == serde_json::json!({"state": "current"})
    }));
    assert!(
        snapshot
            .iter()
            .any(|row| row.account_data_key == quarantine_key)
    );

    apply(
        &reopened,
        record(&actor, invite_key, 3, serde_json::json!({}), true, now),
        2,
    )
    .await;
    let removal = reopened
        .changes_after(&actor, latest_before_gc)
        .await
        .unwrap();
    assert_eq!(removal.len(), 1);
    assert!(removal[0].record.tombstone);
    let (snapshot_after_delete, _) = reopened.snapshot_for_actor(&actor).await.unwrap();
    assert_eq!(snapshot_after_delete.len(), 1);
    assert_eq!(snapshot_after_delete[0].account_data_key, quarantine_key);
}
