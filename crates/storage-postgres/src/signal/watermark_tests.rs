//! Private read-watermark cache behavior; no protocol authority is seeded.
use arkret_wire::{AccountId, ActorId, DidCoreId};

use super::*;

fn account(station: &str) -> AccountId {
    AccountId::new(
        DidCoreId::new("ak:did_core:web:signal-cache-holder.example").unwrap(),
        DidCoreId::new(format!("ak:did_core:web:signal-{station}.example")).unwrap(),
    )
}
async fn private_cache(pool: &PgPool, owner: &AccountId) {
    let mut conn = pool.get().await.unwrap();
    sql_query("INSERT INTO accounts(principal_id,station_id,payload) VALUES($1,$2,'{}'::jsonb)")
        .bind::<Text, _>(owner.principal_id.as_str())
        .bind::<Text, _>(owner.station_id.as_str())
        .execute(&mut *conn)
        .await
        .unwrap();
}

#[tokio::test]
async fn signal_watermark_busy_is_a_typed_failure_and_terminal_late_copy_is_skipped() {
    let database = crate::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let home = account("home");
    let foreign = account("foreign");
    private_cache(&pool, &home).await;
    private_cache(&pool, &foreign).await;
    let store = PgSignalRelayStore { pool: pool.clone() };
    let home_actor = ActorId::account(home.clone()).to_string();
    let foreign_actor = ActorId::account(foreign.clone()).to_string();
    let mut blocker = pool.get().await.unwrap();
    blocker
        .transaction::<_, PgTransactionError, _>(async |conn| {
            sql_query("SELECT pk FROM accounts WHERE principal_id=$1 AND station_id=$2 FOR UPDATE")
                .bind::<Text, _>(home.principal_id.as_str())
                .bind::<Text, _>(home.station_id.as_str())
                .execute(&mut *conn)
                .await?;
            let busy = store
                .advance(&home, "device", "realm", 1)
                .await
                .unwrap_err();
            assert_eq!(
                busy.conflict_code(),
                Some(coland_storage::ConflictCode::TemporarilyUnavailable)
            );
            assert_eq!(
                store
                    .delivered_through(&home_actor, "device", "realm")
                    .await
                    .unwrap(),
                0
            );
            Ok(())
        })
        .await
        .map_err(PgTransactionError::into_persistence)
        .unwrap();
    store.advance(&home, "device", "realm", 1).await.unwrap();
    assert_eq!(
        store
            .delivered_through(&home_actor, "device", "realm")
            .await
            .unwrap(),
        1
    );
    let mut conn = pool.get().await.unwrap();
    sql_query("WITH held AS MATERIALIZED(SELECT pk FROM accounts WHERE principal_id=$1 AND station_id=$2 FOR UPDATE) INSERT INTO account_lifecycle(account_pk,state,changed_at) SELECT pk,'erasure_pending',NOW() FROM held")
        .bind::<Text,_>(home.principal_id.as_str()).bind::<Text,_>(home.station_id.as_str()).execute(&mut *conn).await.unwrap();
    sql_query("DELETE FROM signal_relay_watermark WHERE actor_id=$1")
        .bind::<Text, _>(&home_actor)
        .execute(&mut *conn)
        .await
        .unwrap();
    drop(conn);
    store.advance(&home, "device", "realm", 2).await.unwrap();
    assert_eq!(
        store
            .delivered_through(&home_actor, "device", "realm")
            .await
            .unwrap(),
        0
    );
    store.advance(&foreign, "device", "realm", 3).await.unwrap();
    assert_eq!(
        store
            .delivered_through(&foreign_actor, "device", "realm")
            .await
            .unwrap(),
        3
    );
}
