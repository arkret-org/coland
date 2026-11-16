//! Actual PostgreSQL cache ownership and writer-lock checks, not native authority proof.
use diesel::sql_types::{Array, Integer};
use diesel_async::SimpleAsyncConnection as _;

use super::*;
use crate::test_database::TestDatabase;

#[derive(diesel::QueryableByName)]
struct Number {
    #[diesel(sql_type = BigInt)]
    value: i64,
}

#[derive(diesel::QueryableByName)]
struct Process {
    #[diesel(sql_type = Integer)]
    pid: i32,
}

#[derive(diesel::QueryableByName)]
struct Blocking {
    #[diesel(sql_type = Array<Integer>)]
    pids: Vec<i32>,
}

fn account(station: &str) -> AccountId {
    AccountId::new(
        DidCoreId::new("ak:did_core:web:private-cache-holder.example").unwrap(),
        DidCoreId::new(format!("ak:did_core:web:{station}.example")).unwrap(),
    )
}

async fn insert_account(conn: &mut AsyncPgConnection, account: &AccountId) -> i64 {
    sql_query("INSERT INTO accounts(principal_id,station_id,payload) VALUES($1,$2,'{}'::jsonb) RETURNING pk AS value")
        .bind::<Text,_>(account.principal_id.as_str()).bind::<Text,_>(account.station_id.as_str())
        .get_result::<Number>(conn).await.unwrap().value
}

async fn terminal_cache(conn: &mut AsyncPgConnection, pk: i64) {
    sql_query("INSERT INTO account_lifecycle(account_pk,state,changed_at) VALUES($1,'erasure_pending',NOW()) ON CONFLICT(account_pk) DO UPDATE SET state=EXCLUDED.state,changed_at=EXCLUDED.changed_at")
        .bind::<BigInt,_>(pk).execute(conn).await.unwrap();
}

async fn global(conn: &mut AsyncPgConnection, account: &AccountId, key: &str) {
    sql_query("SELECT project_account_global_value($1,'station_cas',$2,'{\"value\":\"private cache payload\"}'::jsonb,FALSE)")
        .bind::<Text,_>(ActorId::account(account.clone()).to_string()).bind::<Text,_>(key)
        .execute(conn).await.unwrap();
}

async fn notification(
    conn: &mut AsyncPgConnection,
    account: &AccountId,
    controller_pk: i64,
    artifact: &str,
) -> PersistenceResult<usize> {
    sql_query("INSERT INTO notifications(id,recipient_actor_id,controller_account_pk,recipient_id,source_account_artifact_kind,source_account_artifact_id,projection_action,projection_data,created_at) VALUES($1,$2,$3,'ak:did_core:web:runtime.example','agent_runtime_approval',$4,'upsert','{\"value\":\"private preview\"}'::jsonb,NOW())")
        .bind::<diesel::sql_types::Uuid,_>(uuid::Uuid::now_v7())
        .bind::<Text,_>(ActorId::account(account.clone()).to_string())
        .bind::<BigInt,_>(controller_pk).bind::<Text,_>(artifact)
        .execute(conn).await.map_err(PersistenceError::database)
}

async fn count(
    conn: &mut AsyncPgConnection,
    table: &str,
    column: &str,
    account: &AccountId,
) -> i64 {
    assert!(matches!(
        (table, column),
        ("account_global_versions", "actor_key") | ("notifications", "recipient_actor_id")
    ));
    sql_query(format!(
        "SELECT COUNT(*)::bigint AS value FROM {table} WHERE {column}=$1"
    ))
    .bind::<Text, _>(ActorId::account(account.clone()).to_string())
    .get_result::<Number>(conn)
    .await
    .unwrap()
    .value
}

async fn clear_private_cache(conn: &mut AsyncPgConnection, account: &AccountId) {
    let actor = ActorId::account(account.clone()).to_string();
    sql_query("DELETE FROM notifications WHERE recipient_actor_id=$1")
        .bind::<Text, _>(&actor)
        .execute(&mut *conn)
        .await
        .unwrap();
    sql_query("DELETE FROM account_global_versions WHERE actor_key=$1")
        .bind::<Text, _>(&actor)
        .execute(&mut *conn)
        .await
        .unwrap();
    sql_query("DELETE FROM account_global_channel_clocks WHERE actor_key=$1")
        .bind::<Text, _>(&actor)
        .execute(&mut *conn)
        .await
        .unwrap();
}

#[tokio::test]
async fn terminal_private_projection_skips_only_the_exact_account_and_keeps_transaction_live() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let mut conn = pool.get().await.unwrap();
    let erased = account("owning-station");
    let other = account("other-station");
    let erased_pk = insert_account(&mut conn, &erased).await;
    let other_pk = insert_account(&mut conn, &other).await;
    global(&mut conn, &erased, "before").await;
    global(&mut conn, &other, "before").await;
    assert_eq!(
        notification(&mut conn, &erased, erased_pk, "before")
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        notification(&mut conn, &other, other_pk, "before")
            .await
            .unwrap(),
        1
    );
    terminal_cache(&mut conn, erased_pk).await;
    clear_private_cache(&mut conn, &erased).await;
    assert!(!is_active_human_account(&mut conn, &erased).await.unwrap());
    assert!(is_active_human_account(&mut conn, &other).await.unwrap());
    assert!(
        require_active_human_account(&mut conn, &erased)
            .await
            .is_err()
    );
    let other_before = count(&mut conn, "account_global_versions", "actor_key", &other).await;
    conn.batch_execute("BEGIN").await.unwrap();
    global(&mut conn, &erased, "late").await;
    assert_eq!(
        notification(&mut conn, &erased, erased_pk, "late")
            .await
            .unwrap(),
        0
    );
    // The same transaction still publishes a different, active Account.
    global(&mut conn, &other, "after").await;
    assert_eq!(
        notification(&mut conn, &other, other_pk, "after")
            .await
            .unwrap(),
        1
    );
    conn.batch_execute("COMMIT").await.unwrap();
    assert_eq!(
        count(&mut conn, "account_global_versions", "actor_key", &erased).await,
        0
    );
    assert_eq!(
        count(&mut conn, "notifications", "recipient_actor_id", &erased).await,
        0
    );
    assert!(count(&mut conn, "account_global_versions", "actor_key", &other).await > other_before);
    assert_eq!(
        count(&mut conn, "notifications", "recipient_actor_id", &other).await,
        2
    );
    assert!(
        notification(&mut conn, &other, erased_pk, "wrong-owner")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn private_cache_purge_waits_for_inflight_account_writer_and_blocks_late_recreation() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let holder = account("owning-station");
    let mut writer = pool.get().await.unwrap();
    let pk = insert_account(&mut writer, &holder).await;
    writer.batch_execute("BEGIN").await.unwrap();
    assert!(is_active_human_account(&mut writer, &holder).await.unwrap());
    let writer_pid = sql_query("SELECT pg_backend_pid() AS pid")
        .get_result::<Process>(&mut *writer)
        .await
        .unwrap()
        .pid;
    let mut eraser = pool.get().await.unwrap();
    let eraser_pid = sql_query("SELECT pg_backend_pid() AS pid")
        .get_result::<Process>(&mut *eraser)
        .await
        .unwrap()
        .pid;
    let target = holder.clone();
    let task = tokio::spawn(async move {
        eraser.batch_execute("BEGIN").await.unwrap();
        sql_query("SELECT pk AS value FROM accounts WHERE pk=$1 FOR UPDATE")
            .bind::<BigInt, _>(pk)
            .get_result::<Number>(&mut *eraser)
            .await
            .unwrap();
        terminal_cache(&mut eraser, pk).await;
        clear_private_cache(&mut eraser, &target).await;
        eraser.batch_execute("COMMIT").await.unwrap();
    });
    let mut monitor = pool.get().await.unwrap();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let waiting = sql_query("SELECT pg_blocking_pids($1) AS pids")
            .bind::<Integer, _>(eraser_pid)
            .get_result::<Blocking>(&mut *monitor)
            .await
            .unwrap();
        if waiting.pids.contains(&writer_pid) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "eraser never waited on the actual Account writer lock"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    global(&mut writer, &holder, "inflight").await;
    writer.batch_execute("COMMIT").await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(10), task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        count(
            &mut monitor,
            "account_global_versions",
            "actor_key",
            &holder
        )
        .await,
        0
    );
    global(&mut monitor, &holder, "late").await;
    assert_eq!(
        count(
            &mut monitor,
            "account_global_versions",
            "actor_key",
            &holder
        )
        .await,
        0
    );
}

#[tokio::test]
async fn private_account_lookup_database_failure_is_not_a_skipped_recipient() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let holder = account("owning-station");
    let mut conn = pool.get().await.unwrap();
    insert_account(&mut conn, &holder).await;
    conn.batch_execute("BEGIN; CREATE OR REPLACE FUNCTION public.account_private_state_allowed(principal TEXT,station TEXT) RETURNS BOOLEAN LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'actual Account lookup failure'; END $$;").await.unwrap();
    let result = is_active_human_account(&mut conn, &holder).await;
    // Rollback restores the owning function even if the assertion fails, so a
    // reusable test lease cannot retain the injected function definition.
    conn.batch_execute("ROLLBACK").await.unwrap();
    assert!(result.is_err());
    assert!(is_active_human_account(&mut conn, &holder).await.unwrap());
}

async fn wait_for_blocker(conn: &mut AsyncPgConnection, waiting: i32, blocker: i32) {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let blocked = sql_query("SELECT pg_blocking_pids($1) AS pids")
            .bind::<Integer, _>(waiting)
            .get_result::<Blocking>(&mut *conn)
            .await
            .unwrap();
        if blocked.pids.contains(&blocker) {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "expected real Account/source lock wait was not observed"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn status_only_terminal_writer_precedes_permission_reader_without_stale_payload() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let holder = account("owning-station");
    let mut transition = pool.get().await.unwrap();
    let pk = insert_account(&mut transition, &holder).await;
    transition
        .batch_execute("BEGIN ISOLATION LEVEL READ COMMITTED")
        .await
        .unwrap();
    let transition_pid = sql_query("SELECT pg_backend_pid() AS pid")
        .get_result::<Process>(&mut *transition)
        .await
        .unwrap()
        .pid;
    sql_query("SELECT pk AS value FROM accounts WHERE pk=$1 FOR UPDATE")
        .bind::<BigInt, _>(pk)
        .get_result::<Number>(&mut *transition)
        .await
        .unwrap();
    // This transition only locks accounts and changes lifecycle. It deliberately
    // does not UPDATE accounts, matching PgAccountLifecycleStore::put.
    terminal_cache(&mut transition, pk).await;
    let mut writer = pool.get().await.unwrap();
    let writer_pid = sql_query("SELECT pg_backend_pid() AS pid")
        .get_result::<Process>(&mut *writer)
        .await
        .unwrap()
        .pid;
    let target = holder.clone();
    let task = tokio::spawn(async move {
        writer
            .batch_execute("BEGIN ISOLATION LEVEL READ COMMITTED; SET LOCAL lock_timeout='10s'")
            .await
            .unwrap();
        let allowed = is_active_human_account(&mut writer, &target).await;
        let denied = require_active_human_account(&mut writer, &target).await;
        let inserted = notification(&mut writer, &target, pk, "late").await;
        writer.batch_execute("ROLLBACK").await.unwrap();
        (allowed, denied, inserted)
    });
    let mut monitor = pool.get().await.unwrap();
    wait_for_blocker(&mut monitor, writer_pid, transition_pid).await;
    transition.batch_execute("COMMIT").await.unwrap();
    let (allowed, denied, inserted) =
        tokio::time::timeout(std::time::Duration::from_secs(15), task)
            .await
            .unwrap()
            .unwrap();
    assert!(!allowed.unwrap());
    assert!(denied.is_err());
    assert_eq!(inserted.unwrap(), 0);
    assert_eq!(
        count(&mut monitor, "notifications", "recipient_actor_id", &holder).await,
        0
    );
}

#[tokio::test]
async fn terminal_cache_update_never_waits_for_the_erasers_account_lock() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let holder = account("owning-station");
    let mut writer = pool.get().await.unwrap();
    let pk = insert_account(&mut writer, &holder).await;
    notification(&mut writer, &holder, pk, "before")
        .await
        .unwrap();
    writer
        .batch_execute("BEGIN; SET LOCAL lock_timeout='2s'")
        .await
        .unwrap();
    // Hold the real source row before the terminal transition. The later
    // UPDATE invokes the production AFTER UPDATE global projection trigger.
    sql_query("SELECT COUNT(*)::bigint AS value FROM (SELECT id FROM notifications WHERE recipient_actor_id=$1 FOR UPDATE) AS locked")
        .bind::<Text, _>(ActorId::account(holder.clone()).to_string())
        .get_result::<Number>(&mut *writer).await.unwrap();
    let writer_pid = sql_query("SELECT pg_backend_pid() AS pid")
        .get_result::<Process>(&mut *writer)
        .await
        .unwrap()
        .pid;
    let mut eraser = pool.get().await.unwrap();
    terminal_cache(&mut eraser, pk).await;
    let eraser_pid = sql_query("SELECT pg_backend_pid() AS pid")
        .get_result::<Process>(&mut *eraser)
        .await
        .unwrap()
        .pid;
    let target = holder.clone();
    let task = tokio::spawn(async move {
        eraser
            .batch_execute("BEGIN; SET LOCAL lock_timeout='10s'")
            .await
            .unwrap();
        sql_query("SELECT pk AS value FROM accounts WHERE pk=$1 FOR UPDATE")
            .bind::<BigInt, _>(pk)
            .get_result::<Number>(&mut *eraser)
            .await
            .unwrap();
        clear_private_cache(&mut eraser, &target).await;
        eraser.batch_execute("COMMIT").await.unwrap();
    });
    let mut monitor = pool.get().await.unwrap();
    wait_for_blocker(&mut monitor, eraser_pid, writer_pid).await;
    let update = sql_query("UPDATE notifications SET projection_data=jsonb_build_object('late','private preview') WHERE recipient_actor_id=$1")
        .bind::<Text, _>(ActorId::account(holder.clone()).to_string())
        .execute(&mut *writer).await;
    // Always release the source lock before asserting, including a regression
    // that hits lock_timeout. No reusable database lease keeps a blocked task.
    writer
        .batch_execute(if update.is_ok() { "COMMIT" } else { "ROLLBACK" })
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(15), task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(update.unwrap(), 1);
    assert_eq!(
        count(&mut monitor, "notifications", "recipient_actor_id", &holder).await,
        0
    );
    assert_eq!(
        count(
            &mut monitor,
            "account_global_versions",
            "actor_key",
            &holder
        )
        .await,
        0
    );
}

#[tokio::test]
async fn private_permission_reader_rejects_frozen_transaction_snapshots() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let holder = account("owning-station");
    let mut conn = pool.get().await.unwrap();
    insert_account(&mut conn, &holder).await;
    for isolation in ["REPEATABLE READ", "SERIALIZABLE"] {
        conn.batch_execute(&format!("BEGIN ISOLATION LEVEL {isolation}"))
            .await
            .unwrap();
        let result = is_active_human_account(&mut conn, &holder).await;
        conn.batch_execute("ROLLBACK").await.unwrap();
        assert!(
            result.is_err(),
            "a frozen snapshot cannot authorize private writes"
        );
    }
    assert!(is_active_human_account(&mut conn, &holder).await.unwrap());
}

#[tokio::test]
async fn active_projection_contention_is_typed_retryable_and_terminal_projection_is_skipped() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let holder = account("owning-station");
    let mut transition = pool.get().await.unwrap();
    let pk = insert_account(&mut transition, &holder).await;
    transition.batch_execute("BEGIN").await.unwrap();
    sql_query("SELECT pk AS value FROM accounts WHERE pk=$1 FOR UPDATE")
        .bind::<BigInt, _>(pk)
        .get_result::<Number>(&mut *transition)
        .await
        .unwrap();
    let mut writer = pool.get().await.unwrap();
    let result = sql_query(r#"SELECT project_account_global_value($1,'device_lists',$1,'{"private":"cache"}'::jsonb,FALSE)"#)
        .bind::<Text, _>(ActorId::account(holder.clone()).to_string())
        .execute(&mut *writer).await;
    let error = result.expect_err("an active, locked Account must not be treated as erased");
    assert!(matches!(
        &error,
        horme::Error::Query(diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::SerializationFailure,
            _
        ))
    ));
    let error = crate::persistence_query_error(error);
    assert_eq!(
        error.conflict_code(),
        Some(coland_storage::ConflictCode::TemporarilyUnavailable)
    );
    assert_eq!(
        count(&mut writer, "account_global_versions", "actor_key", &holder).await,
        0
    );
    // The exact same busy Account becomes a skipped target only after its
    // actual terminal lifecycle write is committed, never on contention alone.
    terminal_cache(&mut transition, pk).await;
    transition.batch_execute("COMMIT").await.unwrap();
    global(&mut writer, &holder, "late").await;
    assert_eq!(
        count(&mut writer, "account_global_versions", "actor_key", &holder).await,
        0
    );
    assert_eq!(
        notification(&mut writer, &holder, pk, "late")
            .await
            .unwrap(),
        0
    );
    // Other real PostgreSQL failures retain Database classification.
    let other = sql_query(
        "DO $$ BEGIN RAISE EXCEPTION 'actual check failure' USING ERRCODE='23514'; END $$",
    )
    .execute(&mut *writer)
    .await
    .unwrap_err();
    assert!(matches!(
        crate::persistence_query_error(other),
        PersistenceError::Database(_)
    ));
    let denied = crate::PgTransactionError::Storage(PersistenceError::Conflict(
        "device_revoked: original denial".into(),
    ))
    .into_persistence();
    assert_eq!(
        denied.conflict_code(),
        Some(coland_storage::ConflictCode::DeviceRevoked)
    );
}

#[tokio::test]
async fn derived_projection_share_precedes_terminal_account_writer() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let holder = account("owning-station");
    let mut writer = pool.get().await.unwrap();
    let pk = insert_account(&mut writer, &holder).await;
    writer.batch_execute("BEGIN").await.unwrap();
    // No permission helper is called here: the production global projection
    // itself must retain the full-Account SHARE barrier through COMMIT.
    global(&mut writer, &holder, "inflight").await;
    let writer_pid = sql_query("SELECT pg_backend_pid() AS pid")
        .get_result::<Process>(&mut *writer)
        .await
        .unwrap()
        .pid;
    let mut transition = pool.get().await.unwrap();
    let transition_pid = sql_query("SELECT pg_backend_pid() AS pid")
        .get_result::<Process>(&mut *transition)
        .await
        .unwrap()
        .pid;
    let target = holder.clone();
    let task = tokio::spawn(async move {
        transition
            .batch_execute("BEGIN; SET LOCAL lock_timeout='10s'")
            .await
            .unwrap();
        sql_query("SELECT pk AS value FROM accounts WHERE pk=$1 FOR UPDATE")
            .bind::<BigInt, _>(pk)
            .get_result::<Number>(&mut *transition)
            .await
            .unwrap();
        terminal_cache(&mut transition, pk).await;
        clear_private_cache(&mut transition, &target).await;
        transition.batch_execute("COMMIT").await.unwrap();
    });
    let mut monitor = pool.get().await.unwrap();
    wait_for_blocker(&mut monitor, transition_pid, writer_pid).await;
    writer.batch_execute("COMMIT").await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(15), task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        count(
            &mut monitor,
            "account_global_versions",
            "actor_key",
            &holder
        )
        .await,
        0
    );
    global(&mut monitor, &holder, "late").await;
    assert_eq!(
        count(
            &mut monitor,
            "account_global_versions",
            "actor_key",
            &holder
        )
        .await,
        0
    );
}
