//! Restart-semantics integration tests for the five data planes that used to
//! be memory-only in production (realm_meta, messages, device_keys,
//! one_time_keys, member identity). Each case writes through one connection
//! pool, drops it, reconnects with a fresh pool (equivalent to a process
//! restart) and verifies the rows survive.
//!
//! Every case requires `COLAND_TEST_DATABASE_URL` or `DATABASE_URL`; without one
//! they fail rather than skip, because a silent skip here would leave the
//! durable planes unverified. The database they build is named for the
//! migration it came from -- see `tests/support/mod.rs`.

mod support;

use coland_storage::contract_tests::{
    assert_device_key_store_contract, assert_member_identity_store_contract,
    assert_message_store_contract, assert_one_time_key_store_contract,
    assert_realm_meta_store_contract,
};
use coland_storage::{
    DeviceKeyStore, MessageRecord, MessageStore, OneTimeKeyStore, RealmMetaRecord, RealmMetaStore,
};
use coland_storage_postgres::{
    Db, PgDeviceKeyStore, PgMemberIdentityStore, PgMessageStore, PgOneTimeKeyStore, PgPool,
    PgRealmMetaStore,
};

#[path = "../../test-support/src/device_authorization_history.rs"]
#[allow(dead_code)]
mod device_authorization_history;
#[path = "../../test-support/src/pcr_genesis.rs"]
#[allow(dead_code)]
mod pcr_genesis;

/// The founding device of a genuinely signed PCR genesis the Station admitted
/// through its registered unit. Storage admission here does not stand in for
/// HTTP admission coverage.
async fn device_authority(pool: &PgPool) -> coland_storage::DeviceRevocationGateSelector {
    use diesel::sql_query;
    use diesel::sql_types::Text;
    use diesel_async::RunQueryDsl;
    #[derive(diesel::QueryableByName)]
    struct Station {
        #[diesel(sql_type=Text)]
        station_id: String,
    }
    let mut conn = pool.get().await.unwrap();
    sql_query("INSERT INTO device_inventory_station(singleton,station_id) VALUES(TRUE,'ak:did_core:web:device-restart.example') ON CONFLICT DO NOTHING").execute(&mut *conn).await.unwrap();
    let station = sql_query("SELECT station_id FROM device_inventory_station WHERE singleton")
        .get_result::<Station>(&mut *conn)
        .await
        .unwrap();
    drop(conn);
    pcr_genesis::PcrGenesisFixture::new(device_authorization_history::did_web_station(
        &station.station_id.parse().unwrap(),
    ))
    .admit_founding_device(&coland_storage_postgres::PgPersistenceStore::new(
        pool.clone(),
    ))
    .await
    .expect("accepted PCR genesis")
}

/// Build a fresh pool against the configured database. Migrations are
/// idempotent, so a second `Db::connect` behaves like a restarted process
/// attaching to the same database.
async fn fresh_pool() -> PgPool {
    let url = support::contract_database_url();
    support::ensure_contract_database(&url).await;
    Db::connect(Some(&url), Default::default())
        .await
        .expect("initialize test database")
        .pool
        .expect("a configured URL always yields a pool")
}

/// `Db::connect` re-runs the embedded migrations on every call; two
/// concurrent first-time migration runs race on catalog rows (`pg_type`
/// duplicate key), so every case holds this guard for its whole duration,
/// matching the `store_contracts.rs` pattern.
static DB_GUARD: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Round every timestamp through Postgres precision (microseconds) so stored
/// rows compare equal to the in-memory originals.
fn database_now() -> chrono::DateTime<chrono::Utc> {
    let now = chrono::Utc::now();
    chrono::DateTime::from_timestamp_micros(now.timestamp_micros()).expect("micros round-trip")
}

#[tokio::test]
async fn postgres_realm_meta_survives_restart() {
    let _db_guard = DB_GUARD.lock().await;
    let pool = fresh_pool().await;
    let store = PgRealmMetaStore { pool: pool.clone() };
    let namespace = format!("postgres-realm-meta-{}", uuid::Uuid::now_v7());
    assert_realm_meta_store_contract(&store, &namespace).await;

    let realm_id = format!("ak:realm:{namespace}-restart");
    let now = database_now();
    let record = RealmMetaRecord {
        owner: format!("did:web:{namespace}-owner.example"),
        deleted: false,
        discoverability: "public".to_owned(),
        history_access: "since_join".to_owned(),
        preview_policy: None,
        preview_policy_digest: None,
        asset_privacy_policy: None,
        asset_privacy_policy_digest: None,
        encryption_profile: Some("mls_rfc9420".to_owned()),
        plaintext_visible_services: Default::default(),
        plaintext_visible_service_classes: Default::default(),
        minimal_metadata_realm: false,
        created_at: now,
        updated_at: now,
    };
    store
        .put(&realm_id, &record)
        .await
        .expect("write realm meta before restart");
    drop(pool);

    // After a restart the Realm owner must still resolve; this is the read
    // startup hydration performs before lawful controller-issued Agent grants
    // can pass the `grant_exceeds_issuer_authority` check.
    let restarted_pool = fresh_pool().await;
    let restarted = PgRealmMetaStore {
        pool: restarted_pool,
    };
    assert_eq!(
        restarted
            .get(&realm_id)
            .await
            .expect("read realm meta after restart"),
        Some(record),
        "realm owner must survive restart"
    );
}

#[tokio::test]
async fn postgres_messages_survive_restart_and_dedup() {
    let _db_guard = DB_GUARD.lock().await;
    let pool = fresh_pool().await;
    let store = PgMessageStore { pool: pool.clone() };
    let namespace = format!("postgres-messages-{}", uuid::Uuid::now_v7());
    assert_message_store_contract(&store, &namespace).await;
    drop(pool);

    // The contract leaves `second` in place; after a restart the snapshot
    // projection (`messages_for_realm`) must still see it, and replaying the
    // same Event id must dedup instead of double-storing.
    let restarted_pool = fresh_pool().await;
    let restarted = PgMessageStore {
        pool: restarted_pool,
    };
    let realm_id = format!("ak:realm:{namespace}");
    let listed = restarted
        .list_for_realm(&realm_id, 100)
        .await
        .expect("list realm messages after restart");
    assert_eq!(
        listed.len(),
        1,
        "snapshot message projection survives restart"
    );
    let replayed = MessageRecord {
        content: serde_json::json!({"body": "replayed-with-different-content"}),
        ..listed[0].clone()
    };
    restarted
        .put(&replayed)
        .await
        .expect("replay projected message after restart");
    let after_replay = restarted
        .list_for_realm(&realm_id, 100)
        .await
        .expect("list realm messages after replay");
    assert_eq!(after_replay, listed, "idempotency dedup survives restart");
}

#[tokio::test]
async fn postgres_device_keys_survive_restart() {
    let _db_guard = DB_GUARD.lock().await;
    let pool = fresh_pool().await;
    let store = PgDeviceKeyStore { pool: pool.clone() };
    let authorization = device_authority(&pool).await;
    assert_device_key_store_contract(&store, &authorization).await;
    drop(pool);

    let restarted_pool = fresh_pool().await;
    let restarted = PgDeviceKeyStore {
        pool: restarted_pool,
    };
    let actor = authorization.principal_id.to_string();
    let device_id = authorization.device_id.clone();
    let bundle = restarted
        .get(&actor, &device_id)
        .await
        .expect("read device key bundle after restart")
        .expect("uploaded device key bundle survives restart");
    assert_eq!(bundle["rotated"], serde_json::json!(true));
}

#[tokio::test]
async fn postgres_one_time_keys_claim_survives_restart() {
    let _db_guard = DB_GUARD.lock().await;
    let pool = fresh_pool().await;
    let store = PgOneTimeKeyStore { pool: pool.clone() };
    let namespace = format!("postgres-one-time-keys-{}", uuid::Uuid::now_v7());
    let authorization = device_authority(&pool).await;
    assert_one_time_key_store_contract(&store, &namespace, &authorization).await;

    let actor = authorization.principal_id.to_string();
    let device_id = authorization.device_id.clone();
    let pooled =
        serde_json::json!({"key_id": format!("curve25519:{namespace}-restart"), "key": "restart"});
    store
        .put(&authorization, vec![pooled.clone()])
        .await
        .expect("pool one-time key before restart");
    drop(pool);

    let restarted_pool = fresh_pool().await;
    let restarted = PgOneTimeKeyStore {
        pool: restarted_pool,
    };
    assert_eq!(
        restarted
            .claim(&actor, &device_id)
            .await
            .expect("claim one-time key after restart"),
        Some(pooled),
        "claim must return a key from the pre-restart pool"
    );
    assert_eq!(
        restarted
            .claim(&actor, &device_id)
            .await
            .expect("claim drained pool after restart"),
        None
    );
}

#[tokio::test]
async fn postgres_member_identity_handle_claim_cache_contract() {
    let _db_guard = DB_GUARD.lock().await;
    let pool = fresh_pool().await;
    let store = PgMemberIdentityStore { pool: pool.clone() };
    let namespace = format!("postgres-member-identity-{}", uuid::Uuid::now_v7());
    assert_member_identity_store_contract(&store, &namespace).await;

    // Accepted identity restart coverage lives in the production UoW target;
    // this contract exercises only the independent handle-claim cache.
}
