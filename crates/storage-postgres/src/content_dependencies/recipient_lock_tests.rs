//! Real PostgreSQL lock ordering and refusal checks. These structural fixtures
//! do not claim native root admission or continuing recipient qualification.

use diesel::sql_types::{Bool, Integer};
use diesel_async::AsyncConnection;

use super::*;

#[derive(QueryableByName)]
struct Flag {
    #[diesel(sql_type = Bool)]
    value: bool,
}

#[derive(QueryableByName)]
struct Backend {
    #[diesel(sql_type = Integer)]
    value: i32,
}

fn native_actor() -> ActorId {
    let fixture: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../arkret-spec/spec/v1/artifacts/fixtures/realm-actor-content-backup-fixture.json"
    )))
    .unwrap();
    serde_json::from_value(fixture["native_packet"]["actor_id"].clone()).unwrap()
}

fn subjects(actors: &[ActorId]) -> BTreeMap<String, ActorId> {
    actors
        .iter()
        .map(|actor| (actor.to_string(), actor.clone()))
        .collect()
}

async fn try_lock(conn: &mut AsyncPgConnection, key: &str) -> bool {
    sql_query("SELECT pg_try_advisory_xact_lock(hashtextextended($1,0)) AS value")
        .bind::<Text, _>(key)
        .get_result::<Flag>(&mut *conn)
        .await
        .unwrap()
        .value
}

async fn database_state(conn: &mut AsyncPgConnection) -> BTreeMap<String, Value> {
    #[derive(QueryableByName)]
    struct Name {
        #[diesel(sql_type = Text)]
        value: String,
    }
    #[derive(QueryableByName)]
    struct Data {
        #[diesel(sql_type = Jsonb)]
        value: Value,
    }
    let names = sql_query(
        "SELECT tablename AS value FROM pg_tables WHERE schemaname='public' ORDER BY tablename",
    )
    .load::<Name>(&mut *conn)
    .await
    .unwrap();
    let mut state = BTreeMap::new();
    for name in names {
        let table = name.value.replace('"', "\"\"");
        let row = sql_query(format!("SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb) AS value FROM public.\"{table}\" t"))
            .get_result::<Data>(&mut *conn).await.unwrap();
        state.insert(name.value, row.value);
    }
    let sequences = sql_query("SELECT COALESCE(jsonb_agg(to_jsonb(s) ORDER BY s.sequencename),'[]'::jsonb) AS value FROM pg_sequences s WHERE schemaname='public'")
        .get_result::<Data>(&mut *conn).await.unwrap();
    state.insert("__public_sequences".into(), sequences.value);
    state
}

#[tokio::test]
async fn root_recipient_prelocks_reject_foreign_missing_and_unsupported_without_writes() {
    let database = crate::test_database::TestDatabase::lease().await;
    let mut conn = database.pool().get().await.unwrap();
    let mut observer = database.pool().get().await.unwrap();
    let actor = native_actor();
    let realm = actor.as_realm_actor_id().unwrap().realm_id.clone();
    let mut foreign = actor.as_realm_actor_id().unwrap().clone();
    foreign.realm_id = RealmId::from_event_id(&arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [201; 32],
    ));
    let foreign = ActorId::realm(foreign);
    let service =
        ActorId::service(arkret_wire::DidCoreId::new("ak:did_core:web:other.example").unwrap());
    let before = database_state(&mut conn).await;
    for (subject, expected) in [
        (foreign, "native root package belongs to another Realm"),
        (actor, "accepted native backup namespace is absent"),
        (service, "root custodian has no full Account policy"),
    ] {
        let values = subjects(std::slice::from_ref(&subject));
        conn.transaction::<_, PgTransactionError, _>(async |conn| {
            let error = lock_local_root_subjects(conn, &realm, &values, &values)
                .await
                .unwrap_err()
                .into_persistence()
                .to_string();
            assert!(error.contains(expected), "{error}");
            if subject
                .as_realm_actor_id()
                .is_some_and(|id| id.realm_id != realm)
            {
                assert!(
                    try_lock(&mut observer, &format!("key-backup-series:{subject}")).await,
                    "a foreign Realm must be rejected before its actor-series lock"
                );
            }
            assert_eq!(database_state(conn).await, before);
            Ok(())
        })
        .await
        .map_err(PgTransactionError::into_persistence)
        .unwrap();
    }
    assert_eq!(database_state(&mut conn).await, before);
}

#[tokio::test]
async fn root_recipient_prelocks_keep_all_policies_before_sorted_actor_series() {
    let database = crate::test_database::TestDatabase::lease().await;
    let mut observer = database.pool().get().await.unwrap();
    let mut worker = database.pool().get().await.unwrap();
    let before = database_state(&mut observer).await;
    let native = native_actor();
    let realm = native.as_realm_actor_id().unwrap().realm_id.clone();
    let account = arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new("ak:did_core:web:holder.example").unwrap(),
        arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
    );
    let account_actor = ActorId::account(account.clone());
    let account_series_key = format!("key-backup-series:{account_actor}");
    let native_series_key = format!("key-backup-series:{native}");
    let policy_key = format!(
        "recovery-policy:{}",
        arkret_canonical::canonical_json_string(&account).unwrap()
    );
    let values = subjects(&[native, account_actor.clone()]);
    assert_eq!(values.values().next(), Some(&account_actor));
    let worker_pid = sql_query("SELECT pg_backend_pid() AS value")
        .get_result::<Backend>(&mut *worker)
        .await
        .unwrap()
        .value;
    sql_query("BEGIN").execute(&mut *observer).await.unwrap();
    assert!(try_lock(&mut observer, &account_series_key).await);
    let pending = tokio::spawn(async move {
        worker
            .transaction::<_, PgTransactionError, _>(async |conn| {
                // No Account policy row is needed to take its existing lock.
                // Qualification remains the later current-recipient check.
                let error = lock_local_root_subjects(conn, &realm, &values, &values)
                    .await
                    .unwrap_err()
                    .into_persistence()
                    .to_string();
                Ok(error)
            })
            .await
            .map_err(PgTransactionError::into_persistence)
            .unwrap()
    });
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let blocked = sql_query("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND NOT granted) AS value")
                .bind::<Integer,_>(worker_pid).get_result::<Flag>(&mut *observer).await.unwrap().value;
            if blocked {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(
        !try_lock(&mut observer, &policy_key).await,
        "the worker must already hold the Account policy lock"
    );
    assert!(
        try_lock(&mut observer, &native_series_key).await,
        "native actor-series must wait for the earlier Account series"
    );
    sql_query("COMMIT").execute(&mut *observer).await.unwrap();
    let error = pending.await.unwrap();
    assert!(
        error.contains("accepted native backup namespace is absent"),
        "{error}"
    );
    assert_eq!(database_state(&mut observer).await, before);
}
