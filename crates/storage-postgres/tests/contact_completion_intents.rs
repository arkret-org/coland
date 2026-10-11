//! Real PostgreSQL proof that the Contact completion ledger the authority
//! commit stages into exists in the initial schema and enforces its closed
//! staged/terminal shape and binding uniqueness.
//!
//! Requires `COLAND_TEST_DATABASE_URL` or `DATABASE_URL`; the lease gives each
//! case an isolated, freshly migrated database.

use arkret_wire::{AccountId, ActorId, DidCoreId};
use coland_storage::{ContactStore, PersistenceError};
use coland_storage_postgres::PgContactStore;
use coland_storage_postgres::test_database::TestDatabase;
use diesel::sql_query;
use diesel::sql_types::{Jsonb, Nullable, Text};
use diesel_async::RunQueryDsl;
use serde_json::json;

fn actor() -> ActorId {
    ActorId::account(AccountId::new(
        DidCoreId::new("ak:did_core:web:alice-contact.example").unwrap(),
        DidCoreId::new("ak:did_core:web:contact-station.example").unwrap(),
    ))
}

fn binding(actor: &ActorId, key: &str) -> serde_json::Value {
    json!({
        "authenticated_actor": actor,
        "idempotency_key": key,
        "request_hash": format!("sha256:{}", "a".repeat(64)),
    })
}

async fn insert(
    conn: &mut diesel_async::AsyncPgConnection,
    event_id: &str,
    binding: serde_json::Value,
    intent: Option<serde_json::Value>,
    result: Option<serde_json::Value>,
) -> diesel::QueryResult<usize> {
    sql_query(
        "INSERT INTO contact_completion_intents \
         (event_id,event_digest,event_json,binding,intent,intent_digest,committed_ref,result,created_at) \
         VALUES ($1,$2,'{}'::jsonb,$3,$4,'sha256:' || repeat('d',64),'{}'::jsonb,$5,now())",
    )
    .bind::<Text, _>(event_id)
    .bind::<Text, _>(format!("{event_id}:digest"))
    .bind::<Jsonb, _>(binding)
    .bind::<Nullable<Jsonb>, _>(intent)
    .bind::<Nullable<Jsonb>, _>(result)
    .execute(conn)
    .await
}

#[tokio::test]
async fn contact_completion_ledger_is_empty_and_readable_on_a_fresh_schema() {
    let database = TestDatabase::lease().await;
    let contacts = PgContactStore {
        pool: database.pool(),
    };
    let actor = actor();
    assert!(
        contacts
            .completion_for_request(&actor, "contact-commit-1", "sha256:unused")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        contacts
            .committed_completion_intents(16, None)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn contact_completion_ledger_binds_one_request_key_and_one_terminal_shape() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let actor = actor();
    let mut conn = pool.get().await.unwrap();

    insert(
        &mut conn,
        "event-staged",
        binding(&actor, "contact-commit-1"),
        Some(json!({"plan": "frozen"})),
        None,
    )
    .await
    .unwrap();
    // One authenticated actor and idempotency key name exactly one Event.
    assert!(
        insert(
            &mut conn,
            "event-rebound",
            binding(&actor, "contact-commit-1"),
            Some(json!({"plan": "other"})),
            None,
        )
        .await
        .is_err()
    );
    // A row is either the staged plan or its terminal result, never both or neither.
    for (event_id, intent, result) in [
        ("event-empty", None, None),
        (
            "event-both",
            Some(json!({"plan": "frozen"})),
            Some(json!({"result": "accepted"})),
        ),
    ] {
        assert!(
            insert(
                &mut conn,
                event_id,
                binding(&actor, event_id),
                intent,
                result,
            )
            .await
            .is_err(),
            "{event_id} must violate the terminal shape"
        );
    }
    // Delivery is only recorded together with the terminal result.
    assert!(
        sql_query(
            "UPDATE contact_completion_intents SET delivery_outbox_id='outbox-1' \
             WHERE event_id='event-staged'",
        )
        .execute(&mut conn)
        .await
        .is_err()
    );
    drop(conn);

    // The request lookup reads the staged row by its binding and refuses a
    // different canonical request under the same key.
    let contacts = PgContactStore { pool };
    assert!(matches!(
        contacts
            .completion_for_request(&actor, "contact-commit-1", "sha256:different")
            .await,
        Err(PersistenceError::Conflict(_))
    ));
    assert!(
        contacts
            .completion_for_request(&actor, "contact-commit-2", "sha256:unused")
            .await
            .unwrap()
            .is_none()
    );
}
