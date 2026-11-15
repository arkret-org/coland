//! Native recovery source closure, separate from inventory/MLS admission.

use arkret_wire::RecoveryCompletionAttestation;
use coland_storage::{DeliveryPolicyStoreRegistry as _, HumanPcrHistoryReader};
use coland_storage_postgres::{PgPersistenceStore, PgPool};
use diesel::sql_types::{Binary, Uuid};
use horme::RunQueryDsl as _;

pub(super) async fn require_source(
    pool: &PgPool,
    reader: &HumanPcrHistoryReader,
) -> RecoveryCompletionAttestation {
    PgPersistenceStore::new(pool.clone())
        .security_transactions()
        .human_content_recovery_source(reader)
        .await
        .unwrap()
}

pub(super) async fn refuse_ordinary(pool: &PgPool, reader: &HumanPcrHistoryReader) {
    let error = PgPersistenceStore::new(pool.clone())
        .security_transactions()
        .human_content_recovery_source(reader)
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("ordinary Device authorization"),
        "{error}"
    );
}

pub(super) async fn exercise(
    pool: &PgPool,
    reader: &HumanPcrHistoryReader,
    old_reader: &HumanPcrHistoryReader,
) {
    let persistence = PgPersistenceStore::new(pool.clone());
    let store = persistence.security_transactions();
    let source = require_source(pool, reader).await;
    assert_eq!(source.account_id, reader.account_id);
    assert_eq!(source.replacement_device_id, reader.device_id);
    assert_eq!(source.new_model_generation_ref, 2);
    assert_eq!(
        source.device_authorization_event_ref.event_id,
        reader
            .credential_device_binding
            .as_ref()
            .unwrap()
            .authorization_event_id
    );
    assert_eq!(
        source.device_authorization_event_ref.stream_position,
        source.reanchor_event_ref.stream_position + 1
    );
    assert!(
        store
            .human_content_recovery_source(old_reader)
            .await
            .is_err()
    );
    let mut changed = reader.clone();
    changed
        .credential_device_binding
        .as_mut()
        .unwrap()
        .authorization_event_id = old_reader
        .credential_device_binding
        .as_ref()
        .unwrap()
        .authorization_event_id
        .clone();
    assert!(store.human_content_recovery_source(&changed).await.is_err());
    changed = reader.clone();
    changed
        .credential_device_binding
        .as_mut()
        .unwrap()
        .model_generation_ref = 1;
    assert!(store.human_content_recovery_source(&changed).await.is_err());
    changed = reader.clone();
    changed.credential_expires_at = chrono::Utc::now() - chrono::Duration::seconds(1);
    assert!(store.human_content_recovery_source(&changed).await.is_err());
    changed = reader.clone();
    changed.account_id.station_id =
        arkret_wire::DidCoreId::new("ak:did_core:web:wrong-station.example").unwrap();
    assert!(store.human_content_recovery_source(&changed).await.is_err());

    let transaction = store
        .get(source.transaction_id.as_str())
        .await
        .unwrap()
        .unwrap();
    let id = uuid::Uuid::parse_str(
        source
            .transaction_id
            .as_str()
            .strip_prefix("ak:transaction:")
            .unwrap(),
    )
    .unwrap();
    // Expiry ends the old online exchange, not this accepted identity fact.
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "UPDATE recovery_sessions SET expires_at=now()-interval '1 second' WHERE transaction_id=$1",
    )
    .bind::<Uuid, _>(id)
    .execute(&mut *conn)
    .await
    .unwrap();
    drop(conn);
    assert_eq!(require_source(pool, reader).await, source);
    // A native current Device is insufficient if the immutable first signed
    // request no longer matches the accepted R/C closure.
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "UPDATE security_transactions SET canonical_request='\\x00'::bytea WHERE id=$1",
    )
    .bind::<Uuid, _>(id)
    .execute(&mut *conn)
    .await
    .unwrap();
    drop(conn);
    assert!(store.human_content_recovery_source(reader).await.is_err());
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("UPDATE security_transactions SET canonical_request=$2 WHERE id=$1")
        .bind::<Uuid, _>(id)
        .bind::<Binary, _>(&transaction.canonical_request)
        .execute(&mut *conn)
        .await
        .unwrap();
    drop(conn);
    assert_eq!(require_source(pool, reader).await, source);
}
