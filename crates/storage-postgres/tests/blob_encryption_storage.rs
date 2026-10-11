mod support;

use arkret_models_collaboration::objects::blob::{
    BlobStorageEncryption, BlobStorageEncryptionScheme, BlobVisibility,
};
use coland_storage::{BlobRecord, BlobStore};
use coland_storage_postgres::{Db, PgBlobStore};
use diesel::sql_types::{Jsonb, Text};
use diesel_async::RunQueryDsl;

#[tokio::test]
async fn blob_encryption_survives_reconnect_and_sql_rejects_private_descriptors() {
    let url = support::contract_database_url();
    support::ensure_contract_database(&url).await;
    let pool = Db::connect(Some(&url), Default::default())
        .await
        .unwrap()
        .pool
        .unwrap();
    let store = PgBlobStore { pool: pool.clone() };
    for encryption in [
        None,
        Some(BlobStorageEncryption {
            scheme: BlobStorageEncryptionScheme::WholeFileV1,
        }),
        Some(BlobStorageEncryption {
            scheme: BlobStorageEncryptionScheme::StreamV1,
        }),
    ] {
        let sha256 = arkret_canonical::sha256_bytes(uuid::Uuid::now_v7().as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let blob_ref = format!("ak:blob:sha256:{sha256}");
        let record = BlobRecord {
            sha256: sha256.clone(),
            size_bytes: 4,
            storage_backend: "test".to_owned(),
            storage_key: sha256.clone(),
            media_type: "application/octet-stream".to_owned(),
            filename: None,
            realm_id: None,
            encryption,
            legal_hold: false,
            redacted: false,
            visibility: BlobVisibility::ActorPrivate,
            uploaded_by: "ak:did_core:web:blob-owner.example".to_owned(),
            created_at: chrono::Utc::now(),
        };
        store.put(&blob_ref, &record).await.unwrap();
        let reopened_pool = Db::connect(Some(&url), Default::default())
            .await
            .unwrap()
            .pool
            .unwrap();
        let reopened = PgBlobStore {
            pool: reopened_pool,
        };
        assert_eq!(
            reopened.get(&blob_ref).await.unwrap().unwrap().encryption,
            encryption
        );
        assert_eq!(
            reopened
                .snapshot_all()
                .await
                .unwrap()
                .into_iter()
                .find(|row| row.sha256 == sha256)
                .unwrap()
                .encryption,
            encryption
        );
        let mut changed = record.clone();
        changed.encryption = if encryption.is_some() {
            None
        } else {
            Some(BlobStorageEncryption {
                scheme: BlobStorageEncryptionScheme::WholeFileV1,
            })
        };
        assert!(store.put(&blob_ref, &changed).await.is_err());
        assert_eq!(
            store.get(&blob_ref).await.unwrap().unwrap().encryption,
            encryption
        );
        let mut connection = pool.get().await.unwrap();
        for payload in [
            serde_json::json!({}),
            serde_json::json!({"encryption":{"scheme":"unknown"}}),
            serde_json::json!({"encryption":{"scheme":"ak.blob.stream_aead.v1","key_ref":"private"}}),
            serde_json::json!({"encryption":{}}),
        ] {
            assert!(
                diesel::sql_query("UPDATE blobs SET payload=$2 WHERE id=$1")
                    .bind::<Text, _>(&blob_ref)
                    .bind::<Jsonb, _>(&payload)
                    .execute(&mut *connection)
                    .await
                    .is_err(),
                "{payload}"
            );
        }
        if encryption.is_some() {
            assert!(
                diesel::sql_query("UPDATE blobs SET media_type='image/png' WHERE id=$1")
                    .bind::<Text, _>(&blob_ref)
                    .execute(&mut *connection)
                    .await
                    .is_err()
            );
            assert!(
                diesel::sql_query(
                    r#"UPDATE blobs SET payload='{"encryption":null}'::jsonb WHERE id=$1"#
                )
                .bind::<Text, _>(&blob_ref)
                .execute(&mut *connection)
                .await
                .is_err()
            );
        }
        drop(connection);
        store.delete(&blob_ref).await.unwrap();
    }
}
