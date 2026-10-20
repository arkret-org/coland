use super::{
    BigInt, BlobRecord, BlobStore, Bool, Jsonb, Nullable, OptionalExtension, PersistenceError,
    PersistenceResult, PgPool, QueryableByName, RunQueryDsl, Text, Timestamptz, Value, async_trait,
    pg_conn, sql_query,
};
pub struct PgBlobStore {
    pub pool: PgPool,
}

pub(crate) async fn blob_for_delivery_in_connection(
    conn: &mut diesel_async::AsyncPgConnection,
    blob_ref: &arkret_wire::BlobRef,
) -> PersistenceResult<Option<BlobRecord>> {
    sql_query("SELECT sha256,size_bytes,storage_backend,storage_key,media_type,filename,realm_id,NULLIF(payload->'encryption','null'::jsonb) AS encryption,legal_hold,redacted,visibility,uploaded_by,created_at FROM blobs WHERE id=$1 FOR SHARE")
        .bind::<Text,_>(blob_ref.as_str()).get_result::<BlobRow>(&mut *conn).await.optional()
        .map_err(PersistenceError::database).and_then(|row| row.map(BlobRecord::try_from).transpose())
}

pub(crate) async fn put_blob_if_absent_in_connection(
    conn: &mut diesel_async::AsyncPgConnection,
    blob_ref: &str,
    record: &BlobRecord,
) -> PersistenceResult<bool> {
    crate::realm_identity::ensure_optional_realm_pk(conn, record.realm_id.as_deref()).await?;
    let payload = serde_json::json!({"encryption": record.encryption.clone()});
    let written = sql_query(
        "INSERT INTO blobs \
             (id,sha256,media_type,filename,uploaded_by,realm_id,size_bytes, \
              storage_backend,storage_key,payload,legal_hold,redacted,visibility,created_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) \
             ON CONFLICT (id) DO NOTHING",
    )
    .bind::<Text, _>(blob_ref)
    .bind::<Text, _>(&record.sha256)
    .bind::<Text, _>(&record.media_type)
    .bind::<Nullable<Text>, _>(&record.filename)
    .bind::<Text, _>(&record.uploaded_by)
    .bind::<Nullable<Text>, _>(record.realm_id.as_deref())
    .bind::<BigInt, _>(record.size_bytes)
    .bind::<Text, _>(&record.storage_backend)
    .bind::<Text, _>(&record.storage_key)
    .bind::<Jsonb, _>(&payload)
    .bind::<Bool, _>(record.legal_hold)
    .bind::<Bool, _>(record.redacted)
    .bind::<Text, _>(record.visibility.as_str())
    .bind::<Timestamptz, _>(record.created_at)
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    Ok(written == 1)
}
#[async_trait]
impl BlobStore for PgBlobStore {
    async fn get(&self, blob_ref: &str) -> PersistenceResult<Option<BlobRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT sha256, size_bytes, storage_backend, storage_key, media_type, filename, \
             realm_id, NULLIF(payload->'encryption', 'null'::jsonb) AS encryption, \
             legal_hold, redacted, visibility, \
             uploaded_by AS uploaded_by, created_at \
             FROM blobs WHERE id = $1",
        )
        .bind::<Text, _>(blob_ref)
        .get_result::<BlobRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)
        .and_then(|row| row.map(BlobRecord::try_from).transpose())
    }

    async fn put(&self, blob_ref: &str, record: &BlobRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        crate::realm_identity::ensure_optional_realm_pk(&mut conn, record.realm_id.as_deref())
            .await?;
        let payload = serde_json::json!({
            "encryption": record.encryption.clone(),
        });
        sql_query(
            "INSERT INTO blobs \
             (id, sha256, media_type, filename, uploaded_by, realm_id, size_bytes, \
              storage_backend, storage_key, payload, legal_hold, redacted, visibility, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) \
             ON CONFLICT (id) DO UPDATE SET \
             sha256 = EXCLUDED.sha256, \
             media_type = EXCLUDED.media_type, \
             filename = EXCLUDED.filename, \
             uploaded_by = EXCLUDED.uploaded_by, \
             realm_id = EXCLUDED.realm_id, \
             size_bytes = EXCLUDED.size_bytes, \
             storage_backend = EXCLUDED.storage_backend, \
             storage_key = EXCLUDED.storage_key, \
             payload = EXCLUDED.payload, \
             legal_hold = EXCLUDED.legal_hold, \
             redacted = EXCLUDED.redacted, \
             visibility = EXCLUDED.visibility, \
             created_at = EXCLUDED.created_at \
             WHERE blobs.payload->'encryption' = EXCLUDED.payload->'encryption'",
        )
        .bind::<Text, _>(blob_ref)
        .bind::<Text, _>(&record.sha256)
        .bind::<Text, _>(&record.media_type)
        .bind::<Nullable<Text>, _>(&record.filename)
        .bind::<Text, _>(&record.uploaded_by)
        .bind::<Nullable<Text>, _>(record.realm_id.as_deref())
        .bind::<BigInt, _>(record.size_bytes)
        .bind::<Text, _>(&record.storage_backend)
        .bind::<Text, _>(&record.storage_key)
        .bind::<Jsonb, _>(&payload)
        .bind::<Bool, _>(record.legal_hold)
        .bind::<Bool, _>(record.redacted)
        .bind::<Text, _>(record.visibility.as_str())
        .bind::<Timestamptz, _>(record.created_at)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)
        .and_then(|written| {
            if written == 1 {
                Ok(())
            } else {
                Err(PersistenceError::Conflict(
                    "failed_precondition: blob encryption classification is immutable".to_owned(),
                ))
            }
        })
    }

    async fn put_if_absent(&self, blob_ref: &str, record: &BlobRecord) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        put_blob_if_absent_in_connection(&mut conn, blob_ref, record).await
    }

    async fn delete(&self, blob_ref: &str) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("DELETE FROM blobs WHERE id = $1")
            .bind::<Text, _>(blob_ref)
            .execute(&mut *conn)
            .await
            .map(|_| ())
            .map_err(PersistenceError::database)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<BlobRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT sha256, size_bytes, storage_backend, storage_key, media_type, filename, \
             realm_id, NULLIF(payload->'encryption', 'null'::jsonb) AS encryption, \
             legal_hold, redacted, visibility, \
             uploaded_by AS uploaded_by, created_at \
             FROM blobs ORDER BY created_at ASC, id ASC",
        )
        .load::<BlobRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)
        .and_then(|rows| rows.into_iter().map(BlobRecord::try_from).collect())
    }
}
#[derive(QueryableByName)]
struct BlobRow {
    #[diesel(sql_type = Text)]
    sha256: String,
    #[diesel(sql_type = BigInt)]
    size_bytes: i64,
    #[diesel(sql_type = Text)]
    storage_backend: String,
    #[diesel(sql_type = Text)]
    storage_key: String,
    #[diesel(sql_type = Text)]
    media_type: String,
    #[diesel(sql_type = Nullable<Text>)]
    filename: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    realm_id: Option<String>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    encryption: Option<Value>,
    #[diesel(sql_type = Bool)]
    legal_hold: bool,
    #[diesel(sql_type = Bool)]
    redacted: bool,
    #[diesel(sql_type = Text)]
    visibility: String,
    #[diesel(sql_type = Text)]
    uploaded_by: String,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
}
impl TryFrom<BlobRow> for BlobRecord {
    type Error = PersistenceError;

    fn try_from(row: BlobRow) -> PersistenceResult<Self> {
        let encryption = row
            .encryption
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| {
                PersistenceError::SchemaViolation(format!(
                    "invalid stored blob encryption: {error}"
                ))
            })?;
        Ok(Self {
            sha256: row.sha256,
            size_bytes: row.size_bytes,
            storage_backend: row.storage_backend,
            storage_key: row.storage_key,
            media_type: row.media_type,
            filename: row.filename,
            realm_id: row.realm_id,
            encryption,
            legal_hold: row.legal_hold,
            redacted: row.redacted,
            visibility: serde_json::from_value(Value::String(row.visibility))
                .expect("database enforces blob visibility"),
            uploaded_by: row.uploaded_by,
            created_at: row.created_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use arkret_models_collaboration::objects::blob::BlobVisibility;

    use super::*;
    use crate::test_database::TestDatabase;

    #[tokio::test]
    async fn public_material_cache_is_create_only_and_preserves_redaction_and_metadata() {
        let database = TestDatabase::lease().await;
        let store = PgBlobStore {
            pool: database.pool(),
        };
        let digest = arkret_canonical::sha256_digest(b"public cache fixture");
        let blob_ref = format!("ak:blob:{digest}");
        let original = BlobRecord {
            sha256: digest.trim_start_matches("sha256:").into(),
            size_bytes: 20,
            storage_backend: "local".into(),
            storage_key: "existing-public-material".into(),
            media_type: "application/octet-stream".into(),
            filename: Some("original".into()),
            realm_id: None,
            encryption: None,
            legal_hold: true,
            redacted: true,
            visibility: BlobVisibility::Public,
            uploaded_by: "ak:did_core:web:original.example".into(),
            created_at: chrono::Utc::now(),
        };
        store.put(&blob_ref, &original).await.unwrap();
        let mut cached = original.clone();
        cached.legal_hold = false;
        cached.redacted = false;
        cached.filename = None;
        cached.storage_key = "replacement".into();
        cached.uploaded_by = "ak:did_core:web:replacement.example".into();
        assert!(!store.put_if_absent(&blob_ref, &cached).await.unwrap());
        let retained = store.get(&blob_ref).await.unwrap().unwrap();
        assert!(retained.redacted && retained.legal_hold);
        assert_eq!(retained.filename, original.filename);
        assert_eq!(retained.storage_key, original.storage_key);
        assert_eq!(retained.uploaded_by, original.uploaded_by);
        assert_eq!(retained.visibility, original.visibility);
        let new_ref = format!(
            "ak:blob:{}",
            arkret_canonical::sha256_digest(b"new public cache fixture")
        );
        let (first, second) = tokio::join!(
            store.put_if_absent(&new_ref, &cached),
            store.put_if_absent(&new_ref, &cached)
        );
        assert_ne!(first.unwrap(), second.unwrap());
        assert!(!store.put_if_absent(&new_ref, &original).await.unwrap());
        assert!(!store.get(&new_ref).await.unwrap().unwrap().redacted);
    }
}
