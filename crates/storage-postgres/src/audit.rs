use super::{
    AuditStore, JsonPayloadRow, Jsonb, Nullable, PersistenceError, PersistenceResult, PgPool,
    RunQueryDsl, Text, Value, async_trait, audit_uuid_index, operation_uuid_index,
    optional_audit_uuid_index, pg_conn, sql_query, sql_types,
};
pub struct PgAuditStore {
    pub pool: PgPool,
}
#[async_trait]
impl AuditStore for PgAuditStore {
    async fn append(&self, entry: Value) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let extract = |key: &str| -> Option<String> {
            entry
                .get(key)
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        };
        let audit_id = extract("audit_id")
            .ok_or_else(|| PersistenceError::Internal("audit entry missing audit_id".to_owned()))?;
        let action = extract("action")
            .ok_or_else(|| PersistenceError::Internal("audit entry missing action".to_owned()))?;
        let outcome = extract("outcome")
            .ok_or_else(|| PersistenceError::Internal("audit entry missing outcome".to_owned()))?;
        let actor = extract("actor");
        let request_id = extract("request_id");
        let realm_id = extract("realm_id");
        let operation_id = extract("operation_id");
        let device_id = extract("device_id");
        let audit_id_uuid = audit_uuid_index("audit_id", &audit_id, "audit")?;
        let request_id_uuid =
            optional_audit_uuid_index("request_id", request_id.as_deref(), "request")?;
        crate::realm_identity::ensure_optional_realm_pk(&mut conn, realm_id.as_deref()).await?;
        let operation_id_uuid = operation_uuid_index(operation_id.as_deref());
        sql_query(
            "INSERT INTO audit_logs \
             (id, actor_id, request_id, action, outcome, realm_id, operation_id, device_id, payload, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW()) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind::<sql_types::Uuid, _>(audit_id_uuid)
        .bind::<Nullable<Text>, _>(&actor)
        .bind::<Nullable<sql_types::Uuid>, _>(request_id_uuid)
        .bind::<Text, _>(&action)
        .bind::<Text, _>(&outcome)
        .bind::<Nullable<Text>, _>(realm_id.as_deref())
        .bind::<Nullable<sql_types::Uuid>, _>(operation_id_uuid)
        .bind::<Nullable<Text>, _>(&device_id)
        .bind::<Jsonb, _>(&entry)
        .execute(&mut *conn).await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<Value>> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query(
            "SELECT payload FROM audit_logs WHERE actor_id = $1 ORDER BY created_at ASC, id ASC",
        )
        .bind::<Text, _>(actor)
        .load::<JsonPayloadRow>(&mut conn)
        .await
        .map(|rows| rows.into_iter().map(|row| row.payload).collect())
        .map_err(PersistenceError::database)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<Value>> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query("SELECT payload FROM audit_logs ORDER BY created_at ASC, id ASC")
            .load::<JsonPayloadRow>(&mut conn)
            .await
            .map(|rows| rows.into_iter().map(|row| row.payload).collect())
            .map_err(PersistenceError::database)
    }
}
