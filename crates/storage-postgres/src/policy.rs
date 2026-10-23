use super::{
    Bool, Integer, Jsonb, Nullable, OptionalExtension, PersistenceError, PersistenceResult, PgPool,
    PolicyDocumentRecord, PolicyDocumentStore, QueryableByName, RunQueryDsl, Text, Timestamptz,
    Uuid, Value, async_trait, ids, pg_conn, sql_query, sql_types,
};
pub struct PgPolicyDocumentStore {
    pub pool: PgPool,
}
#[derive(QueryableByName)]
struct PolicyDocumentRow {
    #[diesel(sql_type = sql_types::Uuid)]
    policy_id: Uuid,
    #[diesel(sql_type = Text)]
    owner: String,
    #[diesel(sql_type = Text)]
    scope: String,
    #[diesel(sql_type = Text)]
    subject_ref: String,
    #[diesel(sql_type = Text)]
    policy_kind: String,
    #[diesel(sql_type = Jsonb)]
    document: Value,
    #[diesel(sql_type = Bool)]
    active: bool,
    #[diesel(sql_type = Timestamptz)]
    updated_at: chrono::DateTime<chrono::Utc>,
}
impl From<PolicyDocumentRow> for PolicyDocumentRecord {
    fn from(row: PolicyDocumentRow) -> Self {
        Self {
            policy_id: ids::format_typed_uuid("policy", &row.policy_id),
            owner: row.owner,
            scope: row.scope,
            subject_ref: row.subject_ref,
            policy_kind: row.policy_kind,
            payload: row.document,
            active: row.active,
            updated_at: row.updated_at,
        }
    }
}
#[async_trait]
impl PolicyDocumentStore for PgPolicyDocumentStore {
    async fn get(&self, policy_id: &str) -> PersistenceResult<Option<PolicyDocumentRecord>> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query(
            "SELECT id AS policy_id, owner_id AS owner, scope, subject_ref, policy_kind, document, active, updated_at \
             FROM policy_documents WHERE id = $1",
        )
        .bind::<sql_types::Uuid, _>(ids::typed_uuid_part_expect_internal(policy_id))
        .get_result::<PolicyDocumentRow>(&mut conn).await
        .optional()
        .map(|row| row.map(PolicyDocumentRecord::from))
        .map_err(PersistenceError::database)
    }

    async fn put(&self, record: PolicyDocumentRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let version: i32 = record
            .payload
            .get("version")
            .and_then(Value::as_i64)
            .map(|v| v.clamp(i32::MIN as i64, i32::MAX as i64) as i32)
            .unwrap_or(0);
        let verification_method: Option<String> = record
            .payload
            .get("verification_method")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        sql_query(
            "INSERT INTO policy_documents \
             (id, owner_id, scope, subject_ref, policy_kind, document, version, signed_by, active, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
             ON CONFLICT (id) DO UPDATE SET \
                owner_id = EXCLUDED.owner_id, \
                scope = EXCLUDED.scope, \
                subject_ref = EXCLUDED.subject_ref, \
                policy_kind = EXCLUDED.policy_kind, \
                document = EXCLUDED.document, \
                version = EXCLUDED.version, \
                signed_by = EXCLUDED.signed_by, \
                active = EXCLUDED.active, \
                updated_at = EXCLUDED.updated_at",
        )
        .bind::<sql_types::Uuid, _>(ids::typed_uuid_part_expect_internal(&record.policy_id))
        .bind::<Text, _>(&record.owner)
        .bind::<Text, _>(&record.scope)
        .bind::<Text, _>(&record.subject_ref)
        .bind::<Text, _>(&record.policy_kind)
        .bind::<Jsonb, _>(&record.payload)
        .bind::<Integer, _>(version)
        .bind::<Nullable<Text>, _>(&verification_method)
        .bind::<Bool, _>(record.active)
        .bind::<Timestamptz, _>(record.updated_at)
        .execute(&mut conn).await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn delete(&self, policy_id: &str) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("DELETE FROM policy_documents WHERE id = $1")
            .bind::<sql_types::Uuid, _>(ids::typed_uuid_part_expect_internal(policy_id))
            .execute(&mut conn)
            .await
            .map(|n| n > 0)
            .map_err(PersistenceError::database)
    }

    async fn list_for_owner(&self, owner: &str) -> PersistenceResult<Vec<PolicyDocumentRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT id AS policy_id, owner_id AS owner, scope, subject_ref, policy_kind, document, active, updated_at \
             FROM policy_documents WHERE owner_id = $1 ORDER BY updated_at ASC, id ASC",
        )
        .bind::<Text, _>(owner)
        .load::<PolicyDocumentRow>(&mut conn).await
        .map(|rows| rows.into_iter().map(PolicyDocumentRecord::from).collect())
        .map_err(PersistenceError::database)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<PolicyDocumentRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT id AS policy_id, owner_id AS owner, scope, subject_ref, policy_kind, document, active, updated_at \
             FROM policy_documents ORDER BY updated_at ASC, id ASC",
        )
        .load::<PolicyDocumentRow>(&mut conn).await
        .map(|rows| rows.into_iter().map(PolicyDocumentRecord::from).collect())
        .map_err(PersistenceError::database)
    }
}
