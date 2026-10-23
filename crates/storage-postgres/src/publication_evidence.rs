use super::{
    Jsonb, OptionalExtension, PersistenceError, PersistenceResult, PgPool,
    PublicationEvidenceRecord, PublicationEvidenceStore, QueryableByName, RunQueryDsl, Text, Value,
    async_trait, pg_conn, sql_query,
};

pub struct PgPublicationEvidenceStore {
    pub pool: PgPool,
}

#[derive(QueryableByName)]
struct PublicationEvidenceRow {
    #[diesel(sql_type = Text)]
    event_id: String,
    #[diesel(sql_type = Jsonb)]
    committed_ref: Value,
    #[diesel(sql_type = super::Timestamptz)]
    accepted_at: chrono::DateTime<chrono::Utc>,
}

impl TryFrom<PublicationEvidenceRow> for PublicationEvidenceRecord {
    type Error = PersistenceError;

    fn try_from(row: PublicationEvidenceRow) -> PersistenceResult<Self> {
        Ok(Self {
            event_id: arkret_wire::EventId::new(row.event_id)
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?,
            committed_ref: serde_json::from_value(row.committed_ref).map_err(|error| {
                PersistenceError::SchemaViolation(format!(
                    "stored publication committed_ref is invalid: {error}"
                ))
            })?,
            accepted_at: row.accepted_at,
        })
    }
}

const COLUMNS: &str = "event_id, committed_ref, accepted_at";

#[async_trait]
impl PublicationEvidenceStore for PgPublicationEvidenceStore {
    async fn put_if_absent(
        &self,
        record: PublicationEvidenceRecord,
    ) -> PersistenceResult<PublicationEvidenceRecord> {
        if record.committed_ref.event_id != record.event_id {
            return Err(PersistenceError::SchemaViolation(
                "publication evidence must bind the same Event id".to_owned(),
            ));
        }
        let committed_ref =
            serde_json::to_value(&record.committed_ref).map_err(PersistenceError::database)?;
        let mut conn = crate::pg_db(&self.pool);
        sql_query(
            "INSERT INTO publication_evidence (event_id,committed_ref,accepted_at) \
             VALUES ($1,$2,$3) ON CONFLICT (event_id) DO NOTHING",
        )
        .bind::<Text, _>(record.event_id.as_str())
        .bind::<Jsonb, _>(committed_ref)
        .bind::<super::Timestamptz, _>(record.accepted_at)
        .execute(&mut conn)
        .await
        .map_err(PersistenceError::database)?;
        let row = sql_query(format!(
            "SELECT {COLUMNS} FROM publication_evidence WHERE event_id=$1"
        ))
        .bind::<Text, _>(record.event_id.as_str())
        .get_result::<PublicationEvidenceRow>(&mut conn)
        .await
        .map_err(PersistenceError::database)?;
        PublicationEvidenceRecord::try_from(row)
    }

    async fn get(
        &self,
        event_id: &arkret_wire::EventId,
    ) -> PersistenceResult<Option<PublicationEvidenceRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(format!(
            "SELECT {COLUMNS} FROM publication_evidence WHERE event_id=$1"
        ))
        .bind::<Text, _>(event_id.as_str())
        .get_result::<PublicationEvidenceRow>(&mut conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(PublicationEvidenceRecord::try_from)
        .transpose()
    }

    async fn get_many(
        &self,
        event_ids: &[arkret_wire::EventId],
    ) -> PersistenceResult<Vec<PublicationEvidenceRecord>> {
        if event_ids.is_empty() {
            return Ok(Vec::new());
        }
        let values = event_ids
            .iter()
            .map(|event_id| event_id.as_str().to_owned())
            .collect::<Vec<_>>();
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(format!(
            "SELECT {COLUMNS} FROM publication_evidence WHERE event_id=ANY($1)"
        ))
        .bind::<diesel::sql_types::Array<Text>, _>(values)
        .load::<PublicationEvidenceRow>(&mut conn)
        .await
        .map_err(PersistenceError::database)?;
        let mut by_id = std::collections::BTreeMap::new();
        for row in rows {
            let record = PublicationEvidenceRecord::try_from(row)?;
            by_id.insert(record.event_id.clone(), record);
        }
        Ok(event_ids
            .iter()
            .filter_map(|event_id| by_id.get(event_id).cloned())
            .collect())
    }
}
