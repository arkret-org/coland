use super::{
    AsyncConnection, Binary, Bool, CircleMemberProjectionRecord, CircleProjectionRecord,
    CircleProjectionStore, Jsonb, MorphProjectionRecord, MorphProjectionStore, Nullable,
    OptionalExtension, PersistenceError, PersistenceResult, PgPool, PgTransactionError,
    ProjectionEventAppendOutcome, ProjectionEventRecord, ProjectionEventStore, QueryableByName,
    RealmMetaRecord, RealmMetaStore, RunQueryDsl, SpaceContainerProjectionRecord,
    SpaceContainerProjectionStore, StrandProjectionRecord, StrandProjectionStore, Text,
    Timestamptz, Uuid, Value, async_trait, ids, pg_conn, sql_query, sql_types,
};

#[cfg(test)]
#[path = "projection_pg_tests.rs"]
mod pg_tests;

/// Space, Strand, Morph and Circle are Event-derived kinds: their protocol id is
/// the create Event's 33-byte token, stored raw beside the local sequential
/// `pk` that carries the physical ordering.
fn token_bytes(kind: &str, typed: &str) -> Vec<u8> {
    ids::event_token_part_expect_internal(typed, kind).to_vec()
}

fn token_string(kind: &str, bytes: &[u8]) -> String {
    let token: [u8; ids::EVENT_ID_BYTES] = bytes
        .try_into()
        .expect("stored Event-derived id must be 33 bytes");
    ids::format_event_token(kind, &token)
}
fn stored_actor(value: &str) -> PersistenceResult<arkret_wire::ActorId> {
    serde_json::from_str(value).map_err(|_| {
        PersistenceError::Database("projection byline is not a valid ActorId".to_owned())
    })
}
pub struct PgSpaceContainerProjectionStore {
    pub pool: PgPool,
}
#[derive(QueryableByName)]
struct SpaceContainerProjectionRow {
    #[diesel(sql_type = Binary)]
    container_space_id: Vec<u8>,
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Nullable<Binary>)]
    scope_circle_id: Option<Vec<u8>>,
    #[diesel(sql_type = Nullable<Text>)]
    child_scope_policy: Option<String>,
    #[diesel(sql_type = Nullable<Binary>)]
    child_scope_policy_scope_circle_id: Option<Vec<u8>>,
    #[diesel(sql_type = Text)]
    kind: String,
    #[diesel(sql_type = Text)]
    title: String,
    #[diesel(sql_type = Jsonb)]
    fields: Value,
    #[diesel(sql_type = Nullable<Binary>)]
    parent_ref: Option<Vec<u8>>,
    #[diesel(sql_type = Nullable<Text>)]
    rank: Option<String>,
    #[diesel(sql_type = Text)]
    state: String,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    state_changed_at: Option<chrono::DateTime<chrono::Utc>>,
    #[diesel(sql_type = Jsonb)]
    created_by: arkret_wire::ActorId,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Jsonb)]
    #[diesel(sql_type = Nullable<Jsonb>)]
    updated_by: Option<arkret_wire::ActorId>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    updated_at: Option<chrono::DateTime<chrono::Utc>>,
}
impl From<SpaceContainerProjectionRow> for SpaceContainerProjectionRecord {
    fn from(row: SpaceContainerProjectionRow) -> Self {
        Self {
            container_space_id: token_string("space", &row.container_space_id),
            realm_id: row.realm_id,
            kind: row.kind,
            title: row.title,
            fields: serde_json::from_value(row.fields).unwrap_or_default(),
            scope_circle_id: row
                .scope_circle_id
                .as_deref()
                .map(|bytes| token_string("circle", bytes)),
            child_scope_policy: row.child_scope_policy,
            child_scope_policy_scope_circle_id: row
                .child_scope_policy_scope_circle_id
                .as_deref()
                .map(|bytes| token_string("circle", bytes)),
            parent_ref: row
                .parent_ref
                .as_deref()
                .map(|bytes| token_string("space", bytes)),
            rank: row.rank,
            state: row.state,
            state_changed_at: row.state_changed_at,
            created_by: row.created_by.to_string(),
            created_at: row.created_at,
            updated_by: row.updated_by.map(|id| id.to_string()),
            updated_at: row.updated_at,
        }
    }
}
const SPACE_CONTAINER_PROJECTION_COLUMNS: &str = "id AS container_space_id, realm_id, scope_circle_id, \
     child_scope_policy, child_scope_policy_scope_circle_id, kind, title, fields, parent_ref, rank, state, \
     state_changed_at, created_by AS created_by, created_at, updated_by AS updated_by, updated_at";
#[async_trait]
impl SpaceContainerProjectionStore for PgSpaceContainerProjectionStore {
    async fn get(
        &self,
        container_space_id: &str,
    ) -> PersistenceResult<Option<SpaceContainerProjectionRecord>> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query(format!(
            "SELECT {SPACE_CONTAINER_PROJECTION_COLUMNS} FROM projection_spaces WHERE id = $1"
        ))
        .bind::<Binary, _>(token_bytes("space", container_space_id))
        .get_result::<SpaceContainerProjectionRow>(&mut conn)
        .await
        .optional()
        .map(|row| row.map(SpaceContainerProjectionRecord::from))
        .map_err(PersistenceError::database)
    }

    async fn put(&self, record: &SpaceContainerProjectionRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        crate::realm_identity::ensure_realm_pk(&mut conn, &record.realm_id).await?;
        sql_query(
            "INSERT INTO projection_spaces \
             (id, realm_id, scope_circle_id, child_scope_policy, \
              child_scope_policy_scope_circle_id, \
              kind, title, fields, parent_ref, rank, state, state_changed_at, created_by, created_at, \
              updated_by, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16) \
             ON CONFLICT (id) DO UPDATE SET \
                realm_id = EXCLUDED.realm_id, \
                scope_circle_id = EXCLUDED.scope_circle_id, \
                child_scope_policy = EXCLUDED.child_scope_policy, \
                child_scope_policy_scope_circle_id = EXCLUDED.child_scope_policy_scope_circle_id, \
                kind = EXCLUDED.kind, \
                title = EXCLUDED.title, \
                fields = EXCLUDED.fields, \
                parent_ref = EXCLUDED.parent_ref, \
                rank = EXCLUDED.rank, \
                state = EXCLUDED.state, \
                state_changed_at = EXCLUDED.state_changed_at, \
                updated_by = EXCLUDED.updated_by, \
                updated_at = EXCLUDED.updated_at",
        )
        .bind::<Binary, _>(token_bytes("space", &record.container_space_id))
        .bind::<Text, _>(&record.realm_id)
        .bind::<Nullable<Binary>, _>(
            record
                .scope_circle_id
                .as_deref()
                .map(|circle_id| token_bytes("circle", circle_id)),
        )
        .bind::<Nullable<Text>, _>(&record.child_scope_policy)
        .bind::<Nullable<Binary>, _>(
            record
                .child_scope_policy_scope_circle_id
                .as_deref()
                .map(|circle_id| token_bytes("circle", circle_id)),
        )
        .bind::<Text, _>(&record.kind)
        .bind::<Text, _>(&record.title)
        .bind::<Jsonb, _>(&serde_json::json!(record.fields))
        .bind::<Nullable<Binary>, _>(
            record
                .parent_ref
                .as_deref()
                .map(|space_id| token_bytes("space", space_id)),
        )
        .bind::<Nullable<Text>, _>(&record.rank)
        .bind::<Text, _>(&record.state)
        .bind::<Nullable<Timestamptz>, _>(record.state_changed_at)
        .bind::<Jsonb, _>(stored_actor(&record.created_by)?)
        .bind::<Timestamptz, _>(record.created_at)
        .bind::<Nullable<Jsonb>, _>(record.updated_by.as_deref().map(stored_actor).transpose()?)
        .bind::<Nullable<Timestamptz>, _>(record.updated_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn list_for_realm(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Vec<SpaceContainerProjectionRecord>> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query(format!(
            "SELECT {SPACE_CONTAINER_PROJECTION_COLUMNS} FROM projection_spaces \
             WHERE realm_id = $1 ORDER BY pk"
        ))
        .bind::<Text, _>(realm_id)
        .load::<SpaceContainerProjectionRow>(&mut conn)
        .await
        .map(|rows| {
            rows.into_iter()
                .map(SpaceContainerProjectionRecord::from)
                .collect()
        })
        .map_err(PersistenceError::database)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<SpaceContainerProjectionRecord>> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query(format!(
            "SELECT {SPACE_CONTAINER_PROJECTION_COLUMNS} FROM projection_spaces ORDER BY pk"
        ))
        .load::<SpaceContainerProjectionRow>(&mut conn)
        .await
        .map(|rows| {
            rows.into_iter()
                .map(SpaceContainerProjectionRecord::from)
                .collect()
        })
        .map_err(PersistenceError::database)
    }

    async fn delete(&self, container_space_id: &str) -> PersistenceResult<()> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query("DELETE FROM projection_spaces WHERE id = $1")
            .bind::<Binary, _>(token_bytes("space", container_space_id))
            .execute(&mut conn)
            .await
            .map(|_| ())
            .map_err(PersistenceError::database)
    }
}
pub struct PgStrandProjectionStore {
    pub pool: PgPool,
}
#[derive(QueryableByName)]
struct StrandProjectionRow {
    #[diesel(sql_type = Binary)]
    strand_id: Vec<u8>,
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Nullable<Binary>)]
    scope_circle_id: Option<Vec<u8>>,
    #[diesel(sql_type = Jsonb)]
    tracks: serde_json::Value,
    #[diesel(sql_type = Text)]
    title: String,
    #[diesel(sql_type = Nullable<Text>)]
    summary: Option<String>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    content: Option<Value>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    encrypted_content: Option<Value>,
    #[diesel(sql_type = Jsonb)]
    fields: Value,
    #[diesel(sql_type = Jsonb)]
    schema_refs: Value,
    #[diesel(sql_type = Text)]
    state: String,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    state_changed_at: Option<chrono::DateTime<chrono::Utc>>,
    #[diesel(sql_type = Nullable<Text>)]
    stage: Option<String>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    stage_changed_at: Option<chrono::DateTime<chrono::Utc>>,
    #[diesel(sql_type = Jsonb)]
    created_by: arkret_wire::ActorId,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Jsonb)]
    #[diesel(sql_type = Nullable<Jsonb>)]
    updated_by: Option<arkret_wire::ActorId>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    updated_at: Option<chrono::DateTime<chrono::Utc>>,
}
impl From<StrandProjectionRow> for StrandProjectionRecord {
    fn from(row: StrandProjectionRow) -> Self {
        Self {
            strand_id: token_string("strand", &row.strand_id),
            realm_id: row.realm_id,
            scope_circle_id: row
                .scope_circle_id
                .as_deref()
                .map(|bytes| token_string("circle", bytes)),
            tracks: serde_json::from_value(row.tracks).unwrap_or_default(),
            title: row.title,
            summary: row.summary,
            content: row.content,
            encrypted_content: row.encrypted_content,
            fields: serde_json::from_value(row.fields).unwrap_or_default(),
            schema_refs: serde_json::from_value(row.schema_refs).unwrap_or_default(),
            state: row.state,
            state_changed_at: row.state_changed_at,
            stage: row.stage,
            stage_changed_at: row.stage_changed_at,
            created_by: row.created_by.to_string(),
            created_at: row.created_at,
            updated_by: row.updated_by.map(|id| id.to_string()),
            updated_at: row.updated_at,
        }
    }
}
const STRAND_PROJECTION_COLUMNS: &str = "id AS strand_id, realm_id, scope_circle_id, tracks, title, summary, content, encrypted_content, fields, schema_refs, state, \
     state_changed_at, stage, stage_changed_at, created_by AS created_by, created_at, updated_by AS updated_by, updated_at";
#[async_trait]
impl StrandProjectionStore for PgStrandProjectionStore {
    async fn get(&self, strand_id: &str) -> PersistenceResult<Option<StrandProjectionRecord>> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query(format!(
            "SELECT {STRAND_PROJECTION_COLUMNS} FROM projection_strands WHERE id = $1"
        ))
        .bind::<Binary, _>(token_bytes("strand", strand_id))
        .get_result::<StrandProjectionRow>(&mut conn)
        .await
        .optional()
        .map(|row| row.map(StrandProjectionRecord::from))
        .map_err(PersistenceError::database)
    }

    async fn put(&self, record: &StrandProjectionRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        crate::realm_identity::ensure_realm_pk(&mut conn, &record.realm_id).await?;
        let tracks = serde_json::to_value(&record.tracks)
            .unwrap_or_else(|_| Value::Object(Default::default()));
        sql_query(
            "INSERT INTO projection_strands \
             (id, realm_id, scope_circle_id, tracks, title, summary, content, encrypted_content, fields, schema_refs, state, state_changed_at, \
              stage, stage_changed_at, created_by, created_at, updated_by, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18) \
             ON CONFLICT (id) DO UPDATE SET \
                realm_id = EXCLUDED.realm_id, \
                scope_circle_id = EXCLUDED.scope_circle_id, \
                tracks = EXCLUDED.tracks, \
                title = EXCLUDED.title, \
                summary = EXCLUDED.summary, \
                content = EXCLUDED.content, \
                encrypted_content = EXCLUDED.encrypted_content, \
                fields = EXCLUDED.fields, \
                schema_refs = EXCLUDED.schema_refs, \
                state = EXCLUDED.state, \
                state_changed_at = EXCLUDED.state_changed_at, \
                stage = EXCLUDED.stage, \
                stage_changed_at = EXCLUDED.stage_changed_at, \
                updated_by = EXCLUDED.updated_by, \
                updated_at = EXCLUDED.updated_at",
        )
        .bind::<Binary, _>(token_bytes("strand", &record.strand_id))
        .bind::<Text, _>(&record.realm_id)
        .bind::<Nullable<Binary>, _>(
            record
                .scope_circle_id
                .as_deref()
                .map(|circle_id| token_bytes("circle", circle_id)),
        )
        .bind::<Jsonb, _>(&tracks)
        .bind::<Text, _>(&record.title)
        .bind::<Nullable<Text>, _>(&record.summary)
        .bind::<Nullable<Jsonb>, _>(&record.content)
        .bind::<Nullable<Jsonb>, _>(&record.encrypted_content)
        .bind::<Jsonb, _>(&serde_json::json!(record.fields))
        .bind::<Jsonb, _>(&serde_json::json!(record.schema_refs))
        .bind::<Text, _>(&record.state)
        .bind::<Nullable<Timestamptz>, _>(record.state_changed_at)
        .bind::<Nullable<Text>, _>(&record.stage)
        .bind::<Nullable<Timestamptz>, _>(record.stage_changed_at)
        .bind::<Jsonb, _>(stored_actor(&record.created_by)?)
        .bind::<Timestamptz, _>(record.created_at)
        .bind::<Nullable<Jsonb>, _>(record.updated_by.as_deref().map(stored_actor).transpose()?)
        .bind::<Nullable<Timestamptz>, _>(record.updated_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn list_for_realm(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Vec<StrandProjectionRecord>> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query(format!(
            "SELECT {STRAND_PROJECTION_COLUMNS} FROM projection_strands \
             WHERE realm_id = $1 ORDER BY pk"
        ))
        .bind::<Text, _>(realm_id)
        .load::<StrandProjectionRow>(&mut conn)
        .await
        .map(|rows| rows.into_iter().map(StrandProjectionRecord::from).collect())
        .map_err(PersistenceError::database)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<StrandProjectionRecord>> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query(format!(
            "SELECT {STRAND_PROJECTION_COLUMNS} FROM projection_strands ORDER BY pk"
        ))
        .load::<StrandProjectionRow>(&mut conn)
        .await
        .map(|rows| rows.into_iter().map(StrandProjectionRecord::from).collect())
        .map_err(PersistenceError::database)
    }

    async fn delete(&self, strand_id: &str) -> PersistenceResult<()> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query("DELETE FROM projection_strands WHERE id = $1")
            .bind::<Binary, _>(token_bytes("strand", strand_id))
            .execute(&mut conn)
            .await
            .map(|_| ())
            .map_err(PersistenceError::database)
    }
}
pub struct PgMorphProjectionStore {
    pub pool: PgPool,
}
#[derive(QueryableByName)]
struct MorphProjectionRow {
    #[diesel(sql_type = Binary)]
    morph_id: Vec<u8>,
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Nullable<Binary>)]
    scope_circle_id: Option<Vec<u8>>,
    #[diesel(sql_type = Text)]
    morph_kind: String,
    #[diesel(sql_type = Nullable<Text>)]
    title: Option<String>,
    #[diesel(sql_type = Jsonb)]
    fields: serde_json::Value,
    #[diesel(sql_type = Jsonb)]
    schema_refs: serde_json::Value,
    #[diesel(sql_type = Jsonb)]
    facets: serde_json::Value,
    #[diesel(sql_type = Jsonb)]
    versions: serde_json::Value,
    #[diesel(sql_type = Nullable<Jsonb>)]
    content: Option<serde_json::Value>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    encrypted_content: Option<serde_json::Value>,
    #[diesel(sql_type = Text)]
    state: String,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    state_changed_at: Option<chrono::DateTime<chrono::Utc>>,
    #[diesel(sql_type = Nullable<Text>)]
    stage: Option<String>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    stage_changed_at: Option<chrono::DateTime<chrono::Utc>>,
    #[diesel(sql_type = Jsonb)]
    created_by: arkret_wire::ActorId,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Jsonb)]
    #[diesel(sql_type = Nullable<Jsonb>)]
    updated_by: Option<arkret_wire::ActorId>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    updated_at: Option<chrono::DateTime<chrono::Utc>>,
}
impl From<MorphProjectionRow> for MorphProjectionRecord {
    fn from(row: MorphProjectionRow) -> Self {
        Self {
            morph_id: token_string("morph", &row.morph_id),
            realm_id: row.realm_id,
            scope_circle_id: row
                .scope_circle_id
                .as_deref()
                .map(|bytes| token_string("circle", bytes)),
            morph_kind: row.morph_kind,
            title: row.title,
            fields: row.fields,
            schema_refs: row.schema_refs,
            facets: row.facets,
            versions: row.versions,
            content: row.content,
            encrypted_content: row.encrypted_content,
            state: row.state,
            state_changed_at: row.state_changed_at,
            stage: row.stage,
            stage_changed_at: row.stage_changed_at,
            created_by: row.created_by.to_string(),
            created_at: row.created_at,
            updated_by: row.updated_by.map(|id| id.to_string()),
            updated_at: row.updated_at,
        }
    }
}
const MORPH_PROJECTION_COLUMNS: &str = "id AS morph_id, realm_id, scope_circle_id, morph_kind, title, fields, \
     schema_refs, facets, versions, content, encrypted_content, state, state_changed_at, stage, stage_changed_at, \
     created_by AS created_by, created_at, updated_by AS updated_by, updated_at";
#[async_trait]
impl MorphProjectionStore for PgMorphProjectionStore {
    async fn get(&self, morph_id: &str) -> PersistenceResult<Option<MorphProjectionRecord>> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query(format!(
            "SELECT {MORPH_PROJECTION_COLUMNS} FROM projection_morphs WHERE id = $1"
        ))
        .bind::<Binary, _>(token_bytes("morph", morph_id))
        .get_result::<MorphProjectionRow>(&mut conn)
        .await
        .optional()
        .map(|row| row.map(MorphProjectionRecord::from))
        .map_err(PersistenceError::database)
    }

    async fn put(&self, record: &MorphProjectionRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        crate::realm_identity::ensure_realm_pk(&mut conn, &record.realm_id).await?;
        sql_query(
            "INSERT INTO projection_morphs \
             (id, realm_id, scope_circle_id, morph_kind, title, fields, schema_refs, facets, versions, content, encrypted_content, \
              state, state_changed_at, stage, stage_changed_at, created_by, created_at, updated_by, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19) \
             ON CONFLICT (id) DO UPDATE SET \
                realm_id = EXCLUDED.realm_id, \
                scope_circle_id = EXCLUDED.scope_circle_id, \
                morph_kind = EXCLUDED.morph_kind, \
                title = EXCLUDED.title, \
                fields = EXCLUDED.fields, \
                schema_refs = EXCLUDED.schema_refs, \
                facets = EXCLUDED.facets, \
                versions = EXCLUDED.versions, \
                content = EXCLUDED.content, \
                encrypted_content = EXCLUDED.encrypted_content, \
                state = EXCLUDED.state, \
                state_changed_at = EXCLUDED.state_changed_at, \
                stage = EXCLUDED.stage, \
                stage_changed_at = EXCLUDED.stage_changed_at, \
                updated_by = EXCLUDED.updated_by, \
                updated_at = EXCLUDED.updated_at",
        )
        .bind::<Binary, _>(token_bytes("morph", &record.morph_id))
        .bind::<Text, _>(&record.realm_id)
        .bind::<Nullable<Binary>, _>(
            record
                .scope_circle_id
                .as_deref()
                .map(|circle_id| token_bytes("circle", circle_id)),
        )
        .bind::<Text, _>(&record.morph_kind)
        .bind::<Nullable<Text>, _>(&record.title)
        .bind::<Jsonb, _>(&record.fields)
        .bind::<Jsonb, _>(&record.schema_refs)
        .bind::<Jsonb, _>(&record.facets)
        .bind::<Jsonb, _>(&record.versions)
        .bind::<Nullable<Jsonb>, _>(&record.content)
        .bind::<Nullable<Jsonb>, _>(&record.encrypted_content)
        .bind::<Text, _>(&record.state)
        .bind::<Nullable<Timestamptz>, _>(record.state_changed_at)
        .bind::<Nullable<Text>, _>(&record.stage)
        .bind::<Nullable<Timestamptz>, _>(record.stage_changed_at)
        .bind::<Jsonb, _>(stored_actor(&record.created_by)?)
        .bind::<Timestamptz, _>(record.created_at)
        .bind::<Nullable<Jsonb>, _>(record.updated_by.as_deref().map(stored_actor).transpose()?)
        .bind::<Nullable<Timestamptz>, _>(record.updated_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn list_for_realm(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Vec<MorphProjectionRecord>> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query(format!(
            "SELECT {MORPH_PROJECTION_COLUMNS} FROM projection_morphs \
             WHERE realm_id = $1 ORDER BY pk"
        ))
        .bind::<Text, _>(realm_id)
        .load::<MorphProjectionRow>(&mut conn)
        .await
        .map(|rows| rows.into_iter().map(MorphProjectionRecord::from).collect())
        .map_err(PersistenceError::database)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<MorphProjectionRecord>> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query(format!(
            "SELECT {MORPH_PROJECTION_COLUMNS} FROM projection_morphs ORDER BY pk"
        ))
        .load::<MorphProjectionRow>(&mut conn)
        .await
        .map(|rows| rows.into_iter().map(MorphProjectionRecord::from).collect())
        .map_err(PersistenceError::database)
    }

    async fn delete(&self, morph_id: &str) -> PersistenceResult<()> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query("DELETE FROM projection_morphs WHERE id = $1")
            .bind::<Binary, _>(token_bytes("morph", morph_id))
            .execute(&mut conn)
            .await
            .map(|_| ())
            .map_err(PersistenceError::database)
    }
}
// ── Pg-backed projection_events store ────────────────────────────────────
// Append-only mirror of the in-memory ProjectionEventRecord stream
// stamped down by `routing::events::projection::append_projection_event`.
// `id` is the full suite-tagged digest identity. A true hash collision must be
// rejected/quarantined by the canonical commit before materialization; this
// table must never choose a variant with first-row-wins semantics. The
// surrogate `pk` is only a local stream position.

pub struct PgProjectionEventStore {
    pub pool: PgPool,
}

// The Event identity is not duplicated onto `projection_events`; it is reached
// through `event_pk`, so every read joins `committed_events` to recover it.
// One shared column list keeps the eight read paths from drifting apart.
//
// The join is against the normalized read surface rather than the base table:
// a sibling an accepted `ak.fork.resolution` adjudicated out must leave the
// reducer's input as well as the ordinary Event reads, and one projection is
// the only way those two cannot drift apart.
const PROJECTION_EVENT_SELECT: &str = "SELECT parent.id AS event_id, projected.realm_id, \
     projected.event_kind, projected.operation_kind, projected.operation_id, \
     projected.sender_id AS sender, projected.payload, projected.created_at, \
     projected.received_at \
     FROM projection_events projected \
     JOIN committed_events parent ON parent.pk = projected.event_pk";
#[derive(QueryableByName)]
struct ProjectionEventRow {
    #[diesel(sql_type = diesel::sql_types::Binary)]
    event_id: Vec<u8>,
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Text)]
    event_kind: String,
    #[diesel(sql_type = Text)]
    operation_kind: String,
    #[diesel(sql_type = Nullable<sql_types::Uuid>)]
    operation_id: Option<Uuid>,
    #[diesel(sql_type = Nullable<Text>)]
    sender: Option<String>,
    #[diesel(sql_type = Jsonb)]
    payload: Value,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Timestamptz)]
    received_at: chrono::DateTime<chrono::Utc>,
}
#[derive(QueryableByName)]
struct ProjectionEventPkRow {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    pk: i64,
}
impl From<ProjectionEventRow> for ProjectionEventRecord {
    fn from(row: ProjectionEventRow) -> Self {
        let event_id: [u8; ids::EVENT_ID_BYTES] = row
            .event_id
            .try_into()
            .expect("projection_events.id must be 33 bytes");
        Self {
            event_id: ids::format_event_id(&event_id),
            realm_id: row.realm_id,
            event_kind: row.event_kind,
            operation_kind: row.operation_kind,
            operation_id: row
                .operation_id
                .as_ref()
                .map(|u| ids::format_typed_uuid("operation", u)),
            sender: row.sender,
            payload: row.payload,
            created_at: row.created_at,
            received_at: row.received_at,
        }
    }
}
/// Append a projection batch on a caller-owned connection.
///
/// The complete lock set is acquired in canonical Event-id order before the
/// first write, so two concurrent batches that share an Event can never
/// deadlock against each other. Member order stays the confirmed command
/// order of `records`.
pub(crate) async fn append_projection_batch_in_connection(
    conn: &mut diesel_async::AsyncPgConnection,
    records: Vec<ProjectionEventRecord>,
) -> PersistenceResult<Vec<ProjectionEventAppendOutcome>> {
    let mut identities = records
        .iter()
        .map(|record| {
            ids::parse_event_id(&record.event_id).ok_or_else(|| {
                PersistenceError::SchemaViolation("malformed projection Event id".into())
            })
        })
        .collect::<PersistenceResult<Vec<_>>>()?;
    identities.sort();
    identities.dedup();
    for id in identities {
        sql_query("SELECT pg_advisory_xact_lock(hashtextextended(encode($1, 'hex'), 0))")
            .bind::<Binary, _>(id.to_vec())
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
    }
    let mut outcomes = Vec::with_capacity(records.len());
    for record in records {
        outcomes.push(append_projection_event_in_transaction(conn, record).await?);
    }
    Ok(outcomes)
}

/// Append one projection row on a caller-owned connection.
///
/// The Event commit unit of work reuses this so business projection and the
/// authority-signed `RealmCommit` share one transaction: a reader can never see
/// a committed Event whose current-result projection is missing.
pub(crate) async fn append_projection_event_in_transaction(
    conn: &mut diesel_async::AsyncPgConnection,
    mut record: ProjectionEventRecord,
) -> PersistenceResult<ProjectionEventAppendOutcome> {
    // The local receipt observation can have finer precision than PostgreSQL.
    // Freeze it before insertion and replay comparison; created_at retains
    // the original signed Event's canonical millisecond value unchanged.
    record.received_at = arkret_canonical::normalize_timestamp_canonical(record.received_at);
    let event_id = ids::parse_event_id(&record.event_id)
        .ok_or_else(|| PersistenceError::SchemaViolation("malformed projection Event id".into()))?;
    let realm_pk = crate::realm_identity::ensure_realm_pk(conn, &record.realm_id).await?;
    sql_query("SELECT pg_advisory_xact_lock(hashtextextended(encode($1, 'hex'), 0))")
        .bind::<diesel::sql_types::Binary, _>(event_id.to_vec())
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    let event_pk = sql_query("SELECT pk FROM committed_events WHERE id = $1 AND realm_pk = $2")
        .bind::<diesel::sql_types::Binary, _>(event_id.to_vec())
        .bind::<diesel::sql_types::BigInt, _>(realm_pk)
        .get_result::<ProjectionEventPkRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .ok_or_else(|| PersistenceError::Conflict("event_not_accepted".to_owned()))?
        .pk;
    let inserted = sql_query(
            "INSERT INTO projection_events \
             (event_pk, realm_pk, realm_id, event_kind, operation_kind, operation_id, sender_id, payload, created_at, received_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
             ON CONFLICT (event_pk) DO NOTHING",
        )
        .bind::<diesel::sql_types::BigInt, _>(event_pk)
        .bind::<diesel::sql_types::BigInt, _>(realm_pk)
        .bind::<Text, _>(&record.realm_id)
        .bind::<Text, _>(&record.event_kind)
        .bind::<Text, _>(&record.operation_kind)
        .bind::<Nullable<sql_types::Uuid>, _>(
            record
                .operation_id
                .as_deref()
                .map(ids::typed_uuid_part_expect_internal),
        )
        .bind::<Nullable<Text>, _>(&record.sender)
        .bind::<Jsonb, _>(&record.payload)
        .bind::<Timestamptz, _>(record.created_at)
        .bind::<Timestamptz, _>(record.received_at)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    if inserted == 1 {
        return Ok(ProjectionEventAppendOutcome::Inserted);
    }
    let existing = sql_query(format!(
        "{PROJECTION_EVENT_SELECT} WHERE projected.event_pk = $1"
    ))
    .bind::<diesel::sql_types::BigInt, _>(event_pk)
    .get_result::<ProjectionEventRow>(&mut *conn)
    .await
    .map(ProjectionEventRecord::from)
    .map_err(PersistenceError::database)?;
    if existing.event_id == record.event_id
        && existing.realm_id == record.realm_id
        && existing.event_kind == record.event_kind
        && existing.operation_kind == record.operation_kind
        && existing.operation_id == record.operation_id
        && existing.sender == record.sender
        && existing.payload == record.payload
        && existing.created_at == record.created_at
        && existing.received_at == record.received_at
    {
        Ok(ProjectionEventAppendOutcome::AlreadyExists)
    } else {
        Err(PersistenceError::Conflict(
            "duplicate_conflict: projection differs for Event identity".to_owned(),
        ))
    }
}

#[async_trait]
impl ProjectionEventStore for PgProjectionEventStore {
    async fn append(
        &self,
        record: ProjectionEventRecord,
    ) -> PersistenceResult<ProjectionEventAppendOutcome> {
        Ok(self.append_batch(vec![record]).await?.remove(0))
    }

    async fn append_batch(
        &self,
        records: Vec<ProjectionEventRecord>,
    ) -> PersistenceResult<Vec<ProjectionEventAppendOutcome>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            Ok(append_projection_batch_in_connection(conn, records).await?)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<ProjectionEventRecord>> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query(format!("{PROJECTION_EVENT_SELECT} ORDER BY projected.pk"))
            .load::<ProjectionEventRow>(&mut conn)
            .await
            .map(|rows| rows.into_iter().map(ProjectionEventRecord::from).collect())
            .map_err(PersistenceError::database)
    }

    async fn snapshot_kind(
        &self,
        event_kind: &str,
    ) -> PersistenceResult<Vec<ProjectionEventRecord>> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query(format!(
            "{PROJECTION_EVENT_SELECT} WHERE projected.event_kind = $1 ORDER BY projected.pk"
        ))
        .bind::<Text, _>(event_kind)
        .load::<ProjectionEventRow>(&mut conn)
        .await
        .map(|rows| rows.into_iter().map(ProjectionEventRecord::from).collect())
        .map_err(PersistenceError::database)
    }

    async fn get(&self, event_id: &str) -> PersistenceResult<Option<ProjectionEventRecord>> {
        let mut conn = crate::pg_db(&self.pool);
        let event_id = ids::parse_event_id(event_id).ok_or_else(|| {
            PersistenceError::SchemaViolation(format!(
                "malformed projection Event id: {event_id:?}"
            ))
        })?;
        sql_query(format!("{PROJECTION_EVENT_SELECT} WHERE parent.id = $1"))
            .bind::<diesel::sql_types::Binary, _>(event_id.to_vec())
            .get_result::<ProjectionEventRow>(&mut conn)
            .await
            .optional()
            .map(|row| row.map(ProjectionEventRecord::from))
            .map_err(PersistenceError::database)
    }

    async fn get_by_operation_id(
        &self,
        operation_id: &str,
    ) -> PersistenceResult<Option<ProjectionEventRecord>> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query(format!(
            "{PROJECTION_EVENT_SELECT} WHERE projected.operation_id = $1 \
             ORDER BY projected.pk DESC LIMIT 1"
        ))
        .bind::<sql_types::Uuid, _>(ids::typed_uuid_part_expect_internal(operation_id))
        .get_result::<ProjectionEventRow>(&mut conn)
        .await
        .optional()
        .map(|row| row.map(ProjectionEventRecord::from))
        .map_err(PersistenceError::database)
    }

    async fn snapshot_realm(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Vec<ProjectionEventRecord>> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query(format!(
            "{PROJECTION_EVENT_SELECT} \
             WHERE projected.realm_pk = (SELECT pk FROM canonical_realms WHERE wire_id = $1) \
             ORDER BY projected.pk"
        ))
        .bind::<Text, _>(realm_id)
        .load::<ProjectionEventRow>(&mut conn)
        .await
        .map(|rows| rows.into_iter().map(ProjectionEventRecord::from).collect())
        .map_err(PersistenceError::database)
    }

    async fn snapshot_actor(
        &self,
        actor_id: &str,
    ) -> PersistenceResult<Vec<ProjectionEventRecord>> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query(format!(
            "{PROJECTION_EVENT_SELECT} \
             WHERE projected.sender_id = $1 OR projected.payload ->> 'sender' = $1 \
                OR projected.payload ->> 'actor_id' = $1 OR projected.payload ->> 'actor' = $1 \
                OR projected.payload -> 'object' ->> 'created_by' = $1 \
             ORDER BY projected.pk"
        ))
        .bind::<Text, _>(actor_id)
        .load::<ProjectionEventRow>(&mut conn)
        .await
        .map(|rows| rows.into_iter().map(ProjectionEventRecord::from).collect())
        .map_err(PersistenceError::database)
    }
}

pub struct PgCircleProjectionStore {
    pub pool: PgPool,
}

#[derive(QueryableByName)]
struct CircleProjectionRow {
    #[diesel(sql_type = Binary)]
    circle_id: Vec<u8>,
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Nullable<Text>)]
    profile_ref: Option<String>,
    #[diesel(sql_type = Text)]
    title: String,
    #[diesel(sql_type = Nullable<Text>)]
    summary: Option<String>,
    #[diesel(sql_type = Jsonb)]
    display: Value,
    #[diesel(sql_type = Text)]
    directory_visibility: String,
    #[diesel(sql_type = Text)]
    join_rule: String,
    #[diesel(sql_type = Text)]
    history_access: String,
    #[diesel(sql_type = Text)]
    encryption_profile: String,
    #[diesel(sql_type = Nullable<Text>)]
    mls_group_ref: Option<String>,
    #[diesel(sql_type = Text)]
    state: String,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    state_changed_at: Option<chrono::DateTime<chrono::Utc>>,
    #[diesel(sql_type = Jsonb)]
    created_by: arkret_wire::ActorId,
    #[diesel(sql_type = Nullable<Jsonb>)]
    updated_by: Option<arkret_wire::ActorId>,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<CircleProjectionRow> for CircleProjectionRecord {
    fn from(row: CircleProjectionRow) -> Self {
        Self {
            circle_id: token_string("circle", &row.circle_id),
            realm_id: row.realm_id,
            profile_ref: row.profile_ref,
            title: row.title,
            summary: row.summary,
            display: row.display,
            directory_visibility: row.directory_visibility,
            join_rule: row.join_rule,
            history_access: row.history_access,
            encryption_profile: row.encryption_profile,
            mls_group_ref: row.mls_group_ref,
            state: row.state,
            state_changed_at: row.state_changed_at,
            created_by: row.created_by.to_string(),
            updated_by: row.updated_by.map(|id| id.to_string()),
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

const CIRCLE_PROJECTION_COLUMNS: &str = "id AS circle_id, realm_id, profile_ref, title, summary, display, \
     directory_visibility, join_rule, history_access, \
     encryption_profile, mls_group_ref, state, state_changed_at, \
     created_by AS created_by, updated_by AS updated_by, created_at, updated_at";

#[derive(QueryableByName)]
struct CircleMemberProjectionRow {
    #[diesel(sql_type = Binary)]
    circle_id: Vec<u8>,
    #[diesel(sql_type = Text)]
    actor_id: String,
    #[diesel(sql_type = Text)]
    state: String,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    invited_at: Option<chrono::DateTime<chrono::Utc>>,
    #[diesel(sql_type = Timestamptz)]
    joined_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Timestamptz)]
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<CircleMemberProjectionRow> for CircleMemberProjectionRecord {
    fn from(row: CircleMemberProjectionRow) -> Self {
        Self {
            circle_id: token_string("circle", &row.circle_id),
            actor_id: row.actor_id.to_string(),
            state: row.state,
            invited_at: row.invited_at,
            joined_at: row.joined_at,
            updated_at: row.updated_at,
        }
    }
}

#[async_trait]
impl CircleProjectionStore for PgCircleProjectionStore {
    async fn get(&self, circle_id: &str) -> PersistenceResult<Option<CircleProjectionRecord>> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query(format!(
            "SELECT {CIRCLE_PROJECTION_COLUMNS} FROM projection_circles WHERE id = $1"
        ))
        .bind::<Binary, _>(token_bytes("circle", circle_id))
        .get_result::<CircleProjectionRow>(&mut conn)
        .await
        .optional()
        .map(|row| row.map(CircleProjectionRecord::from))
        .map_err(PersistenceError::database)
    }

    async fn put(&self, record: &CircleProjectionRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        crate::realm_identity::ensure_realm_pk(&mut conn, &record.realm_id).await?;
        sql_query(
            "INSERT INTO projection_circles \
             (id, realm_id, profile_ref, title, summary, display, directory_visibility, join_rule, \
              history_access, encryption_profile, mls_group_ref, state, \
              state_changed_at, created_by, \
              updated_by, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17) \
             ON CONFLICT (id) DO UPDATE SET \
                realm_id = EXCLUDED.realm_id, \
                profile_ref = EXCLUDED.profile_ref, \
                title = EXCLUDED.title, \
                summary = EXCLUDED.summary, \
                display = EXCLUDED.display, \
                directory_visibility = EXCLUDED.directory_visibility, \
                join_rule = EXCLUDED.join_rule, \
                history_access = EXCLUDED.history_access, \
                encryption_profile = EXCLUDED.encryption_profile, \
                mls_group_ref = EXCLUDED.mls_group_ref, \
                state = EXCLUDED.state, \
                state_changed_at = EXCLUDED.state_changed_at, \
                updated_by = EXCLUDED.updated_by, \
                updated_at = EXCLUDED.updated_at",
        )
        .bind::<Binary, _>(token_bytes("circle", &record.circle_id))
        .bind::<Text, _>(&record.realm_id)
        .bind::<Nullable<Text>, _>(&record.profile_ref)
        .bind::<Text, _>(&record.title)
        .bind::<Nullable<Text>, _>(&record.summary)
        .bind::<Jsonb, _>(&record.display)
        .bind::<Text, _>(&record.directory_visibility)
        .bind::<Text, _>(&record.join_rule)
        .bind::<Text, _>(&record.history_access)
        .bind::<Text, _>(&record.encryption_profile)
        .bind::<Nullable<Text>, _>(&record.mls_group_ref)
        .bind::<Text, _>(&record.state)
        .bind::<Nullable<Timestamptz>, _>(record.state_changed_at)
        .bind::<Jsonb, _>(stored_actor(&record.created_by)?)
        .bind::<Nullable<Jsonb>, _>(record.updated_by.as_deref().map(stored_actor).transpose()?)
        .bind::<Timestamptz, _>(record.created_at)
        .bind::<Nullable<Timestamptz>, _>(record.updated_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn list_for_realm(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Vec<CircleProjectionRecord>> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query(format!(
            "SELECT {CIRCLE_PROJECTION_COLUMNS} FROM projection_circles \
             WHERE realm_id = $1 ORDER BY pk"
        ))
        .bind::<Text, _>(realm_id)
        .load::<CircleProjectionRow>(&mut conn)
        .await
        .map(|rows| rows.into_iter().map(CircleProjectionRecord::from).collect())
        .map_err(PersistenceError::database)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<CircleProjectionRecord>> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query(format!(
            "SELECT {CIRCLE_PROJECTION_COLUMNS} FROM projection_circles ORDER BY pk"
        ))
        .load::<CircleProjectionRow>(&mut conn)
        .await
        .map(|rows| rows.into_iter().map(CircleProjectionRecord::from).collect())
        .map_err(PersistenceError::database)
    }

    async fn delete(&self, circle_id: &str) -> PersistenceResult<()> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query("DELETE FROM projection_circles WHERE id = $1")
            .bind::<Binary, _>(token_bytes("circle", circle_id))
            .execute(&mut conn)
            .await
            .map(|_| ())
            .map_err(PersistenceError::database)
    }

    async fn put_members(
        &self,
        circle_id: &str,
        members: &[CircleMemberProjectionRecord],
    ) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let circle_token = token_bytes("circle", circle_id);
        let members = members.to_vec();
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            // Membership is a set, not a log: a member the reducer dropped
            // has to disappear in the same commit that writes the
            // survivors, or a removed actor stays inside the Circle
            // boundary until the next full replay.
            sql_query(
                "DELETE FROM projection_circle_members \
                     WHERE circle_pk = (SELECT pk FROM projection_circles WHERE id = $1)",
            )
            .bind::<Binary, _>(circle_token.clone())
            .execute(&mut *conn)
            .await?;
            for member in &members {
                sql_query(
                    "INSERT INTO projection_circle_members \
                         (circle_pk, actor_id, state, invited_at, joined_at, updated_at) \
                         SELECT pk, $2, $3, $4, $5, $6 FROM projection_circles WHERE id = $1",
                )
                .bind::<Binary, _>(circle_token.clone())
                .bind::<Text, _>(&member.actor_id)
                .bind::<Text, _>(&member.state)
                .bind::<Nullable<Timestamptz>, _>(member.invited_at)
                .bind::<Timestamptz, _>(member.joined_at)
                .bind::<Timestamptz, _>(member.updated_at)
                .execute(&mut *conn)
                .await?;
            }
            Ok(())
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn snapshot_all_members(&self) -> PersistenceResult<Vec<CircleMemberProjectionRecord>> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query(
            "SELECT c.id AS circle_id, m.actor_id, m.state, m.invited_at, m.joined_at, m.updated_at \
             FROM projection_circle_members m JOIN projection_circles c ON c.pk = m.circle_pk \
             ORDER BY m.pk",
        )
        .load::<CircleMemberProjectionRow>(&mut conn)
        .await
        .map(|rows| {
            rows.into_iter()
                .map(CircleMemberProjectionRecord::from)
                .collect()
        })
        .map_err(PersistenceError::database)
    }
}

const REALM_META_COLUMNS: &str = "realm_id, owner, deleted, discoverability, history_access, \
     preview_policy, preview_policy_digest, asset_privacy_policy, asset_privacy_policy_digest, encryption_profile, \
     plaintext_visible_services, plaintext_visible_service_classes, minimal_metadata_realm, \
     created_at, updated_at";

pub struct PgRealmMetaStore {
    pub pool: PgPool,
}

#[derive(QueryableByName)]
struct RealmMetaRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Text)]
    owner: String,
    #[diesel(sql_type = Bool)]
    deleted: bool,
    #[diesel(sql_type = Text)]
    discoverability: String,
    #[diesel(sql_type = Text)]
    history_access: String,
    #[diesel(sql_type = Nullable<Jsonb>)]
    preview_policy: Option<Value>,
    #[diesel(sql_type = Nullable<Text>)]
    preview_policy_digest: Option<String>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    asset_privacy_policy: Option<Value>,
    #[diesel(sql_type = Nullable<Text>)]
    asset_privacy_policy_digest: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    encryption_profile: Option<String>,
    #[diesel(sql_type = Jsonb)]
    plaintext_visible_services: Value,
    #[diesel(sql_type = Jsonb)]
    plaintext_visible_service_classes: Value,
    #[diesel(sql_type = Bool)]
    minimal_metadata_realm: bool,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Timestamptz)]
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<RealmMetaRow> for RealmMetaRecord {
    fn from(row: RealmMetaRow) -> Self {
        Self {
            owner: row.owner,
            deleted: row.deleted,
            discoverability: row.discoverability,
            history_access: row.history_access,
            preview_policy: row.preview_policy,
            preview_policy_digest: row.preview_policy_digest,
            asset_privacy_policy: row.asset_privacy_policy,
            asset_privacy_policy_digest: row.asset_privacy_policy_digest,
            encryption_profile: row.encryption_profile,
            plaintext_visible_services: serde_json::from_value(row.plaintext_visible_services)
                .unwrap_or_default(),
            plaintext_visible_service_classes: serde_json::from_value(
                row.plaintext_visible_service_classes,
            )
            .unwrap_or_default(),
            minimal_metadata_realm: row.minimal_metadata_realm,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[async_trait]
impl RealmMetaStore for PgRealmMetaStore {
    async fn get(&self, realm_id: &str) -> PersistenceResult<Option<RealmMetaRecord>> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query(format!(
            "SELECT {REALM_META_COLUMNS} FROM realm_meta WHERE realm_id = $1"
        ))
        .bind::<Text, _>(realm_id)
        .get_result::<RealmMetaRow>(&mut conn)
        .await
        .optional()
        .map(|row| row.map(RealmMetaRecord::from))
        .map_err(PersistenceError::database)
    }

    async fn put(&self, realm_id: &str, record: &RealmMetaRecord) -> PersistenceResult<()> {
        let plaintext_visible_services = serde_json::to_value(&record.plaintext_visible_services)
            .map_err(|error| {
            PersistenceError::Internal(format!("cannot encode plaintext_visible_services: {error}"))
        })?;
        let plaintext_visible_service_classes =
            serde_json::to_value(&record.plaintext_visible_service_classes).map_err(|error| {
                PersistenceError::Internal(format!(
                    "cannot encode plaintext_visible_service_classes: {error}"
                ))
            })?;
        let mut conn = crate::pg_db(&self.pool);
        sql_query(
            "INSERT INTO realm_meta \
             (realm_id, owner, deleted, discoverability, history_access, \
              preview_policy, preview_policy_digest, asset_privacy_policy, asset_privacy_policy_digest, \
              encryption_profile, plaintext_visible_services, plaintext_visible_service_classes, \
              minimal_metadata_realm, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) \
             ON CONFLICT (realm_id) DO UPDATE SET \
                owner = EXCLUDED.owner, \
                deleted = EXCLUDED.deleted, \
                discoverability = EXCLUDED.discoverability, \
                history_access = EXCLUDED.history_access, \
                preview_policy = EXCLUDED.preview_policy, \
                preview_policy_digest = EXCLUDED.preview_policy_digest, \
                asset_privacy_policy = EXCLUDED.asset_privacy_policy, \
                asset_privacy_policy_digest = EXCLUDED.asset_privacy_policy_digest, \
                encryption_profile = EXCLUDED.encryption_profile, \
                plaintext_visible_services = EXCLUDED.plaintext_visible_services, \
                plaintext_visible_service_classes = EXCLUDED.plaintext_visible_service_classes, \
                minimal_metadata_realm = EXCLUDED.minimal_metadata_realm, \
                created_at = EXCLUDED.created_at, \
                updated_at = EXCLUDED.updated_at",
        )
        .bind::<Text, _>(realm_id)
        .bind::<Text, _>(&record.owner)
        .bind::<Bool, _>(record.deleted)
        .bind::<Text, _>(&record.discoverability)
        .bind::<Text, _>(&record.history_access)
        .bind::<Nullable<Jsonb>, _>(&record.preview_policy)
        .bind::<Nullable<Text>, _>(&record.preview_policy_digest)
        .bind::<Nullable<Jsonb>, _>(&record.asset_privacy_policy)
        .bind::<Nullable<Text>, _>(&record.asset_privacy_policy_digest)
        .bind::<Nullable<Text>, _>(&record.encryption_profile)
        .bind::<Jsonb, _>(&plaintext_visible_services)
        .bind::<Jsonb, _>(&plaintext_visible_service_classes)
        .bind::<Bool, _>(record.minimal_metadata_realm)
        .bind::<Timestamptz, _>(record.created_at)
        .bind::<Timestamptz, _>(record.updated_at)
        .execute(&mut conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn list(&self) -> PersistenceResult<Vec<(String, RealmMetaRecord)>> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query(format!(
            "SELECT {REALM_META_COLUMNS} FROM realm_meta ORDER BY realm_id"
        ))
        .load::<RealmMetaRow>(&mut conn)
        .await
        .map(|rows| {
            rows.into_iter()
                .map(|row| {
                    let realm_id = row.realm_id.clone();
                    (realm_id, RealmMetaRecord::from(row))
                })
                .collect()
        })
        .map_err(PersistenceError::database)
    }

    async fn delete(&self, realm_id: &str) -> PersistenceResult<()> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query("DELETE FROM realm_meta WHERE realm_id = $1")
            .bind::<Text, _>(realm_id)
            .execute(&mut conn)
            .await
            .map(|_| ())
            .map_err(PersistenceError::database)
    }
}
