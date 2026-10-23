use coland_storage::SidecarLifecycleState;

use super::{
    AgentSidecarContextRecord, AgentSidecarRecord, AsyncPgConnection, BigInt, Binary, Jsonb,
    Nullable, Object, OptionalExtension, PersistenceError, PersistenceResult, PgPool,
    QueryableByName, RunQueryDsl, SidecarStore, Text, Timestamptz, Value, async_trait, ids,
    pg_conn, sql_query,
};

fn sidecar_id_bytes(sidecar_id: &str) -> Vec<u8> {
    ids::event_token_part_expect_internal(sidecar_id, "sidecar").to_vec()
}

fn event_token(bytes: &[u8]) -> String {
    let token: [u8; ids::EVENT_ID_BYTES] = bytes
        .try_into()
        .expect("stored Event reference must be 33 bytes");
    ids::format_event_id(&token)
}

pub struct PgSidecarStore {
    pub pool: PgPool,
}

#[derive(QueryableByName)]
struct SidecarRow {
    #[diesel(sql_type = Binary)]
    id: Vec<u8>,
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Jsonb)]
    controller_account_id: Value,
    #[diesel(sql_type = Text)]
    state: String,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    state_changed_at: Option<chrono::DateTime<chrono::Utc>>,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl TryFrom<SidecarRow> for AgentSidecarRecord {
    type Error = PersistenceError;

    fn try_from(row: SidecarRow) -> Result<Self, Self::Error> {
        let sidecar_id = {
            let token: [u8; ids::EVENT_ID_BYTES] = row
                .id
                .as_slice()
                .try_into()
                .expect("agent_sidecars.id must be 33 bytes");
            ids::format_event_token("sidecar", &token)
        };
        let state = serde_json::from_value(Value::String(row.state)).map_err(|error| {
            PersistenceError::Internal(format!("Sidecar `{sidecar_id}` has invalid state: {error}"))
        })?;
        Ok(Self {
            sidecar_id: sidecar_id.clone(),
            realm_id: row.realm_id,
            controller_account_id: serde_json::from_value(row.controller_account_id).map_err(
                |error| {
                    PersistenceError::Internal(format!(
                        "Sidecar `{sidecar_id}` has invalid controller account: {error}"
                    ))
                },
            )?,
            state,
            state_changed_at: row.state_changed_at,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

/// Snake_case name of the local Sidecar lifecycle projection, matching
/// the text-column encoding of `agent_sidecars.state`.
fn sidecar_state_label(state: SidecarLifecycleState) -> &'static str {
    match state {
        SidecarLifecycleState::Active => "active",
        SidecarLifecycleState::Suspended => "suspended",
        SidecarLifecycleState::Tombstoned => "tombstoned",
    }
}

#[derive(QueryableByName)]
struct SidecarContextRow {
    #[diesel(sql_type = Binary)]
    sidecar_id: Vec<u8>,
    #[diesel(sql_type = Text)]
    normalized_context_ref_digest: String,
    #[diesel(sql_type = Jsonb)]
    normalized_context_ref: Value,
    #[diesel(sql_type = BigInt)]
    version: i64,
    #[diesel(sql_type = Nullable<Binary>)]
    predecessor_event_ref: Option<Vec<u8>>,
    #[diesel(sql_type = Binary)]
    attach_event_ref: Vec<u8>,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
}

impl From<SidecarContextRow> for AgentSidecarContextRecord {
    fn from(row: SidecarContextRow) -> Self {
        Self {
            sidecar_id: {
                let token: [u8; ids::EVENT_ID_BYTES] = row
                    .sidecar_id
                    .as_slice()
                    .try_into()
                    .expect("agent_sidecars.id must be 33 bytes");
                ids::format_event_token("sidecar", &token)
            },
            normalized_context_ref_digest: row.normalized_context_ref_digest,
            normalized_context_ref: row.normalized_context_ref,
            version: row.version,
            predecessor_event_ref: row.predecessor_event_ref.as_deref().map(event_token),
            attach_event_ref: event_token(&row.attach_event_ref),
            created_at: row.created_at,
        }
    }
}

const SIDECAR_SELECT: &str = "SELECT id, realm_id, controller_account_id, state, state_changed_at, created_at, updated_at FROM agent_sidecars";
// `sidecar_pk` never leaves the database, so every context read joins back to
// `agent_sidecars` and returns the protocol 33-byte Sidecar identity instead.
const CONTEXT_SELECT: &str = "SELECT s.id AS sidecar_id, c.normalized_context_ref_digest, c.normalized_context_ref, c.version, c.predecessor_event_ref, c.attach_event_ref, c.created_at      FROM agent_sidecar_contexts c JOIN agent_sidecars s ON s.pk = c.sidecar_pk";

#[derive(QueryableByName)]
struct SidecarPkRow {
    #[diesel(sql_type = BigInt)]
    pk: i64,
}

async fn sidecar_pk(
    conn: &mut Object<AsyncPgConnection>,
    sidecar_id: &str,
) -> PersistenceResult<i64> {
    sql_query("SELECT pk FROM agent_sidecars WHERE id=$1")
        .bind::<Binary, _>(sidecar_id_bytes(sidecar_id))
        .get_result::<SidecarPkRow>(&mut **conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(|row| row.pk)
        .ok_or_else(|| {
            PersistenceError::SchemaViolation(format!("unknown Sidecar id {sidecar_id:?}"))
        })
}

#[async_trait]
impl SidecarStore for PgSidecarStore {
    async fn insert_or_get(
        &self,
        record: AgentSidecarRecord,
    ) -> PersistenceResult<AgentSidecarRecord> {
        let mut conn = pg_conn(&self.pool).await?;
        let id = sidecar_id_bytes(&record.sidecar_id);
        crate::realm_identity::ensure_realm_pk(&mut conn, &record.realm_id).await?;
        sql_query(
            "WITH inserted AS (\
             INSERT INTO agent_sidecars (id, realm_id, controller_account_id, state, state_changed_at, created_at, updated_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (realm_id, controller_account_id) DO NOTHING \
             RETURNING id, realm_id, controller_account_id, state, state_changed_at, created_at, updated_at) \
             SELECT * FROM inserted UNION ALL \
             SELECT id, realm_id, controller_account_id, state, state_changed_at, created_at, updated_at \
             FROM agent_sidecars WHERE realm_id=$2 AND controller_account_id=$3 LIMIT 1",
        )
        .bind::<Binary, _>(id)
        .bind::<Text, _>(&record.realm_id)
        .bind::<Jsonb, _>(serde_json::to_value(&record.controller_account_id).map_err(|error| {
            PersistenceError::SchemaViolation(format!("Sidecar controller account is not serializable: {error}"))
        })?)
        .bind::<Text, _>(sidecar_state_label(record.state))
        .bind::<Nullable<Timestamptz>, _>(record.state_changed_at)
        .bind::<Timestamptz, _>(record.created_at)
        .bind::<Nullable<Timestamptz>, _>(record.updated_at)
        .get_result::<SidecarRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)
        .and_then(AgentSidecarRecord::try_from)
    }

    async fn get(&self, sidecar_id: &str) -> PersistenceResult<Option<AgentSidecarRecord>> {
        let mut conn = crate::pg_db(&self.pool);
        let id = sidecar_id_bytes(sidecar_id);
        sql_query(format!("{SIDECAR_SELECT} WHERE id=$1"))
            .bind::<Binary, _>(id)
            .get_result::<SidecarRow>(&mut conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?
            .map(AgentSidecarRecord::try_from)
            .transpose()
    }

    async fn get_for_realm_controller(
        &self,
        realm_id: &str,
        controller_account_id: &arkret_wire::AccountId,
    ) -> PersistenceResult<Option<AgentSidecarRecord>> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query(format!(
            "{SIDECAR_SELECT} WHERE realm_id=$1 AND controller_account_id=$2"
        ))
        .bind::<Text, _>(realm_id)
        .bind::<Jsonb, _>(
            serde_json::to_value(controller_account_id).map_err(|error| {
                PersistenceError::SchemaViolation(format!(
                    "Sidecar controller account is not serializable: {error}"
                ))
            })?,
        )
        .get_result::<SidecarRow>(&mut conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(AgentSidecarRecord::try_from)
        .transpose()
    }

    async fn list_for_controller(
        &self,
        controller_account_id: &arkret_wire::AccountId,
        realm_id: Option<&str>,
    ) -> PersistenceResult<Vec<AgentSidecarRecord>> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query(format!(
            "{SIDECAR_SELECT} WHERE controller_account_id=$1 AND ($2 IS NULL OR realm_id=$2) ORDER BY created_at,pk"
        ))
        .bind::<Jsonb, _>(serde_json::to_value(controller_account_id).map_err(|error| {
            PersistenceError::SchemaViolation(format!("Sidecar controller account is not serializable: {error}"))
        })?)
            .bind::<Nullable<Text>, _>(realm_id)
        .load::<SidecarRow>(&mut conn)
        .await
        .map_err(PersistenceError::database)?
        .into_iter()
        .map(AgentSidecarRecord::try_from)
        .collect()
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<AgentSidecarRecord>> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query(format!("{SIDECAR_SELECT} ORDER BY created_at,pk"))
            .load::<SidecarRow>(&mut conn)
            .await
            .map_err(PersistenceError::database)?
            .into_iter()
            .map(AgentSidecarRecord::try_from)
            .collect()
    }

    async fn insert_or_get_context(
        &self,
        record: AgentSidecarContextRecord,
    ) -> PersistenceResult<AgentSidecarContextRecord> {
        let mut conn = pg_conn(&self.pool).await?;
        let sidecar_pk = sidecar_pk(&mut conn, &record.sidecar_id).await?;
        let predecessor_event_ref = record
            .predecessor_event_ref
            .as_deref()
            .map(|event_id| ids::event_token_part_expect_internal(event_id, "event").to_vec());
        let attach_event_ref =
            ids::event_token_part_expect_internal(&record.attach_event_ref, "event").to_vec();
        sql_query(
            "WITH inserted AS (\
             INSERT INTO agent_sidecar_contexts (sidecar_pk, normalized_context_ref_digest, normalized_context_ref, version, predecessor_event_ref, attach_event_ref, created_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (sidecar_pk, normalized_context_ref_digest, version) DO NOTHING \
             RETURNING sidecar_pk, normalized_context_ref_digest, normalized_context_ref, version, predecessor_event_ref, attach_event_ref, created_at) \
             SELECT s.id AS sidecar_id, c.normalized_context_ref_digest, c.normalized_context_ref, c.version, c.predecessor_event_ref, c.attach_event_ref, c.created_at \
             FROM (SELECT * FROM inserted UNION ALL \
                   SELECT sidecar_pk, normalized_context_ref_digest, normalized_context_ref, version, predecessor_event_ref, attach_event_ref, created_at \
                   FROM agent_sidecar_contexts WHERE sidecar_pk=$1 AND normalized_context_ref_digest=$2 AND version=$4) c \
             JOIN agent_sidecars s ON s.pk = c.sidecar_pk LIMIT 1",
        )
        .bind::<BigInt, _>(sidecar_pk)
        .bind::<Text, _>(&record.normalized_context_ref_digest)
        .bind::<Jsonb, _>(&record.normalized_context_ref)
        .bind::<BigInt, _>(record.version)
        .bind::<Nullable<Binary>, _>(predecessor_event_ref)
        .bind::<Binary, _>(attach_event_ref)
        .bind::<Timestamptz, _>(record.created_at)
        .get_result::<SidecarContextRow>(&mut *conn)
        .await
        .map(AgentSidecarContextRecord::from)
        .map_err(PersistenceError::database)
    }

    async fn get_context(
        &self,
        sidecar_id: &str,
        normalized_context_ref_digest: &str,
    ) -> PersistenceResult<Option<AgentSidecarContextRecord>> {
        let mut conn = crate::pg_db(&self.pool);
        let sidecar_id = sidecar_id_bytes(sidecar_id);
        sql_query(format!(
            "{CONTEXT_SELECT} WHERE s.id=$1 AND c.normalized_context_ref_digest=$2 ORDER BY c.version DESC LIMIT 1"
        ))
        .bind::<Binary, _>(sidecar_id)
        .bind::<Text, _>(normalized_context_ref_digest)
        .get_result::<SidecarContextRow>(&mut conn)
        .await
        .optional()
        .map(|row| row.map(AgentSidecarContextRecord::from))
        .map_err(PersistenceError::database)
    }
}
