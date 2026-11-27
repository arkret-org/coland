use super::{PersistenceResult, Value, async_trait};

/// Service-local lifecycle of a Sidecar projection. Creation/attachment is
/// committed on the Sidecar's own stream; lifecycle is not a producer Event
/// ordering field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SidecarLifecycleState {
    Active,
    Suspended,
    Tombstoned,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentSidecarRecord {
    pub sidecar_id: String,
    pub realm_id: String,
    pub source_realm_id: String,
    pub controller_account_id: arkret_wire::AccountId,
    /// Lifecycle state; canonical SDK enum, persisted as its snake_case wire
    /// name (`active` | `suspended` | `tombstoned`).
    pub state: SidecarLifecycleState,
    pub state_changed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentSidecarContextRecord {
    pub sidecar_id: String,
    pub normalized_context_ref_digest: String,
    pub normalized_context_ref: Value,
    pub version: i64,
    pub predecessor_event_ref: Option<String>,
    pub attach_event_ref: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[async_trait]
pub trait SidecarStore: Send + Sync {
    async fn insert_or_get(
        &self,
        record: AgentSidecarRecord,
    ) -> PersistenceResult<AgentSidecarRecord>;
    async fn get(&self, sidecar_id: &str) -> PersistenceResult<Option<AgentSidecarRecord>>;
    async fn get_for_realm_controller(
        &self,
        realm_id: &str,
        controller_account_id: &arkret_wire::AccountId,
    ) -> PersistenceResult<Option<AgentSidecarRecord>>;
    async fn list_for_controller(
        &self,
        controller_account_id: &arkret_wire::AccountId,
        realm_id: Option<&str>,
    ) -> PersistenceResult<Vec<AgentSidecarRecord>>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<AgentSidecarRecord>>;
    async fn insert_or_get_context(
        &self,
        record: AgentSidecarContextRecord,
    ) -> PersistenceResult<AgentSidecarContextRecord>;
    async fn get_context(
        &self,
        sidecar_id: &str,
        normalized_context_ref_digest: &str,
    ) -> PersistenceResult<Option<AgentSidecarContextRecord>>;
}
