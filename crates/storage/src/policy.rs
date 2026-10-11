// Durable adapters enforce the same policy invariants as the domain reducer.
pub use coland_domain::reducer::{
    join_policy_declares_an_automatic_gate, join_rule_requires_an_automatic_gate,
    validate_join_policy_payload,
};

use super::{PersistenceResult, PolicyDocumentRecord, async_trait};

/// Per-owner policy documents.
#[async_trait]
pub trait PolicyDocumentStore: Send + Sync {
    async fn get(&self, policy_id: &str) -> PersistenceResult<Option<PolicyDocumentRecord>>;
    async fn put(&self, record: PolicyDocumentRecord) -> PersistenceResult<()>;
    async fn delete(&self, policy_id: &str) -> PersistenceResult<bool>;
    async fn list_for_owner(&self, owner: &str) -> PersistenceResult<Vec<PolicyDocumentRecord>>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<PolicyDocumentRecord>>;
}
