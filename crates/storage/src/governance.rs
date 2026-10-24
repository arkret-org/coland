use arkret_wire::DidCoreId;

use super::{
    BTreeSet, OrganizationRecord, PersistenceResult, RealmOrganizationStatementRecord,
    RetentionPolicyRecord, RetentionTombstoneRecord, async_trait,
};
#[async_trait]
pub trait HandleReleaseStore: Send + Sync {
    async fn put(
        &self,
        localpart: &str,
        released_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<()>;
    async fn snapshot_all(&self)
    -> PersistenceResult<Vec<(String, chrono::DateTime<chrono::Utc>)>>;
}
#[async_trait]
pub trait RetentionPolicyStore: Send + Sync {
    async fn get(&self, realm_id: &str) -> PersistenceResult<Option<RetentionPolicyRecord>>;
    async fn put(&self, record: &RetentionPolicyRecord) -> PersistenceResult<()>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<RetentionPolicyRecord>>;
}
#[async_trait]
pub trait RetentionTombstoneStore: Send + Sync {
    async fn get(&self, event_id: &str) -> PersistenceResult<Option<RetentionTombstoneRecord>>;
    async fn put(&self, record: &RetentionTombstoneRecord) -> PersistenceResult<()>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<RetentionTombstoneRecord>>;
}
#[async_trait]
pub trait OrganizationStore: Send + Sync {
    async fn get(&self, organization_id: &str) -> PersistenceResult<Option<OrganizationRecord>>;
    async fn put(&self, record: &OrganizationRecord) -> PersistenceResult<()>;
    async fn list(&self) -> PersistenceResult<Vec<OrganizationRecord>>;
}
/// SOL-ORG-05 — declared `owning_organization_ids` hint links. These are NOT
/// verified relationships and do not drive policy inheritance; see
/// [`RealmOrganizationStatementStore`] for the verified statement surface.
/// Backed by the `realm_owning_organizations` table.
#[async_trait]
pub trait RealmOrganizationStore: Send + Sync {
    async fn link(&self, realm_id: &str, organization_id: &DidCoreId) -> PersistenceResult<()>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<(String, BTreeSet<DidCoreId>)>>;
}
/// SOL-ORG-04 — verified `ak.realm.organization` relationship statements.
/// Backed by the `realm_organizations` table, keyed by
/// `(realm_id, organization_id, relationship)`.
#[async_trait]
pub trait RealmOrganizationStatementStore: Send + Sync {
    async fn accepted_relationships(
        &self,
        realm_id: &arkret_wire::RealmId,
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<Vec<arkret_models_collaboration::governance::realm_governance::RealmOrganizationRelationshipView>>;
    /// Refuse a sensitive dependency on the unavailable cross-Realm policy
    /// authority from accepted relationships at one locked Realm cut.
    async fn require_moderation_authority(
        &self,
        realm_id: &arkret_wire::RealmId,
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<()>;
    async fn put(&self, record: &RealmOrganizationStatementRecord) -> PersistenceResult<()>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<RealmOrganizationStatementRecord>>;
}
