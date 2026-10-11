use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use arkret_identifiers::DidCoreId;
use async_trait::async_trait;
pub use coland_storage::{
    OrganizationRecord, PolicyDocumentRecord, RetentionPolicyRecord, RetentionTombstoneRecord,
};
use parking_lot::Mutex;
use serde_json::Value;

use crate::ServiceResult;

#[async_trait]
pub trait RuntimeSettingsPort: Send + Sync {
    async fn load_overrides(&self) -> ServiceResult<Vec<(String, Value)>>;
    async fn store_override(&self, key: &str, value: &Value, updated_by: &str)
    -> ServiceResult<()>;
}

#[derive(Clone, Debug)]
pub struct AppendAuditEntryCommand {
    pub entry: Value,
}

#[async_trait]
pub trait AuditLogPort: Send + Sync {
    async fn append(&self, entry: Value) -> ServiceResult<()>;
    async fn entries(&self) -> ServiceResult<Vec<Value>>;
    async fn entries_for_actor(&self, actor_id: &str) -> ServiceResult<Vec<Value>>;
}

#[async_trait]
pub trait ModerationPort: Send + Sync {
    async fn queue_view_for_actor(
        &self,
        actor: &arkret_wire::ActorId,
        realm_id: Option<&arkret_wire::RealmId>,
    ) -> ServiceResult<
        Vec<arkret_models_collaboration::governance::moderation_queue::ModerationQueueItem>,
    >;
    async fn management_view_for_actor(
        &self,
        actor: &arkret_wire::ActorId,
        realm_id: Option<&arkret_wire::RealmId>,
    ) -> ServiceResult<coland_storage::ModerationManagementView>;
    async fn report_count(&self) -> ServiceResult<u64>;
}

#[async_trait]
pub trait GovernanceRecordsPort: Send + Sync {
    async fn organization(
        &self,
        organization_id: &str,
    ) -> ServiceResult<Option<OrganizationRecord>>;
    async fn store_organization(&self, record: &OrganizationRecord) -> ServiceResult<()>;
    async fn organizations(&self) -> ServiceResult<Vec<OrganizationRecord>>;
    async fn link_realm_organization(
        &self,
        realm_id: &str,
        organization_id: &DidCoreId,
    ) -> ServiceResult<()>;
    async fn realm_organization_links(&self) -> ServiceResult<Vec<(String, BTreeSet<DidCoreId>)>>;
    async fn policy_document(&self, policy_id: &str)
    -> ServiceResult<Option<PolicyDocumentRecord>>;
    async fn store_policy_document(&self, record: PolicyDocumentRecord) -> ServiceResult<()>;
    async fn delete_policy_document(&self, policy_id: &str) -> ServiceResult<bool>;
    async fn policy_documents_for_owner(
        &self,
        owner: &str,
    ) -> ServiceResult<Vec<PolicyDocumentRecord>>;
    async fn policy_documents(&self) -> ServiceResult<Vec<PolicyDocumentRecord>>;
    async fn retention_policy(
        &self,
        realm_id: &str,
    ) -> ServiceResult<Option<RetentionPolicyRecord>>;
    async fn store_retention_policy(&self, record: &RetentionPolicyRecord) -> ServiceResult<()>;
    async fn retention_tombstone(
        &self,
        event_id: &str,
    ) -> ServiceResult<Option<RetentionTombstoneRecord>>;
    async fn retention_tombstones(&self) -> ServiceResult<Vec<RetentionTombstoneRecord>>;
    async fn store_retention_tombstone(
        &self,
        record: &RetentionTombstoneRecord,
    ) -> ServiceResult<()>;
}

#[derive(Clone)]
pub struct GovernanceService {
    audit_log: Arc<dyn AuditLogPort>,
    moderation: Arc<dyn ModerationPort>,
    records: Arc<dyn GovernanceRecordsPort>,
    organizations: Arc<Mutex<BTreeMap<String, OrganizationRecord>>>,
    realm_organizations: Arc<Mutex<BTreeMap<String, BTreeSet<DidCoreId>>>>,
    organization_realms: Arc<Mutex<BTreeMap<DidCoreId, BTreeSet<String>>>>,
    retention_tombstones: Arc<Mutex<BTreeMap<String, RetentionTombstoneRecord>>>,
    runtime_settings: Arc<dyn RuntimeSettingsPort>,
}

impl GovernanceService {
    pub async fn hydrate_projections(&self) -> ServiceResult<()> {
        let retention_tombstones = self.records.retention_tombstones().await?;
        let organizations = self.records.organizations().await?;
        let realm_organizations = self.records.realm_organization_links().await?;

        self.replace_retention_tombstones(retention_tombstones);
        self.replace_organization_projection(organizations, realm_organizations);
        Ok(())
    }

    pub async fn organization(
        &self,
        organization_id: &str,
    ) -> ServiceResult<Option<OrganizationRecord>> {
        self.records.organization(organization_id).await
    }

    pub async fn store_organization(&self, record: &OrganizationRecord) -> ServiceResult<()> {
        self.records.store_organization(record).await?;
        self.organizations
            .lock()
            .insert(record.organization_id.clone(), record.clone());
        Ok(())
    }

    pub async fn organizations(&self) -> ServiceResult<Vec<OrganizationRecord>> {
        self.records.organizations().await
    }

    pub async fn link_realm_organization(
        &self,
        realm_id: &str,
        organization_id: &DidCoreId,
    ) -> ServiceResult<()> {
        self.records
            .link_realm_organization(realm_id, organization_id)
            .await?;
        self.realm_organizations
            .lock()
            .entry(realm_id.to_owned())
            .or_default()
            .insert(organization_id.clone());
        self.organization_realms
            .lock()
            .entry(organization_id.clone())
            .or_default()
            .insert(realm_id.to_owned());
        Ok(())
    }

    pub async fn realm_organization_links(
        &self,
    ) -> ServiceResult<Vec<(String, BTreeSet<DidCoreId>)>> {
        self.records.realm_organization_links().await
    }

    pub fn new(
        audit_log: Arc<dyn AuditLogPort>,
        moderation: Arc<dyn ModerationPort>,
        records: Arc<dyn GovernanceRecordsPort>,
        runtime_settings: Arc<dyn RuntimeSettingsPort>,
    ) -> Self {
        Self {
            audit_log,
            moderation,
            records,
            organizations: Arc::new(Mutex::new(BTreeMap::new())),
            realm_organizations: Arc::new(Mutex::new(BTreeMap::new())),
            organization_realms: Arc::new(Mutex::new(BTreeMap::new())),
            retention_tombstones: Arc::new(Mutex::new(BTreeMap::new())),
            runtime_settings,
        }
    }

    pub async fn runtime_setting_overrides(&self) -> ServiceResult<Vec<(String, Value)>> {
        self.runtime_settings.load_overrides().await
    }

    pub async fn store_runtime_setting(
        &self,
        key: &str,
        value: &Value,
        updated_by: &str,
    ) -> ServiceResult<()> {
        self.runtime_settings
            .store_override(key, value, updated_by)
            .await
    }

    pub fn replace_organization_projection(
        &self,
        organizations: impl IntoIterator<Item = OrganizationRecord>,
        links: impl IntoIterator<Item = (String, BTreeSet<DidCoreId>)>,
    ) {
        *self.organizations.lock() = organizations
            .into_iter()
            .map(|record| (record.organization_id.clone(), record))
            .collect();
        let realm_organizations: BTreeMap<_, _> = links.into_iter().collect();
        let mut organization_realms = BTreeMap::<DidCoreId, BTreeSet<String>>::new();
        for (realm_id, organization_ids) in &realm_organizations {
            for organization_id in organization_ids {
                organization_realms
                    .entry(organization_id.clone())
                    .or_default()
                    .insert(realm_id.clone());
            }
        }
        *self.realm_organizations.lock() = realm_organizations;
        *self.organization_realms.lock() = organization_realms;
    }

    pub fn cached_organization(&self, organization_id: &str) -> Option<OrganizationRecord> {
        self.organizations.lock().get(organization_id).cloned()
    }

    pub fn cached_organizations(&self) -> Vec<OrganizationRecord> {
        self.organizations.lock().values().cloned().collect()
    }

    pub fn cached_organization_realms(&self, organization_id: &DidCoreId) -> Vec<String> {
        self.organization_realms
            .lock()
            .get(organization_id)
            .map(|realms| realms.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn cached_realm_organizations(&self, realm_id: &str) -> Vec<DidCoreId> {
        self.realm_organizations
            .lock()
            .get(realm_id)
            .map(|organizations| organizations.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn replace_retention_tombstones(
        &self,
        tombstones: impl IntoIterator<Item = RetentionTombstoneRecord>,
    ) {
        *self.retention_tombstones.lock() = tombstones
            .into_iter()
            .map(|record| (record.event_id.clone(), record))
            .collect();
    }

    pub fn cached_retention_tombstone(&self, event_id: &str) -> Option<RetentionTombstoneRecord> {
        self.retention_tombstones.lock().get(event_id).cloned()
    }

    pub async fn append_audit_entry(&self, command: AppendAuditEntryCommand) -> ServiceResult<()> {
        self.audit_log.append(command.entry).await
    }

    pub async fn audit_entries_for_actor(&self, actor_id: &str) -> ServiceResult<Vec<Value>> {
        self.audit_log.entries_for_actor(actor_id).await
    }

    pub async fn audit_entries(&self) -> ServiceResult<Vec<Value>> {
        self.audit_log.entries().await
    }

    /// The moderation queue View for `actor` from one durable cut.
    pub async fn moderation_queue_for_actor(
        &self,
        actor: &arkret_wire::ActorId,
        realm_id: Option<&arkret_wire::RealmId>,
    ) -> ServiceResult<
        Vec<arkret_models_collaboration::governance::moderation_queue::ModerationQueueItem>,
    > {
        self.moderation.queue_view_for_actor(actor, realm_id).await
    }
    pub async fn moderation_management_view_for_actor(
        &self,
        actor: &arkret_wire::ActorId,
        realm_id: Option<&arkret_wire::RealmId>,
    ) -> ServiceResult<coland_storage::ModerationManagementView> {
        self.moderation
            .management_view_for_actor(actor, realm_id)
            .await
    }
    pub async fn moderation_report_count(&self) -> ServiceResult<u64> {
        self.moderation.report_count().await
    }
    pub async fn retention_policy(
        &self,
        realm_id: &str,
    ) -> ServiceResult<Option<RetentionPolicyRecord>> {
        self.records.retention_policy(realm_id).await
    }

    pub async fn policy_document(
        &self,
        policy_id: &str,
    ) -> ServiceResult<Option<PolicyDocumentRecord>> {
        self.records.policy_document(policy_id).await
    }

    pub async fn store_policy_document(&self, record: PolicyDocumentRecord) -> ServiceResult<()> {
        self.records.store_policy_document(record).await
    }

    pub async fn delete_policy_document(&self, policy_id: &str) -> ServiceResult<bool> {
        self.records.delete_policy_document(policy_id).await
    }

    pub async fn policy_documents_for_owner(
        &self,
        owner: &str,
    ) -> ServiceResult<Vec<PolicyDocumentRecord>> {
        self.records.policy_documents_for_owner(owner).await
    }

    pub async fn policy_documents(&self) -> ServiceResult<Vec<PolicyDocumentRecord>> {
        self.records.policy_documents().await
    }

    pub async fn store_retention_policy(
        &self,
        record: &RetentionPolicyRecord,
    ) -> ServiceResult<()> {
        self.records.store_retention_policy(record).await
    }

    pub async fn retention_tombstone(
        &self,
        event_id: &str,
    ) -> ServiceResult<Option<RetentionTombstoneRecord>> {
        self.records.retention_tombstone(event_id).await
    }

    pub async fn store_retention_tombstone(
        &self,
        record: &RetentionTombstoneRecord,
    ) -> ServiceResult<()> {
        self.records.store_retention_tombstone(record).await?;
        self.retention_tombstones
            .lock()
            .insert(record.event_id.clone(), record.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    #[derive(Default)]
    struct RecordingAuditLog(Mutex<Vec<Value>>);
    struct NoModeration;

    struct NoRuntimeSettings;

    #[async_trait]
    impl RuntimeSettingsPort for NoRuntimeSettings {
        async fn load_overrides(&self) -> ServiceResult<Vec<(String, Value)>> {
            Ok(Vec::new())
        }

        async fn store_override(
            &self,
            _key: &str,
            _value: &Value,
            _updated_by: &str,
        ) -> ServiceResult<()> {
            Ok(())
        }
    }
    struct NoGovernanceRecords;

    #[async_trait]
    impl GovernanceRecordsPort for NoGovernanceRecords {
        async fn organization(
            &self,
            _organization_id: &str,
        ) -> ServiceResult<Option<OrganizationRecord>> {
            Ok(None)
        }
        async fn store_organization(&self, _record: &OrganizationRecord) -> ServiceResult<()> {
            Ok(())
        }
        async fn organizations(&self) -> ServiceResult<Vec<OrganizationRecord>> {
            Ok(Vec::new())
        }
        async fn link_realm_organization(
            &self,
            _realm_id: &str,
            _organization_id: &DidCoreId,
        ) -> ServiceResult<()> {
            Ok(())
        }
        async fn realm_organization_links(
            &self,
        ) -> ServiceResult<Vec<(String, BTreeSet<DidCoreId>)>> {
            Ok(Vec::new())
        }
        async fn policy_document(
            &self,
            _policy_id: &str,
        ) -> ServiceResult<Option<PolicyDocumentRecord>> {
            Ok(None)
        }
        async fn store_policy_document(&self, _record: PolicyDocumentRecord) -> ServiceResult<()> {
            Ok(())
        }
        async fn delete_policy_document(&self, _policy_id: &str) -> ServiceResult<bool> {
            Ok(false)
        }
        async fn policy_documents_for_owner(
            &self,
            _owner: &str,
        ) -> ServiceResult<Vec<PolicyDocumentRecord>> {
            Ok(Vec::new())
        }
        async fn policy_documents(&self) -> ServiceResult<Vec<PolicyDocumentRecord>> {
            Ok(Vec::new())
        }
        async fn retention_policy(
            &self,
            _realm_id: &str,
        ) -> ServiceResult<Option<RetentionPolicyRecord>> {
            Ok(None)
        }
        async fn store_retention_policy(
            &self,
            _record: &RetentionPolicyRecord,
        ) -> ServiceResult<()> {
            Ok(())
        }
        async fn retention_tombstone(
            &self,
            _event_id: &str,
        ) -> ServiceResult<Option<RetentionTombstoneRecord>> {
            Ok(None)
        }
        async fn retention_tombstones(&self) -> ServiceResult<Vec<RetentionTombstoneRecord>> {
            Ok(Vec::new())
        }
        async fn store_retention_tombstone(
            &self,
            _record: &RetentionTombstoneRecord,
        ) -> ServiceResult<()> {
            Ok(())
        }
    }

    #[async_trait]
    impl ModerationPort for NoModeration {
        async fn queue_view_for_actor(
            &self,
            _actor: &arkret_wire::ActorId,
            _realm_id: Option<&arkret_wire::RealmId>,
        ) -> ServiceResult<
            Vec<arkret_models_collaboration::governance::moderation_queue::ModerationQueueItem>,
        > {
            Ok(Vec::new())
        }
        async fn management_view_for_actor(
            &self,
            _actor: &arkret_wire::ActorId,
            _realm_id: Option<&arkret_wire::RealmId>,
        ) -> ServiceResult<coland_storage::ModerationManagementView> {
            Ok(coland_storage::ModerationManagementView::default())
        }
        async fn report_count(&self) -> ServiceResult<u64> {
            Ok(0)
        }
    }

    #[async_trait]
    impl AuditLogPort for RecordingAuditLog {
        async fn append(&self, entry: Value) -> ServiceResult<()> {
            self.0.lock().expect("audit lock").push(entry);
            Ok(())
        }

        async fn entries(&self) -> ServiceResult<Vec<Value>> {
            Ok(self.0.lock().expect("audit lock").clone())
        }

        async fn entries_for_actor(&self, _actor_id: &str) -> ServiceResult<Vec<Value>> {
            Ok(self.0.lock().expect("audit lock").clone())
        }
    }

    #[tokio::test]
    async fn audit_append_uses_only_the_audit_port() {
        let port = Arc::new(RecordingAuditLog::default());
        let service = GovernanceService::new(
            port.clone(),
            Arc::new(NoModeration),
            Arc::new(NoGovernanceRecords),
            Arc::new(NoRuntimeSettings),
        );
        service
            .append_audit_entry(AppendAuditEntryCommand {
                entry: serde_json::json!({"audit_id": "ak:audit:test"}),
            })
            .await
            .expect("append audit entry");
        assert_eq!(port.0.lock().expect("audit lock").len(), 1);
        assert_eq!(
            service
                .audit_entries()
                .await
                .expect("list audit entries")
                .len(),
            1
        );
    }
}
