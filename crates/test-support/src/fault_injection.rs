//! Durable-boundary fault injection for fixtures.
//!
//! A crash-consistency fixture needs to interrupt a durable commit at an exact
//! boundary and then prove the retry converges. Coland has one storage
//! implementation, so the interruption is a decorator around the store rather
//! than a second adapter that grows its own injection points.
//!
//! Every point is at a method's entry or exit, which is what makes the
//! decorator equivalent to the adapter-internal checks it replaces. Against a
//! real database the two timings also mean something sharper than they did in
//! memory: `Before` is a crash with the transaction unopened, so nothing may be
//! visible, and `After` is a crash once it has committed, so the retry must be
//! an idempotent replay.

use std::sync::Arc;

use async_trait::async_trait;
use coland_storage::{
    AgentPairingCommitIntent, AgentPrincipalRecord, AgentRuntimeActivation,
    AgentRuntimeApprovalWrite, AgentRuntimeEnqueueOutcome, AgentStore, EnqueueAgentRuntimeMessage,
    EventBatchCommitRequest, EventCommitOutcome, EventCommitRequest, EventCommitUnitOfWork,
    PersistenceError, PersistenceResult, PersistenceStore, ServiceRegistrationCommitOutcome,
    WebvhDocumentRecord, WebvhLogCommitOutcome, WebvhLogRecord, WebvhStore,
};
use parking_lot::Mutex;

/// The durable boundaries a fixture may interrupt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultPoint {
    EventCommit,
    WebvhLogCommit,
    AgentPut,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultTiming {
    /// Before the inner call: the commit never reached the database.
    Before,
    /// After the inner call returned: the commit landed and the caller died.
    After,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FaultPlan {
    pub point: FaultPoint,
    pub timing: FaultTiming,
    pub occurrence: usize,
}

impl FaultPlan {
    #[must_use]
    pub fn new(point: FaultPoint, timing: FaultTiming, occurrence: usize) -> Self {
        assert!(occurrence > 0, "fault occurrence must be positive");
        Self {
            point,
            timing,
            occurrence,
        }
    }
}

#[derive(Debug)]
struct ArmedFault {
    plan: FaultPlan,
    observed: usize,
}

#[derive(Debug, Default)]
pub struct FaultInjector {
    armed: Mutex<Option<ArmedFault>>,
}

impl FaultInjector {
    pub fn arm(&self, plan: FaultPlan) {
        *self.armed.lock() = Some(ArmedFault { plan, observed: 0 });
    }

    pub fn clear(&self) {
        self.armed.lock().take();
    }

    fn check(&self, point: FaultPoint, timing: FaultTiming) -> PersistenceResult<()> {
        let mut armed = self.armed.lock();
        let Some(fault) = armed.as_mut() else {
            return Ok(());
        };
        if fault.plan.point != point || fault.plan.timing != timing {
            return Ok(());
        }
        fault.observed += 1;
        if fault.observed != fault.plan.occurrence {
            return Ok(());
        }
        armed.take();
        Err(PersistenceError::Database(format!(
            "injected {timing:?} failure at {point:?}"
        )))
    }
}

/// A `PersistenceStore` that can fail at named durable boundaries.
pub struct FaultInjectingStore {
    inner: Arc<dyn PersistenceStore>,
    injector: Arc<FaultInjector>,
    webvh: FaultWebvhStore,
    agents: FaultAgentStore,
}

impl FaultInjectingStore {
    #[must_use]
    pub fn new(inner: Arc<dyn PersistenceStore>) -> Self {
        let injector = Arc::new(FaultInjector::default());
        Self {
            webvh: FaultWebvhStore {
                inner: inner.clone(),
                injector: injector.clone(),
            },
            agents: FaultAgentStore {
                inner: inner.clone(),
                injector: injector.clone(),
            },
            inner,
            injector,
        }
    }

    #[must_use]
    pub fn fault_injector(&self) -> Arc<FaultInjector> {
        self.injector.clone()
    }
}

impl PersistenceStore for FaultInjectingStore {
    fn authority_commits(&self) -> &dyn coland_storage::AuthorityCommitStore {
        self.inner.authority_commits()
    }

    fn account_device_signer_evidence(
        &self,
    ) -> &dyn coland_storage::AccountDeviceSignerEvidenceStore {
        self.inner.account_device_signer_evidence()
    }

    fn read_cursors(&self) -> &dyn coland_storage::ReadCursorStore {
        self.inner.read_cursors()
    }

    fn actor_private_events(&self) -> &dyn coland_storage::ActorPrivateEventStore {
        self.inner.actor_private_events()
    }
}

#[async_trait]
impl EventCommitUnitOfWork for FaultInjectingStore {
    async fn commit_event(
        &self,
        request: EventCommitRequest,
    ) -> PersistenceResult<EventCommitOutcome> {
        self.injector
            .check(FaultPoint::EventCommit, FaultTiming::Before)?;
        let outcome = self.inner.commit_event(request).await?;
        self.injector
            .check(FaultPoint::EventCommit, FaultTiming::After)?;
        Ok(outcome)
    }

    async fn commit_event_batch(
        &self,
        request: EventBatchCommitRequest,
    ) -> PersistenceResult<EventCommitOutcome> {
        self.injector
            .check(FaultPoint::EventCommit, FaultTiming::Before)?;
        let outcome = self.inner.commit_event_batch(request).await?;
        self.injector
            .check(FaultPoint::EventCommit, FaultTiming::After)?;
        Ok(outcome)
    }
}

struct FaultWebvhStore {
    inner: Arc<dyn PersistenceStore>,
    injector: Arc<FaultInjector>,
}

#[async_trait]
impl WebvhStore for FaultWebvhStore {
    async fn get_document(&self, did: &str) -> PersistenceResult<Option<WebvhDocumentRecord>> {
        self.inner.webvh().get_document(did).await
    }
    async fn get_embedded_webvh_document_by_local_id(
        &self,
        local_id: &str,
    ) -> PersistenceResult<Option<WebvhDocumentRecord>> {
        self.inner
            .webvh()
            .get_embedded_webvh_document_by_local_id(local_id)
            .await
    }
    async fn put_document(&self, record: WebvhDocumentRecord) -> PersistenceResult<()> {
        self.inner.webvh().put_document(record).await
    }
    async fn append_log_event(&self, event: WebvhLogRecord) -> PersistenceResult<()> {
        self.inner.webvh().append_log_event(event).await
    }
    async fn list_log_events(&self, did: &str) -> PersistenceResult<Vec<WebvhLogRecord>> {
        self.inner.webvh().list_log_events(did).await
    }
    async fn commit_log_operation(
        &self,
        expected_current_head: Option<String>,
        document: WebvhDocumentRecord,
        event: WebvhLogRecord,
        service_identity: Option<coland_storage::ServiceIdentitySuccessor>,
    ) -> PersistenceResult<WebvhLogCommitOutcome> {
        self.injector
            .check(FaultPoint::WebvhLogCommit, FaultTiming::Before)?;
        let outcome = self
            .inner
            .webvh()
            .commit_log_operation(expected_current_head, document, event, service_identity)
            .await?;
        self.injector
            .check(FaultPoint::WebvhLogCommit, FaultTiming::After)?;
        Ok(outcome)
    }
    async fn get_service_registration(
        &self,
        key: &arkret_models_identity::service_identity::ServiceRegistrationKey,
    ) -> PersistenceResult<
        Option<arkret_models_identity::service_identity::ServiceRegistrationOutcome>,
    > {
        self.inner.webvh().get_service_registration(key).await
    }
    async fn commit_service_registration(
        &self,
        key: arkret_models_identity::service_identity::ServiceRegistrationKey,
        outcome: arkret_models_identity::service_identity::ServiceRegistrationOutcome,
        document: WebvhDocumentRecord,
        event: WebvhLogRecord,
    ) -> PersistenceResult<ServiceRegistrationCommitOutcome> {
        self.inner
            .webvh()
            .commit_service_registration(key, outcome, document, event)
            .await
    }
}

struct FaultAgentStore {
    inner: Arc<dyn PersistenceStore>,
    injector: Arc<FaultInjector>,
}

#[async_trait]
impl AgentStore for FaultAgentStore {
    async fn pairing_receipt(
        &self,
        event_id: &str,
    ) -> PersistenceResult<Option<coland_storage::AgentPairingReceipt>> {
        self.inner.agents().pairing_receipt(event_id).await
    }
    async fn pending_pairings_after(
        &self,
        after_id: &str,
        limit: usize,
    ) -> PersistenceResult<Vec<AgentPrincipalRecord>> {
        self.inner
            .agents()
            .pending_pairings_after(after_id, limit)
            .await
    }

    async fn put(&self, record: AgentPrincipalRecord) -> PersistenceResult<()> {
        self.injector
            .check(FaultPoint::AgentPut, FaultTiming::Before)?;
        let outcome = self.inner.agents().put(record).await?;
        self.injector
            .check(FaultPoint::AgentPut, FaultTiming::After)?;
        Ok(outcome)
    }
    async fn get(&self, agent_id: &str) -> PersistenceResult<Option<AgentPrincipalRecord>> {
        self.inner.agents().get(agent_id).await
    }
    async fn get_by_pairing_request_id(
        &self,
        pairing_request_id: &str,
    ) -> PersistenceResult<Option<AgentPrincipalRecord>> {
        self.inner
            .agents()
            .get_by_pairing_request_id(pairing_request_id)
            .await
    }
    async fn list_for_controller(
        &self,
        controller_principal_id: &str,
    ) -> PersistenceResult<Vec<AgentPrincipalRecord>> {
        self.inner
            .agents()
            .list_for_controller(controller_principal_id)
            .await
    }
    async fn set_state(
        &self,
        agent_id: &str,
        state: arkret_models_collaboration::agent_operations::AgentLifecycleState,
        changed_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<bool> {
        self.inner
            .agents()
            .set_state(agent_id, state, changed_at)
            .await
    }
    async fn activate_runtime_if_current(
        &self,
        activation: &AgentRuntimeActivation,
    ) -> PersistenceResult<bool> {
        self.inner
            .agents()
            .activate_runtime_if_current(activation)
            .await
    }
    async fn put_pairing_commit_intent_if_compatible(
        &self,
        intent: &AgentPairingCommitIntent,
    ) -> PersistenceResult<Option<AgentPrincipalRecord>> {
        self.inner
            .agents()
            .put_pairing_commit_intent_if_compatible(intent)
            .await
    }
    async fn clear_runtime_approval_notification_if_current(
        &self,
        agent_id: &str,
        approval_request_id: &str,
    ) -> PersistenceResult<bool> {
        self.inner
            .agents()
            .clear_runtime_approval_notification_if_current(agent_id, approval_request_id)
            .await
    }
    async fn put_runtime_approval_if_compatible(
        &self,
        write: &AgentRuntimeApprovalWrite,
    ) -> PersistenceResult<Option<AgentPrincipalRecord>> {
        self.inner
            .agents()
            .put_runtime_approval_if_compatible(write)
            .await
    }
    async fn enqueue_runtime_message_if_current(
        &self,
        command: &EnqueueAgentRuntimeMessage,
    ) -> PersistenceResult<AgentRuntimeEnqueueOutcome> {
        self.inner
            .agents()
            .enqueue_runtime_message_if_current(command)
            .await
    }
}

impl coland_storage::IdentityStoreRegistry for FaultInjectingStore {
    fn accounts(&self) -> &dyn coland_storage::AccountStore {
        self.inner.accounts()
    }
    fn account_localparts(&self) -> &dyn coland_storage::AccountLocalpartStore {
        self.inner.account_localparts()
    }
    fn account_lifecycle(&self) -> &dyn coland_storage::AccountLifecycleStore {
        self.inner.account_lifecycle()
    }
    fn sessions(&self) -> &dyn coland_storage::SessionStore {
        self.inner.sessions()
    }
    fn account_data(&self) -> &dyn coland_storage::AccountDataStore {
        self.inner.account_data()
    }
    fn contacts(&self) -> &dyn coland_storage::ContactStore {
        self.inner.contacts()
    }
    fn contact_verified_mirrors(&self) -> &dyn coland_storage::ContactVerifiedMirrorStore {
        self.inner.contact_verified_mirrors()
    }
    fn invite_receive_policies(&self) -> &dyn coland_storage::InviteReceivePolicyStore {
        self.inner.invite_receive_policies()
    }
    fn invite_locators(&self) -> &dyn coland_storage::InviteLocatorStore {
        self.inner.invite_locators()
    }
    fn invite_new_source_ledger(&self) -> &dyn coland_storage::InviteNewSourceLedgerStore {
        self.inner.invite_new_source_ledger()
    }
    fn consent_request_quarantine(&self) -> &dyn coland_storage::ConsentRequestQuarantineStore {
        self.inner.consent_request_quarantine()
    }

    fn consent_current(&self) -> &dyn coland_storage::ConsentCurrentStore {
        self.inner.consent_current()
    }
    fn mimi_consent_correlations(&self) -> &dyn coland_storage::MimiConsentCorrelationStore {
        self.inner.mimi_consent_correlations()
    }
    fn realm_meta(&self) -> &dyn coland_storage::RealmMetaStore {
        self.inner.realm_meta()
    }
    fn messages(&self) -> &dyn coland_storage::MessageStore {
        self.inner.messages()
    }
    fn member_identity(&self) -> &dyn coland_storage::MemberIdentityStore {
        self.inner.member_identity()
    }
    fn blobs(&self) -> &dyn coland_storage::BlobStore {
        self.inner.blobs()
    }
    fn devices(&self) -> &dyn coland_storage::DeviceInventoryStore {
        self.inner.devices()
    }
    fn device_revocations(&self) -> &dyn coland_storage::DeviceRevocationStore {
        self.inner.device_revocations()
    }
}

impl coland_storage::FederationGovernanceStoreRegistry for FaultInjectingStore {
    fn federation_outbox(&self) -> &dyn coland_storage::FederationOutboxStore {
        self.inner.federation_outbox()
    }
    fn handle_releases(&self) -> &dyn coland_storage::HandleReleaseStore {
        self.inner.handle_releases()
    }
    fn retention_policies(&self) -> &dyn coland_storage::RetentionPolicyStore {
        self.inner.retention_policies()
    }
    fn retention_tombstones(&self) -> &dyn coland_storage::RetentionTombstoneStore {
        self.inner.retention_tombstones()
    }
    fn organizations(&self) -> &dyn coland_storage::OrganizationStore {
        self.inner.organizations()
    }
    fn organization_registrations(&self) -> &dyn coland_storage::OrganizationRegistrationStore {
        self.inner.organization_registrations()
    }
    fn realm_organizations(&self) -> &dyn coland_storage::RealmOrganizationStore {
        self.inner.realm_organizations()
    }
    fn realm_organization_statements(
        &self,
    ) -> &dyn coland_storage::RealmOrganizationStatementStore {
        self.inner.realm_organization_statements()
    }
    fn audit(&self) -> &dyn coland_storage::AuditStore {
        self.inner.audit()
    }
}

impl coland_storage::DeliveryPolicyStoreRegistry for FaultInjectingStore {
    fn moderation(&self) -> &dyn coland_storage::ModerationStore {
        self.inner.moderation()
    }
    fn federation_operations(&self) -> &dyn coland_storage::FederationOperationsStore {
        self.inner.federation_operations()
    }
    fn push_devices(&self) -> &dyn coland_storage::PushDeviceStore {
        self.inner.push_devices()
    }
    fn push_registration_handoffs(&self) -> &dyn coland_storage::PushRegistrationHandoffStore {
        self.inner.push_registration_handoffs()
    }
    fn signal_relay(&self) -> &dyn coland_storage::SignalRelayStore {
        self.inner.signal_relay()
    }
    fn policy_documents(&self) -> &dyn coland_storage::PolicyDocumentStore {
        self.inner.policy_documents()
    }
    fn recovery_policies(&self) -> &dyn coland_storage::RecoveryPolicyStore {
        self.inner.recovery_policies()
    }
    fn actor_profiles(&self) -> &dyn coland_storage::ActorProfileStore {
        self.inner.actor_profiles()
    }
    fn recovery_sessions(&self) -> &dyn coland_storage::RecoverySessionStore {
        self.inner.recovery_sessions()
    }
    fn security_transactions(&self) -> &dyn coland_storage::SecurityTransactionStore {
        self.inner.security_transactions()
    }
    fn webvh(&self) -> &dyn coland_storage::WebvhStore {
        &self.webvh
    }
    fn service_identity(&self) -> &dyn coland_storage::ServiceIdentityStore {
        self.inner.service_identity()
    }
}

impl coland_storage::EventProjectionStoreRegistry for FaultInjectingStore {
    fn events(&self) -> &dyn coland_storage::EventStore {
        self.inner.events()
    }
    fn projection_events(&self) -> &dyn coland_storage::ProjectionEventStore {
        self.inner.projection_events()
    }
    fn applets(&self) -> &dyn coland_storage::AppletStore {
        self.inner.applets()
    }
    fn device_messages(&self) -> &dyn coland_storage::DeviceMessageStore {
        self.inner.device_messages()
    }
    fn device_keys(&self) -> &dyn coland_storage::DeviceKeyStore {
        self.inner.device_keys()
    }
    fn one_time_keys(&self) -> &dyn coland_storage::OneTimeKeyStore {
        self.inner.one_time_keys()
    }
    fn key_backups(&self) -> &dyn coland_storage::KeyBackupStore {
        self.inner.key_backups()
    }
    fn space_container_projections(&self) -> &dyn coland_storage::SpaceContainerProjectionStore {
        self.inner.space_container_projections()
    }
    fn circle_projections(&self) -> &dyn coland_storage::CircleProjectionStore {
        self.inner.circle_projections()
    }
    fn strand_projections(&self) -> &dyn coland_storage::StrandProjectionStore {
        self.inner.strand_projections()
    }
    fn object_current_snapshot(&self) -> &dyn coland_storage::ObjectCurrentSnapshotStore {
        self.inner.object_current_snapshot()
    }
    fn morph_projections(&self) -> &dyn coland_storage::MorphProjectionStore {
        self.inner.morph_projections()
    }
    fn relation_current_results(&self) -> &dyn coland_storage::RelationCurrentResultStore {
        self.inner.relation_current_results()
    }
    fn capability_grant_current_results(
        &self,
    ) -> &dyn coland_storage::CapabilityGrantCurrentResultStore {
        self.inner.capability_grant_current_results()
    }

    fn invite_current_results(&self) -> &dyn coland_storage::InviteCurrentResultStore {
        self.inner.invite_current_results()
    }
    fn publication_evidence(&self) -> &dyn coland_storage::PublicationEvidenceStore {
        self.inner.publication_evidence()
    }
}

impl coland_storage::MlsAgentStoreRegistry for FaultInjectingStore {
    fn mls_key_packages(&self) -> &dyn coland_storage::MlsKeyPackageStore {
        self.inner.mls_key_packages()
    }
    fn mls_groups(&self) -> &dyn coland_storage::MlsGroupCurrentStore {
        self.inner.mls_groups()
    }
    fn agent_participation(&self) -> &dyn coland_storage::AgentParticipationStore {
        self.inner.agent_participation()
    }
    fn agents(&self) -> &dyn coland_storage::AgentStore {
        &self.agents
    }
    fn agent_membership_cascades(&self) -> &dyn coland_storage::AgentMembershipCascadeStore {
        self.inner.agent_membership_cascades()
    }
    fn agent_draft_pending_intents(&self) -> &dyn coland_storage::AgentDraftPendingIntentStore {
        self.inner.agent_draft_pending_intents()
    }
    fn sidecars(&self) -> &dyn coland_storage::SidecarStore {
        self.inner.sidecars()
    }
    fn notifications(&self) -> &dyn coland_storage::NotificationStore {
        self.inner.notifications()
    }
}

impl coland_storage::SyncStoreRegistry for FaultInjectingStore {
    fn sync_cursors(&self) -> &dyn coland_storage::SyncCursorStore {
        self.inner.sync_cursors()
    }
    fn idempotency_keys(&self) -> &dyn coland_storage::IdempotencyStore {
        self.inner.idempotency_keys()
    }
    fn websocket_auth(&self) -> &dyn coland_storage::WebsocketAuthStore {
        self.inner.websocket_auth()
    }
    fn account_status_replicas(&self) -> &dyn coland_storage::AccountStatusReplicaStore {
        self.inner.account_status_replicas()
    }
}

impl coland_storage::ResolutionStoreRegistry for FaultInjectingStore {
    fn principal_resolutions(&self) -> &dyn coland_storage::PrincipalResolutionStore {
        self.inner.principal_resolutions()
    }
    fn service_routes(&self) -> &dyn coland_storage::ServiceRouteStore {
        self.inner.service_routes()
    }
}
