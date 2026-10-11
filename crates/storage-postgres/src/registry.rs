//! PostgreSQL-backed implementation of [`PersistenceStore`].

use crate::*;

/// PostgreSQL-backed persistence store for durable projections with shipped Pg
/// tables.
///
/// Every registry accessor is backed by a durable Pg table, including the
/// realm meta, message, device key, one-time key and member-identity planes;
/// nothing delegates to a process-local memory store, so all planes survive
/// restart and are shared across replicas.
pub struct PgPersistenceStore {
    authority_commits: PgAuthorityCommitStore,
    account_device_signer_evidence: PgAccountDeviceSignerEvidenceArchive,
    read_cursors: PgReadCursorStore,
    actor_private_events: PgActorPrivateEventStore,
    event_commits: PgEventCommitUnitOfWork,
    agent_membership_cascades: PgAgentMembershipCascadeStore,
    agent_draft_pending_intents: PgAgentDraftPendingIntentStore,
    accounts: PgAccountStore,
    account_localparts: PgAccountLocalpartStore,
    account_lifecycle: PgAccountLifecycleStore,
    account_status_replicas: PgAccountStatusReplicaStore,
    sessions: PgSessionStore,
    account_data: PgAccountDataStore,
    contacts: PgContactStore,
    contact_verified_mirrors: PgContactVerifiedMirrorStore,
    invite_receive_policies: PgInviteReceivePolicyStore,
    invite_locators: PgInviteLocatorStore,
    invite_new_source_ledger: PgInviteNewSourceLedgerStore,
    consent_request_quarantine: PgConsentRequestQuarantineStore,
    consent_current: PgConsentCurrentStore,
    mimi_consent_correlations: PgMimiConsentCorrelationStore,
    realm_meta: PgRealmMetaStore,
    messages: PgMessageStore,
    blobs: PgBlobStore,
    devices: PgDeviceInventoryStore,
    device_revocations: PgDeviceRevocationStore,
    federation_outbox: PgFederationOutboxStore,
    handle_releases: PgHandleReleaseStore,
    retention_policies: PgRetentionPolicyStore,
    retention_tombstones: PgRetentionTombstoneStore,
    organizations: PgOrganizationStore,
    organization_registrations: PgOrganizationRegistrationStore,
    realm_organizations: PgRealmOrganizationStore,
    realm_organization_statements: PgRealmOrganizationStatementStore,
    audit: PgAuditStore,
    push_devices: PgPushDeviceStore,
    push_registration_handoffs: PgPushRegistrationHandoffStore,
    events: PgEventStore,
    federation_operations: PgFederationOperationsStore,
    moderation: PgModerationStore,
    signal_relay: PgSignalRelayStore,
    webvh: PgWebvhStore,
    service_identity: PgServiceIdentityStore,
    principal_resolutions: PgPrincipalResolutionStore,
    service_routes: PgServiceRouteStore,
    circle_projections: PgCircleProjectionStore,
    key_backups: PgKeyBackupStore,
    policy_documents: PgPolicyDocumentStore,
    recovery_policies: PgRecoveryPolicyStore,
    actor_profiles: crate::actor_profiles::PgActorProfileStore,
    recovery_sessions: PgRecoverySessionStore,
    security_transactions: PgSecurityTransactionStore,
    space_container_projections: PgSpaceContainerProjectionStore,
    strand_projections: PgStrandProjectionStore,
    object_current_snapshot: crate::object_projection_reads::PgObjectCurrentSnapshotStore,
    morph_projections: PgMorphProjectionStore,
    relation_current_results: PgRelationCurrentResultStore,
    capability_grant_current_results: PgCapabilityGrantCurrentResultStore,
    invite_current_results: crate::invite_current_results::PgInviteCurrentResultStore,
    publication_evidence: PgPublicationEvidenceStore,
    projection_events: PgProjectionEventStore,
    applets: PgAppletStore,
    device_messages: PgDeviceMessageStore,
    device_keys: PgDeviceKeyStore,
    one_time_keys: PgOneTimeKeyStore,
    member_identity: PgMemberIdentityStore,
    mls_key_packages: PgMlsKeyPackageStore,
    mls_groups: crate::mls_group_current_results::PgMlsGroupCurrentStore,
    agent_participation: PgAgentParticipationStore,
    agents: PgAgentStore,
    sidecars: PgSidecarStore,
    notifications: PgNotificationStore,
    sync_cursors: PgSyncCursorStore,
    idempotency_keys: PgIdempotencyStore,
    websocket_auth: PgWebsocketAuthStore,
    /// The leased test database this store reads and writes, when a fixture
    /// built it. Holding the lease here ties it to the store's lifetime, so a
    /// fixture that keeps the store keeps its database, and a restart fixture
    /// that rebuilds `AppState` over the same store keeps the same rows.
    #[cfg(any(test, feature = "test-support"))]
    lease: Option<std::sync::Arc<crate::test_database::TestDatabase>>,
}

impl PgPersistenceStore {
    pub fn new(pool: PgPool) -> Self {
        Self {
            authority_commits: PgAuthorityCommitStore { pool: pool.clone() },
            account_device_signer_evidence: PgAccountDeviceSignerEvidenceArchive::new(pool.clone()),
            read_cursors: PgReadCursorStore::new(pool.clone()),
            actor_private_events: PgActorPrivateEventStore::new(pool.clone()),
            event_commits: PgEventCommitUnitOfWork::new(pool.clone()),
            agent_membership_cascades: PgAgentMembershipCascadeStore { pool: pool.clone() },
            agent_draft_pending_intents: PgAgentDraftPendingIntentStore { pool: pool.clone() },
            accounts: PgAccountStore { pool: pool.clone() },
            account_localparts: PgAccountLocalpartStore { pool: pool.clone() },
            account_lifecycle: PgAccountLifecycleStore { pool: pool.clone() },
            account_status_replicas: PgAccountStatusReplicaStore { pool: pool.clone() },
            sessions: PgSessionStore { pool: pool.clone() },
            account_data: PgAccountDataStore { pool: pool.clone() },
            contacts: PgContactStore { pool: pool.clone() },
            contact_verified_mirrors: PgContactVerifiedMirrorStore { pool: pool.clone() },
            invite_receive_policies: PgInviteReceivePolicyStore { pool: pool.clone() },
            invite_locators: PgInviteLocatorStore { pool: pool.clone() },
            invite_new_source_ledger: PgInviteNewSourceLedgerStore { pool: pool.clone() },
            consent_request_quarantine: PgConsentRequestQuarantineStore { pool: pool.clone() },
            consent_current: PgConsentCurrentStore { pool: pool.clone() },
            mimi_consent_correlations: PgMimiConsentCorrelationStore { pool: pool.clone() },
            realm_meta: PgRealmMetaStore { pool: pool.clone() },
            messages: PgMessageStore { pool: pool.clone() },
            blobs: PgBlobStore { pool: pool.clone() },
            devices: PgDeviceInventoryStore { pool: pool.clone() },
            device_revocations: PgDeviceRevocationStore { pool: pool.clone() },
            federation_outbox: PgFederationOutboxStore { pool: pool.clone() },
            handle_releases: PgHandleReleaseStore { pool: pool.clone() },
            retention_policies: PgRetentionPolicyStore { pool: pool.clone() },
            retention_tombstones: PgRetentionTombstoneStore { pool: pool.clone() },
            organizations: PgOrganizationStore { pool: pool.clone() },
            organization_registrations: PgOrganizationRegistrationStore::new(pool.clone()),
            realm_organizations: PgRealmOrganizationStore { pool: pool.clone() },
            realm_organization_statements: PgRealmOrganizationStatementStore { pool: pool.clone() },
            audit: PgAuditStore { pool: pool.clone() },
            push_devices: PgPushDeviceStore { pool: pool.clone() },
            push_registration_handoffs: PgPushRegistrationHandoffStore { pool: pool.clone() },
            events: PgEventStore { pool: pool.clone() },
            federation_operations: PgFederationOperationsStore { pool: pool.clone() },
            moderation: PgModerationStore { pool: pool.clone() },
            signal_relay: PgSignalRelayStore { pool: pool.clone() },
            webvh: PgWebvhStore { pool: pool.clone() },
            service_identity: PgServiceIdentityStore { pool: pool.clone() },
            principal_resolutions: PgPrincipalResolutionStore { pool: pool.clone() },
            service_routes: PgServiceRouteStore { pool: pool.clone() },
            circle_projections: PgCircleProjectionStore { pool: pool.clone() },
            key_backups: PgKeyBackupStore { pool: pool.clone() },
            policy_documents: PgPolicyDocumentStore { pool: pool.clone() },
            recovery_policies: PgRecoveryPolicyStore { pool: pool.clone() },
            actor_profiles: crate::actor_profiles::PgActorProfileStore { pool: pool.clone() },
            recovery_sessions: PgRecoverySessionStore { pool: pool.clone() },
            security_transactions: PgSecurityTransactionStore { pool: pool.clone() },
            space_container_projections: PgSpaceContainerProjectionStore { pool: pool.clone() },
            strand_projections: PgStrandProjectionStore { pool: pool.clone() },
            object_current_snapshot: crate::object_projection_reads::PgObjectCurrentSnapshotStore {
                pool: pool.clone(),
            },
            morph_projections: PgMorphProjectionStore { pool: pool.clone() },
            relation_current_results: PgRelationCurrentResultStore { pool: pool.clone() },
            capability_grant_current_results: PgCapabilityGrantCurrentResultStore {
                pool: pool.clone(),
            },
            invite_current_results: crate::invite_current_results::PgInviteCurrentResultStore {
                pool: pool.clone(),
            },
            publication_evidence: PgPublicationEvidenceStore { pool: pool.clone() },
            projection_events: PgProjectionEventStore { pool: pool.clone() },
            applets: PgAppletStore { pool: pool.clone() },
            device_messages: PgDeviceMessageStore { pool: pool.clone() },
            device_keys: PgDeviceKeyStore { pool: pool.clone() },
            one_time_keys: PgOneTimeKeyStore { pool: pool.clone() },
            member_identity: PgMemberIdentityStore { pool: pool.clone() },
            mls_key_packages: PgMlsKeyPackageStore { pool: pool.clone() },
            mls_groups: crate::mls_group_current_results::PgMlsGroupCurrentStore {
                pool: pool.clone(),
            },
            agent_participation: PgAgentParticipationStore { pool: pool.clone() },
            agents: PgAgentStore { pool: pool.clone() },
            sidecars: PgSidecarStore { pool: pool.clone() },
            sync_cursors: PgSyncCursorStore { pool: pool.clone() },
            idempotency_keys: PgIdempotencyStore { pool: pool.clone() },
            websocket_auth: PgWebsocketAuthStore { pool: pool.clone() },
            notifications: PgNotificationStore { pool },
            #[cfg(any(test, feature = "test-support"))]
            lease: None,
        }
    }

    /// Build a store over a leased test database and take ownership of the
    /// lease, so the slot is returned when the last holder of this store drops.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn leased(database: std::sync::Arc<crate::test_database::TestDatabase>) -> Self {
        let mut store = Self::new(database.pool());
        store.lease = Some(database);
        store
    }
}

#[async_trait::async_trait]
impl EventCommitUnitOfWork for PgPersistenceStore {
    async fn commit_event(
        &self,
        request: EventCommitRequest,
    ) -> PersistenceResult<EventCommitOutcome> {
        self.event_commits.commit_event(request).await
    }

    async fn commit_event_batch(
        &self,
        request: coland_storage::EventBatchCommitRequest,
    ) -> PersistenceResult<EventCommitOutcome> {
        self.event_commits.commit_event_batch(request).await
    }
}

impl IdentityStoreRegistry for PgPersistenceStore {
    fn accounts(&self) -> &dyn AccountStore {
        &self.accounts
    }

    fn account_localparts(&self) -> &dyn AccountLocalpartStore {
        &self.account_localparts
    }

    fn account_lifecycle(&self) -> &dyn AccountLifecycleStore {
        &self.account_lifecycle
    }

    fn sessions(&self) -> &dyn SessionStore {
        &self.sessions
    }

    fn account_data(&self) -> &dyn AccountDataStore {
        &self.account_data
    }

    fn contacts(&self) -> &dyn ContactStore {
        &self.contacts
    }

    fn contact_verified_mirrors(&self) -> &dyn ContactVerifiedMirrorStore {
        &self.contact_verified_mirrors
    }

    fn invite_receive_policies(&self) -> &dyn InviteReceivePolicyStore {
        &self.invite_receive_policies
    }

    fn invite_locators(&self) -> &dyn InviteLocatorStore {
        &self.invite_locators
    }

    fn invite_new_source_ledger(&self) -> &dyn InviteNewSourceLedgerStore {
        &self.invite_new_source_ledger
    }

    fn consent_request_quarantine(&self) -> &dyn ConsentRequestQuarantineStore {
        &self.consent_request_quarantine
    }

    fn consent_current(&self) -> &dyn ConsentCurrentStore {
        &self.consent_current
    }

    fn mimi_consent_correlations(&self) -> &dyn MimiConsentCorrelationStore {
        &self.mimi_consent_correlations
    }

    fn realm_meta(&self) -> &dyn RealmMetaStore {
        &self.realm_meta
    }

    fn messages(&self) -> &dyn MessageStore {
        &self.messages
    }

    fn member_identity(&self) -> &dyn MemberIdentityStore {
        &self.member_identity
    }

    fn blobs(&self) -> &dyn BlobStore {
        &self.blobs
    }

    fn devices(&self) -> &dyn DeviceInventoryStore {
        &self.devices
    }

    fn device_revocations(&self) -> &dyn DeviceRevocationStore {
        &self.device_revocations
    }
}

impl FederationGovernanceStoreRegistry for PgPersistenceStore {
    fn federation_outbox(&self) -> &dyn FederationOutboxStore {
        &self.federation_outbox
    }

    fn handle_releases(&self) -> &dyn HandleReleaseStore {
        &self.handle_releases
    }

    fn retention_policies(&self) -> &dyn RetentionPolicyStore {
        &self.retention_policies
    }

    fn retention_tombstones(&self) -> &dyn RetentionTombstoneStore {
        &self.retention_tombstones
    }

    fn organizations(&self) -> &dyn OrganizationStore {
        &self.organizations
    }

    fn organization_registrations(&self) -> &dyn OrganizationRegistrationStore {
        &self.organization_registrations
    }

    fn realm_organizations(&self) -> &dyn RealmOrganizationStore {
        &self.realm_organizations
    }

    fn realm_organization_statements(&self) -> &dyn RealmOrganizationStatementStore {
        &self.realm_organization_statements
    }

    fn audit(&self) -> &dyn AuditStore {
        &self.audit
    }
}

impl DeliveryPolicyStoreRegistry for PgPersistenceStore {
    fn moderation(&self) -> &dyn ModerationStore {
        &self.moderation
    }

    fn federation_operations(&self) -> &dyn FederationOperationsStore {
        &self.federation_operations
    }

    fn push_devices(&self) -> &dyn PushDeviceStore {
        &self.push_devices
    }

    fn push_registration_handoffs(&self) -> &dyn PushRegistrationHandoffStore {
        &self.push_registration_handoffs
    }

    fn signal_relay(&self) -> &dyn SignalRelayStore {
        &self.signal_relay
    }

    fn policy_documents(&self) -> &dyn PolicyDocumentStore {
        &self.policy_documents
    }

    fn recovery_policies(&self) -> &dyn RecoveryPolicyStore {
        &self.recovery_policies
    }

    fn actor_profiles(&self) -> &dyn coland_storage::ActorProfileStore {
        &self.actor_profiles
    }

    fn recovery_sessions(&self) -> &dyn RecoverySessionStore {
        &self.recovery_sessions
    }

    fn security_transactions(&self) -> &dyn SecurityTransactionStore {
        &self.security_transactions
    }

    fn webvh(&self) -> &dyn WebvhStore {
        &self.webvh
    }

    fn service_identity(&self) -> &dyn ServiceIdentityStore {
        &self.service_identity
    }
}

impl EventProjectionStoreRegistry for PgPersistenceStore {
    fn events(&self) -> &dyn EventStore {
        &self.events
    }

    fn projection_events(&self) -> &dyn ProjectionEventStore {
        &self.projection_events
    }

    fn applets(&self) -> &dyn AppletStore {
        &self.applets
    }

    fn device_messages(&self) -> &dyn DeviceMessageStore {
        &self.device_messages
    }

    fn device_keys(&self) -> &dyn DeviceKeyStore {
        &self.device_keys
    }

    fn one_time_keys(&self) -> &dyn OneTimeKeyStore {
        &self.one_time_keys
    }

    fn key_backups(&self) -> &dyn KeyBackupStore {
        &self.key_backups
    }

    fn space_container_projections(&self) -> &dyn SpaceContainerProjectionStore {
        &self.space_container_projections
    }

    fn circle_projections(&self) -> &dyn CircleProjectionStore {
        &self.circle_projections
    }

    fn strand_projections(&self) -> &dyn StrandProjectionStore {
        &self.strand_projections
    }

    fn object_current_snapshot(&self) -> &dyn ObjectCurrentSnapshotStore {
        &self.object_current_snapshot
    }

    fn morph_projections(&self) -> &dyn MorphProjectionStore {
        &self.morph_projections
    }

    fn relation_current_results(&self) -> &dyn RelationCurrentResultStore {
        &self.relation_current_results
    }

    fn capability_grant_current_results(&self) -> &dyn CapabilityGrantCurrentResultStore {
        &self.capability_grant_current_results
    }

    fn invite_current_results(&self) -> &dyn coland_storage::InviteCurrentResultStore {
        &self.invite_current_results
    }

    fn publication_evidence(&self) -> &dyn PublicationEvidenceStore {
        &self.publication_evidence
    }
}

impl MlsAgentStoreRegistry for PgPersistenceStore {
    fn mls_key_packages(&self) -> &dyn MlsKeyPackageStore {
        &self.mls_key_packages
    }

    fn mls_groups(&self) -> &dyn coland_storage::MlsGroupCurrentStore {
        &self.mls_groups
    }

    fn agent_participation(&self) -> &dyn AgentParticipationStore {
        &self.agent_participation
    }

    fn agents(&self) -> &dyn AgentStore {
        &self.agents
    }

    fn agent_membership_cascades(&self) -> &dyn AgentMembershipCascadeStore {
        &self.agent_membership_cascades
    }

    fn agent_draft_pending_intents(&self) -> &dyn AgentDraftPendingIntentStore {
        &self.agent_draft_pending_intents
    }

    fn sidecars(&self) -> &dyn SidecarStore {
        &self.sidecars
    }

    fn notifications(&self) -> &dyn NotificationStore {
        &self.notifications
    }
}

impl SyncStoreRegistry for PgPersistenceStore {
    fn sync_cursors(&self) -> &dyn SyncCursorStore {
        &self.sync_cursors
    }

    fn idempotency_keys(&self) -> &dyn IdempotencyStore {
        &self.idempotency_keys
    }

    fn websocket_auth(&self) -> &dyn WebsocketAuthStore {
        &self.websocket_auth
    }

    fn account_status_replicas(&self) -> &dyn AccountStatusReplicaStore {
        &self.account_status_replicas
    }
}

impl ResolutionStoreRegistry for PgPersistenceStore {
    fn principal_resolutions(&self) -> &dyn PrincipalResolutionStore {
        &self.principal_resolutions
    }

    fn service_routes(&self) -> &dyn ServiceRouteStore {
        &self.service_routes
    }
}

impl PersistenceStore for PgPersistenceStore {
    fn authority_commits(&self) -> &dyn AuthorityCommitStore {
        &self.authority_commits
    }

    fn account_device_signer_evidence(&self) -> &dyn AccountDeviceSignerEvidenceStore {
        &self.account_device_signer_evidence
    }

    fn read_cursors(&self) -> &dyn ReadCursorStore {
        &self.read_cursors
    }

    fn actor_private_events(&self) -> &dyn ActorPrivateEventStore {
        &self.actor_private_events
    }
}
