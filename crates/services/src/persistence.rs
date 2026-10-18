use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use arkret_identifiers::RealmId;
use arkret_models_collaboration::governance::third_party_invite::{
    ThirdPartyInviteAcceptanceAttestationOutcome, ThirdPartyInviteAcceptanceAttestationRequestBody,
};
use coland_storage::{PersistenceResult, PersistenceStore};

use crate::delivery::{DeliveryService, ObjectStoragePort};
use crate::events::{RealmDirectoryEntry, RealmDirectoryIndex};
use crate::governance::RuntimeSettingsPort;
use crate::hydration::{
    HydrationProjectionAdapter, hydrate_realm_from_canonical_events,
    hydrate_realms_from_canonical_events,
};
use crate::identity::{
    DidDocumentState, DidLogEvent, DidResolverPort, ServiceRegistrationCommitResult,
};
use crate::jobs::RuntimeHealthPort;
use crate::persistence_delivery::build_persistence_delivery_service;
use crate::persistence_events::{PersistenceEventServices, build_persistence_event_services};
use crate::persistence_identity::{
    PersistenceIdentityServices, build_persistence_identity_services,
};
use crate::persistence_operations::{
    PersistenceOperationalServices, build_persistence_operational_services,
};
use crate::projection::ProjectionService;

/// Opaque application-owned handle used by the composition root to install a
/// concrete persistence adapter without exposing the storage registry to HTTP
/// or runtime state.
#[derive(Clone)]
pub struct PersistenceHandle {
    persistence: Arc<dyn PersistenceStore>,
}

impl PersistenceHandle {
    pub async fn applet_creation_approval_accounts(
        &self,
        candidate: &coland_storage::AppletAuthoringCandidate,
    ) -> PersistenceResult<Vec<arkret_wire::AccountId>> {
        self.persistence
            .applets()
            .creation_approval_accounts(candidate)
            .await
    }
    pub async fn managed_pcr_creation_context(
        &self,
        genesis: &arkret_wire::EventId,
    ) -> PersistenceResult<Option<arkret_models_integration::AppletManagedActorAuthoringContext>>
    {
        self.persistence
            .applets()
            .managed_pcr_creation_context(genesis)
            .await
    }
    pub async fn management_review_request(
        &self,
        caller: &arkret_wire::ActorId,
        request: &arkret_models_integration::management_review::ManagementReviewRequestBody,
        producer: Option<&coland_storage::SelfProducerCommitGuard>,
        current: &coland_storage::ManagementReviewCurrent,
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<arkret_models_integration::management_review::ManagementReviewOutcome>
    {
        self.persistence
            .agents()
            .management_review_request(caller, request, producer, current, at)
            .await
    }
    pub async fn management_review_status(
        &self,
        caller: &arkret_wire::ActorId,
        request: &arkret_models_integration::management_review::ManagementReviewLookupRequestBody,
        current: &coland_storage::ManagementReviewCurrent,
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<arkret_models_integration::management_review::ManagementReviewOutcome>
    {
        self.persistence
            .agents()
            .management_review_status(caller, request, current, at)
            .await
    }
    pub async fn management_review_event_material(
        &self,
        event: &arkret_wire::Event,
        id: &str,
        signatures: &[arkret_wire::ApprovalSignature],
    ) -> PersistenceResult<coland_storage::ManagementReviewMaterial> {
        self.persistence
            .agents()
            .management_review_event_material(event, id, signatures)
            .await
    }
    pub async fn management_review_material(
        &self,
        caller: &arkret_wire::ActorId,
        id: &str,
        new_signatures: &[arkret_wire::ApprovalSignature],
    ) -> PersistenceResult<coland_storage::ManagementReviewMaterial> {
        self.persistence
            .agents()
            .management_review_material(caller, id, new_signatures)
            .await
    }
    pub async fn management_review_decide(
        &self,
        caller: &arkret_wire::ActorId,
        request: &arkret_models_integration::management_review::ManagementReviewDecisionRequestBody,
        methods: &[coland_storage::ApprovalHistoricalMethod],
        current: &coland_storage::ManagementReviewCurrent,
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<arkret_models_integration::management_review::ManagementReviewOutcome>
    {
        self.persistence
            .agents()
            .management_review_decide(caller, request, methods, current, at)
            .await
    }
    pub async fn historical_content_holders(
        &self,
        realm_ids: &[arkret_wire::RealmId],
    ) -> PersistenceResult<Vec<arkret_wire::DidCoreId>> {
        self.persistence
            .federation_outbox()
            .historical_content_holders(realm_ids)
            .await
    }

    pub async fn historical_content_holders_for_actor(
        &self,
        actor: &arkret_wire::ActorId,
    ) -> PersistenceResult<Vec<arkret_wire::DidCoreId>> {
        self.persistence
            .federation_outbox()
            .historical_content_holders_for_actor(actor)
            .await
    }

    pub async fn erasure_receipt_deliveries(
        &self,
        receipt_id: &str,
    ) -> PersistenceResult<Vec<coland_storage::FederationOutboxRecord>> {
        self.persistence
            .federation_outbox()
            .erasure_receipt_deliveries(receipt_id)
            .await
    }

    pub async fn erasure_receipt_feedback(
        &self,
        receipt: &arkret_models_collaboration::governance::erasure::ErasureReceipt,
    ) -> PersistenceResult<
        Vec<(
            arkret_models_collaboration::governance::erasure::ErasureReceiptPackage,
            chrono::DateTime<chrono::Utc>,
        )>,
    > {
        self.persistence
            .federation_outbox()
            .erasure_receipt_feedback(receipt)
            .await
    }

    pub async fn record_idempotency_with_lookup(
        &self,
        response: &coland_storage::IdempotencyRecord,
        lookup: &coland_storage::IdempotencyRecord,
    ) -> PersistenceResult<coland_storage::IdempotencyRecord> {
        self.persistence
            .idempotency_keys()
            .record_with_lookup(response, lookup)
            .await
    }

    pub async fn applet_authority_material(
        &self,
        applet: &arkret_wire::AppletId,
        service: &arkret_wire::DidCoreId,
        station: &arkret_wire::DidCoreId,
        request: &arkret_models_collaboration::applet_installation_authority::AppletAuthorityMaterialRequestBody,
    ) -> PersistenceResult<
        arkret_models_collaboration::applet_installation_authority::AppletAuthorityMaterialOutcome,
    > {
        self.persistence
            .applets()
            .authority_material(applet, service, station, request)
            .await
    }

    /// Registered Realm links retain their durable accepted Event/Commit source.
    pub async fn accepted_realm_links(
        &self,
        realm: &arkret_wire::RealmId,
        direction: arkret_models_collaboration::governance::realm_governance::RealmLinkDirection,
        allow: Option<&[String]>,
    ) -> PersistenceResult<
        Vec<arkret_models_collaboration::governance::realm_governance::RealmLinkEntry>,
    > {
        self.persistence
            .authority_commits()
            .accepted_realm_links(realm, direction, allow)
            .await
    }

    /// Full-Actor current membership and the disclosed organization rows share a cut.
    pub async fn accepted_realm_organization_read(
        &self, realm: &arkret_wire::RealmId, caller: &arkret_wire::ActorId, at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<Option<arkret_models_collaboration::governance::realm_governance::RealmOrganizationRelationshipList>>{
        self.persistence
            .authority_commits()
            .accepted_realm_organization_read(realm, caller, at)
            .await
    }

    pub async fn accepted_realm_organization_relationships(&self, realm_id: &arkret_wire::RealmId, at: chrono::DateTime<chrono::Utc>) -> PersistenceResult<Vec<arkret_models_collaboration::governance::realm_governance::RealmOrganizationRelationshipRow>>{
        self.persistence
            .realm_organization_statements()
            .accepted_relationships(realm_id, at)
            .await
    }

    pub async fn require_organization_moderation_authority(
        &self,
        realm_id: &arkret_wire::RealmId,
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<()> {
        self.persistence
            .realm_organization_statements()
            .require_moderation_authority(realm_id, at)
            .await
    }

    pub async fn consent_historical_basis(
        &self,
        holder: &arkret_wire::AccountId,
        id: &arkret_wire::ConsentId,
        revision: &arkret_wire::CurrentRevision,
    ) -> PersistenceResult<Option<coland_storage::CommittedEventRecord>> {
        self.persistence
            .consent_current()
            .historical_basis(holder, id, revision)
            .await
    }
    pub async fn pending_consent_effect_holders(
        &self,
        issuer: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<Vec<arkret_wire::AccountId>> {
        self.persistence
            .consent_current()
            .pending_effect_holders(issuer)
            .await
    }
    pub async fn prepare_consent_effect_publication(
        &self,
        holder: &arkret_wire::AccountId,
        issuer: &arkret_wire::DidCoreId,
        nonce: String,
    ) -> PersistenceResult<Option<coland_storage::PrivateEffectsPublication>> {
        self.persistence
            .consent_current()
            .prepare_effect_publication(holder, issuer, nonce)
            .await
    }
    pub async fn acknowledge_consent_effect_publication(
        &self,
        holder: &arkret_wire::AccountId,
        issuer: &arkret_wire::DidCoreId,
        sequence: u64,
    ) -> PersistenceResult<()> {
        self.persistence
            .consent_current()
            .acknowledge_effect_publication(holder, issuer, sequence)
            .await
    }
    pub async fn project_consent_effect_publication(
        &self,
        request: &arkret_models_collaboration::consent_private::ConsentPrivateEffectsPublishRequest,
        source: &arkret_wire::DidCoreId,
        receiver: &arkret_wire::DidCoreId,
        authority: &coland_storage::CurrentRealmAuthority,
        known_head: &arkret_wire::CommitStreamHead,
    ) -> PersistenceResult<coland_storage::PrivateEffectsProjection> {
        self.persistence
            .consent_current()
            .project_effect_publication(request, source, receiver, authority, known_head)
            .await
    }

    pub async fn observe_consent_private_cut(
        &self,
        request: &arkret_models_collaboration::consent_private::ConsentPrivateProxyRequest,
        outcome: &arkret_models_collaboration::consent_private::ConsentPrivateProxyOutcome,
    ) -> PersistenceResult<()> {
        self.persistence
            .consent_current()
            .observe_private_cut(request, outcome)
            .await
    }

    pub async fn consent_private_command_prepared(
        &self,
        request: &arkret_models_collaboration::consent_private::ConsentPrivateProxyRequest,
        source: &arkret_wire::DidCoreId,
        acceptor: &arkret_wire::DidCoreId,
        quota: &arkret_wire::NewSourceQuotaConstraints,
        prepared: Option<&coland_storage::PreparedPrivateInviteDelivery>,
    ) -> PersistenceResult<arkret_models_collaboration::consent_private::ConsentPrivateProxyOutcome>
    {
        self.persistence
            .consent_current()
            .private_command_prepared(request, source, acceptor, quota, prepared)
            .await
    }

    pub async fn consent_private_command(
        &self,
        request: &arkret_models_collaboration::consent_private::ConsentPrivateProxyRequest,
        source: &arkret_wire::DidCoreId,
        acceptor: &arkret_wire::DidCoreId,
        quota: &arkret_wire::NewSourceQuotaConstraints,
    ) -> PersistenceResult<arkret_models_collaboration::consent_private::ConsentPrivateProxyOutcome>
    {
        self.persistence
            .consent_current()
            .private_command(request, source, acceptor, quota)
            .await
    }

    pub async fn admit_consent(
        &self,
        write: coland_storage::ConsentAdmissionWrite,
    ) -> PersistenceResult<coland_storage::ConsentAdmissionOutcome> {
        self.persistence.consent_current().admit(write).await
    }

    pub async fn admit_consented_invite_delivery(
        &self,
        write: coland_storage::ConsentDeliveryWrite,
    ) -> PersistenceResult<Option<coland_storage::AccountDataCasResult>> {
        self.persistence
            .consent_current()
            .admit_invite_delivery(write)
            .await
    }

    pub async fn consent_current(
        &self,
        holder: &arkret_wire::AccountId,
    ) -> PersistenceResult<Vec<coland_storage::ConsentCurrentRecord>> {
        self.persistence.consent_current().list(holder).await
    }
    pub async fn consent_current_cut(
        &self,
        holder: &arkret_wire::AccountId,
        peer: &arkret_models_collaboration::events_payloads::consent::ConsentPeer,
        scope: arkret_wire::ConsentScope,
        device: Option<&arkret_wire::DeviceId>,
    ) -> PersistenceResult<coland_storage::ConsentCurrentCut> {
        self.persistence
            .consent_current()
            .read_cut(holder, peer, scope, device)
            .await
    }
    pub async fn prepare_managed_forward(
        &self,
        request: &arkret_models_collaboration::authority_commit::PeerAuthoritySubmitRequest,
        destination: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<coland_storage::PreparedManagedForward> {
        self.persistence
            .account_device_signer_evidence()
            .prepare_managed_forward(request, destination)
            .await
    }

    pub async fn retain_managed_forward(
        &self,
        request: &arkret_models_collaboration::authority_commit::PeerAuthoritySubmitRequest,
    ) -> PersistenceResult<arkret_wire::SignerEvidenceRef> {
        self.persistence
            .account_device_signer_evidence()
            .retain_managed_forward(request)
            .await
    }

    pub async fn get_managed_forward(
        &self,
        account: &arkret_wire::AccountId,
        device: &arkret_wire::DeviceId,
        reference: &arkret_wire::SignerEvidenceRef,
    ) -> PersistenceResult<
        Option<arkret_models_collaboration::authority_commit::PeerAuthoritySubmitRequest>,
    > {
        self.persistence
            .account_device_signer_evidence()
            .get_managed_forward(account, device, reference)
            .await
    }

    pub async fn prepare_forward_current_signer_evidence(
        &self,
        event: &arkret_wire::Event,
        destination: &arkret_wire::DidCoreId,
        body_digest: &arkret_wire::Hash,
    ) -> PersistenceResult<Option<arkret_models_crypto::ForwardDeviceProjectionAttestationCore>>
    {
        self.persistence
            .account_device_signer_evidence()
            .prepare_forward_current(event, destination, body_digest)
            .await
    }

    pub async fn retain_forward_current_signer_evidence(
        &self,
        event: &arkret_wire::Event,
        evidence: &arkret_models_identity::ForwardAccountDeviceSignerEvidence,
    ) -> PersistenceResult<arkret_wire::SignerEvidenceRef> {
        self.persistence
            .account_device_signer_evidence()
            .retain_forward_current(event, evidence)
            .await
    }

    pub async fn forwarded_bound_account_device_signer_fact(
        &self,
        event: &arkret_wire::Event,
        commit: &arkret_wire::RealmCommit,
        governance: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<
        Option<arkret_models_collaboration::authority_commit::AccountDeviceHistoricalSignerFact>,
    > {
        self.persistence
            .account_device_signer_evidence()
            .forwarded_bound_account_device_signer_fact(event, commit, governance)
            .await
    }

    pub async fn retain_current_account_device_signer_evidence(
        &self,
        evidence: &arkret_models_identity::AccountDeviceSignerEvidence,
        authorization_ref: &arkret_wire::CommittedEventRef,
    ) -> PersistenceResult<arkret_wire::SignerEvidenceRef> {
        self.persistence
            .account_device_signer_evidence()
            .retain_current(evidence, authorization_ref)
            .await
    }

    pub async fn account_device_signer_evidence(
        &self,
        account: &arkret_wire::AccountId,
        device: &arkret_wire::DeviceId,
        reference: &arkret_wire::SignerEvidenceRef,
    ) -> PersistenceResult<Option<arkret_models_identity::AccountDeviceSignerEvidence>> {
        self.persistence
            .account_device_signer_evidence()
            .get(account, device, reference)
            .await
    }

    /// Classify one producer-verified read cursor advance and store its
    /// account-private winner (`ak.private.read_cursor.v1`).
    pub async fn advance_read_cursor(
        &self,
        advance: &coland_storage::ReadCursorAdvance,
    ) -> PersistenceResult<coland_storage::ReadCursorAdvanceOutcome> {
        self.persistence.read_cursors().advance(advance).await
    }

    /// Admit one producer-verified actor-private account-data Event and its
    /// holder CAS in one private transaction.
    pub async fn admit_actor_private_account_data(
        &self,
        admission: &coland_storage::ActorPrivateAccountDataAdmission,
    ) -> PersistenceResult<coland_storage::ActorPrivateAccountDataOutcome> {
        self.persistence
            .account_data()
            .admit_actor_private_event(admission)
            .await
    }

    /// Admit one producer-verified Event of the generic actor-private submit
    /// operation into its owner's private store with the exact-retry ledger.
    pub async fn submit_actor_private_event(
        &self,
        submission: &coland_storage::ActorPrivateEventSubmission,
    ) -> PersistenceResult<coland_storage::ActorPrivateEventSubmitResult> {
        self.persistence
            .actor_private_events()
            .submit(submission)
            .await
    }

    /// The owner's durable read cursor winners.
    pub async fn read_cursor_winners(
        &self,
        owner: &arkret_wire::AccountId,
        realm_id: Option<&RealmId>,
    ) -> PersistenceResult<
        Vec<arkret_models_collaboration::objects::read_receipts::ReadMarkerOutcome>,
    > {
        self.persistence.read_cursors().list(owner, realm_id).await
    }

    /// Admit one holder-signed Actor Profile Event through its PCR unit.
    pub async fn admit_actor_profile(
        &self,
        write: coland_storage::ActorProfileAdmissionWrite,
    ) -> PersistenceResult<coland_storage::ActorProfileAdmissionOutcome> {
        self.persistence.actor_profiles().admit_profile(write).await
    }

    /// Admit one controller-signed `ak.agent.provision` through its
    /// controller-PCR unit.
    pub async fn admit_agent_provision(
        &self,
        write: coland_storage::AgentProvisionAdmissionWrite,
    ) -> PersistenceResult<coland_storage::AgentProvisionAdmissionOutcome> {
        self.persistence
            .actor_profiles()
            .admit_agent_provision(write)
            .await
    }

    /// Admit one controller-executed Agent PCR genesis through its unit.
    pub async fn admit_agent_pcr_genesis(
        &self,
        write: coland_storage::AgentPcrGenesisAdmissionWrite,
    ) -> PersistenceResult<coland_storage::AgentPcrGenesisAdmissionOutcome> {
        self.persistence
            .actor_profiles()
            .admit_agent_pcr_genesis(write)
            .await
    }

    /// Admit one controller-executed Agent PCR control Event through its unit.
    pub async fn admit_agent_control_event(
        &self,
        write: coland_storage::AgentControlAdmissionWrite,
    ) -> PersistenceResult<coland_storage::AgentControlAdmissionOutcome> {
        self.persistence
            .actor_profiles()
            .admit_agent_control_event(write)
            .await
    }

    /// Admit a same-key replacement without bypassing fresh-key pairing.
    pub async fn admit_agent_same_key_renewal(
        &self,
        write: coland_storage::AgentControlAdmissionWrite,
        origin: Option<coland_storage::AgentControlOriginSource>,
    ) -> PersistenceResult<coland_storage::AgentControlAdmissionOutcome> {
        self.persistence
            .actor_profiles()
            .admit_agent_same_key_renewal(write, origin)
            .await
    }

    /// Retain a prepared origin only with the accepted Agent control Event.
    pub async fn admit_agent_control_event_with_origin(
        &self,
        write: coland_storage::AgentControlAdmissionWrite,
        origin: Option<coland_storage::AgentControlOriginSource>,
    ) -> PersistenceResult<coland_storage::AgentControlAdmissionOutcome> {
        self.persistence
            .actor_profiles()
            .admit_agent_control_event_with_origin(write, origin)
            .await
    }

    /// Admit one issuer-signed accountability grant through its PCR unit.
    pub async fn admit_accountability_grant(
        &self,
        write: coland_storage::AccountabilityGrantAdmissionWrite,
    ) -> PersistenceResult<coland_storage::AccountabilityGrantAdmissionOutcome> {
        self.persistence
            .actor_profiles()
            .admit_accountability_grant(write)
            .await
    }

    /// The account's current PCR Actor Profile with its exact Event and Commit.
    pub async fn current_actor_profile(
        &self,
        account: &arkret_wire::AccountId,
    ) -> PersistenceResult<Option<coland_storage::ActorProfileResultRecord>> {
        self.persistence
            .actor_profiles()
            .current_profile(account)
            .await
    }

    /// Whether a committed `identity_accountability` record verifies the
    /// `(issuer, subject)` endorsement at `at`.
    pub async fn accountability_verified_at(
        &self,
        issuer_id: &arkret_wire::DidCoreId,
        subject_id: &arkret_wire::DidCoreId,
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<bool> {
        self.persistence
            .actor_profiles()
            .accountability_verified_at(issuer_id, subject_id, at)
            .await
    }

    pub(crate) fn authority_commit_store(&self) -> &dyn coland_storage::AuthorityCommitStore {
        self.persistence.authority_commits()
    }

    pub async fn committed_event(
        &self,
        event_id: &arkret_wire::EventId,
    ) -> PersistenceResult<Option<coland_storage::CommittedEventRecord>> {
        self.persistence
            .authority_commits()
            .committed_event(event_id)
            .await
    }

    /// Read the authoritative Relation current-result rows used by exact CAS.
    ///
    /// The returned records include both the complete materialized Relation
    /// and its accepting RealmCommit revision.  Keeping this behind the
    /// opaque application handle lets private read adapters observe the same
    /// durable truth as admission without exposing the storage registry.
    pub async fn relation_current_results(
        &self,
    ) -> PersistenceResult<Vec<coland_storage::RelationCurrentResultRecord>> {
        self.persistence
            .relation_current_results()
            .snapshot_all()
            .await
    }

    /// Read one Realm's authoritative Capability Grant current-result rows in
    /// a single storage snapshot. The HTTP effective-grants read derives both
    /// each canonical grant and its exact CAS revision from these same rows.
    pub async fn capability_grant_current_results(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> PersistenceResult<Vec<coland_storage::CapabilityGrantCurrentResultRecord>> {
        self.persistence
            .capability_grant_current_results()
            .snapshot_for_realm(realm_id)
            .await
    }

    /// Every current Capability Grant of every Realm.
    pub async fn all_capability_grant_current_results(
        &self,
    ) -> PersistenceResult<Vec<coland_storage::CapabilityGrantCurrentResultRecord>> {
        self.persistence
            .capability_grant_current_results()
            .snapshot_all()
            .await
    }

    /// Every `active` current Capability Grant naming exactly `subject`.
    pub async fn active_capability_grants_for_subject(
        &self,
        subject: &arkret_wire::ActorId,
    ) -> PersistenceResult<Vec<coland_storage::CapabilityGrantCurrentResultRecord>> {
        self.persistence
            .capability_grant_current_results()
            .active_for_subject(subject)
            .await
    }

    /// Every open directed Invite addressed to exactly `invitee`, read from
    /// the Invite typed current results at one cut.
    pub async fn open_directed_invites_for_invitee(
        &self,
        invitee: &arkret_wire::AccountId,
        realm_id: Option<&arkret_wire::RealmId>,
    ) -> PersistenceResult<Vec<coland_storage::DirectedInviteCurrent>> {
        self.persistence
            .invite_current_results()
            .open_directed_invites_for_invitee(invitee, realm_id)
            .await
    }

    /// Sign portable third-party Invite evidence while holding its current cut.
    pub async fn third_party_invite_acceptance_attestation(
        &self,
        request: &ThirdPartyInviteAcceptanceAttestationRequestBody,
        caller: &arkret_wire::AccountId,
        station: &arkret_wire::DidCoreId,
        verification_method: &arkret_wire::DidUrl,
        observe: &(dyn Fn() -> chrono::DateTime<chrono::Utc> + Send + Sync),
        sign: &coland_storage::InviteAcceptanceAttestationSigner<'_>,
    ) -> PersistenceResult<ThirdPartyInviteAcceptanceAttestationOutcome> {
        self.persistence
            .invite_current_results()
            .third_party_invite_acceptance_attestation(
                request,
                caller,
                station,
                verification_method,
                observe,
                sign,
            )
            .await
    }

    /// Invite results, optionally across all Realms, at one committed cut.
    pub async fn invites_in_realm(
        &self,
        realm_id: Option<&arkret_wire::RealmId>,
    ) -> PersistenceResult<Vec<coland_storage::InviteCurrent>> {
        self.persistence
            .invite_current_results()
            .invites_in_realm(realm_id)
            .await
    }

    /// Deployment-private Agent content ceilings from one current snapshot.
    pub async fn agent_session_authority(
        &self,
        request: &coland_storage::AgentSessionAuthorityRequest,
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<coland_storage::AgentSessionAuthorityOutcome> {
        self.persistence
            .capability_grant_current_results()
            .agent_session_authority(request, at)
            .await
    }

    /// The authorization inputs of `actor` in `realm_id`, read at one cut.
    pub async fn actor_realm_authorization(
        &self,
        realm_id: &arkret_wire::RealmId,
        actor: &arkret_wire::ActorId,
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<coland_storage::ActorRealmAuthorization> {
        self.persistence
            .capability_grant_current_results()
            .actor_authorization(realm_id, actor, at)
            .await
    }

    pub async fn append_account_status_record(
        &self,
        record: &arkret_models_collaboration::account_status::AccountStatusRecord,
        receipt: &arkret_models_collaboration::account_status::AccountStatusReceipt,
    ) -> crate::ServiceResult<coland_storage::AccountStatusReplicaAppend> {
        Ok(self
            .persistence
            .account_status_replicas()
            .append(record, receipt)
            .await?)
    }

    pub async fn resolve_account_status_records(
        &self,
        account_authority_id: &str,
        account_id: &arkret_wire::AccountId,
        from_status_seq: u64,
        limit: u16,
    ) -> crate::ServiceResult<Vec<arkret_models_collaboration::account_status::AccountStatusRecord>>
    {
        Ok(self
            .persistence
            .account_status_replicas()
            .resolve(account_authority_id, account_id, from_status_seq, limit)
            .await?)
    }

    pub async fn current_account_status_record(
        &self,
        account_authority_id: &str,
        account_id: &arkret_wire::AccountId,
    ) -> crate::ServiceResult<
        Option<arkret_models_collaboration::account_status::AccountStatusRecord>,
    > {
        Ok(self
            .persistence
            .account_status_replicas()
            .current(account_authority_id, account_id)
            .await?)
    }

    pub async fn erasure_pending_account_status_records(
        &self,
        limit: u16,
    ) -> crate::ServiceResult<Vec<arkret_models_collaboration::account_status::AccountStatusRecord>>
    {
        Ok(self
            .persistence
            .account_status_replicas()
            .erasure_pending(limit)
            .await?)
    }

    pub async fn account_status_receipt(
        &self,
        account_authority_id: &str,
        account_id: &arkret_wire::AccountId,
        status_seq: u64,
    ) -> crate::ServiceResult<
        Option<arkret_models_collaboration::account_status::AccountStatusReceipt>,
    > {
        Ok(self
            .persistence
            .account_status_replicas()
            .receipt(account_authority_id, account_id, status_seq)
            .await?)
    }

    pub async fn merge_account_status_affected_services(
        &self,
        account_id: &arkret_wire::AccountId,
        observations: &[coland_storage::AccountStatusAffectedServiceObservation],
        max_services: usize,
    ) -> crate::ServiceResult<Vec<arkret_wire::DidCoreId>> {
        Ok(self
            .persistence
            .account_status_replicas()
            .merge_affected_services(account_id, observations, max_services)
            .await?)
    }

    pub async fn discover_account_status_affected_services(
        &self,
        account_id: &arkret_wire::AccountId,
        holder_service_id: &arkret_wire::DidCoreId,
        observed_at: chrono::DateTime<chrono::Utc>,
    ) -> crate::ServiceResult<Vec<coland_storage::AccountStatusAffectedServiceObservation>> {
        Ok(self
            .persistence
            .account_status_replicas()
            .discover_affected_services(account_id, holder_service_id, observed_at)
            .await?)
    }

    pub async fn account_status_affected_services(
        &self,
        account_id: &arkret_wire::AccountId,
        limit: usize,
    ) -> crate::ServiceResult<Vec<arkret_wire::DidCoreId>> {
        Ok(self
            .persistence
            .account_status_replicas()
            .affected_services(account_id, limit)
            .await?)
    }

    pub async fn begin_account_status_propagation(
        &self,
        record: &arkret_models_collaboration::account_status::AccountStatusRecord,
        destinations: &[arkret_wire::DidCoreId],
        deadline_at: chrono::DateTime<chrono::Utc>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> crate::ServiceResult<coland_storage::AccountStatusPropagationProjection> {
        Ok(self
            .persistence
            .account_status_replicas()
            .begin_propagation(record, destinations, deadline_at, now)
            .await?)
    }

    pub async fn acknowledge_account_status_propagation_destination(
        &self,
        account_status_record_id: &arkret_wire::AccountStatusRecordId,
        destination_id: &arkret_wire::DidCoreId,
        acknowledged_at: chrono::DateTime<chrono::Utc>,
    ) -> crate::ServiceResult<Option<coland_storage::AccountStatusPropagationProjectionTransition>>
    {
        Ok(self
            .persistence
            .account_status_replicas()
            .acknowledge_propagation_destination(
                account_status_record_id,
                destination_id,
                acknowledged_at,
            )
            .await?)
    }

    pub async fn current_account_status_propagation_projection(
        &self,
        account_id: &arkret_wire::AccountId,
        now: chrono::DateTime<chrono::Utc>,
    ) -> crate::ServiceResult<Option<coland_storage::AccountStatusPropagationProjectionTransition>>
    {
        Ok(self
            .persistence
            .account_status_replicas()
            .current_propagation_projection(account_id, now)
            .await?)
    }

    pub async fn contact_completion_for_request(
        &self,
        actor: &arkret_wire::ActorId,
        key: &str,
        request_hash: &str,
    ) -> crate::ServiceResult<Option<coland_storage::ContactCompletionState>> {
        Ok(self
            .persistence
            .contacts()
            .completion_for_request(actor, key, request_hash)
            .await?)
    }
    pub async fn committed_contact_completion_intents(
        &self,
        limit: u16,
        after: Option<&arkret_wire::Hash>,
    ) -> crate::ServiceResult<Vec<coland_storage::CommittedContactCompletionIntent>> {
        Ok(self
            .persistence
            .contacts()
            .committed_completion_intents(limit, after)
            .await?)
    }
    pub async fn finalize_contact_completion_intent(
        &self,
        ready: &coland_storage::CommittedContactCompletionIntent,
        result: &coland_storage::ContactCompletionResult,
        delivery: Option<&coland_storage::FederationOutboxRecord>,
        counterpart_proof: Option<
            &arkret_models_collaboration::contact_operations::ContactCurrentProof,
        >,
    ) -> crate::ServiceResult<bool> {
        Ok(self
            .persistence
            .contacts()
            .finalize_completion_intent(ready, result, delivery, counterpart_proof)
            .await?)
    }

    pub async fn contact_verified_mirror(
        &self,
        target_holder_principal_id: &str,
        request_event_id: &str,
    ) -> crate::ServiceResult<Option<coland_storage::ContactVerifiedMirrorRecord>> {
        Ok(self
            .persistence
            .contact_verified_mirrors()
            .get(target_holder_principal_id, request_event_id)
            .await?)
    }

    pub async fn put_contact_verified_mirror(
        &self,
        record: &coland_storage::ContactVerifiedMirrorRecord,
    ) -> crate::ServiceResult<()> {
        Ok(self
            .persistence
            .contact_verified_mirrors()
            .put_verified(record)
            .await?)
    }

    pub async fn agent_cleanup_intent(
        &self,
        cleanup_intent_digest: &arkret_wire::Hash,
    ) -> crate::ServiceResult<Option<coland_storage::AgentCleanupRecord>> {
        Ok(self
            .persistence
            .agent_membership_cascades()
            .agent_cleanup_intent(cleanup_intent_digest)
            .await?)
    }

    pub async fn agent_cleanup_intent_for_terminal_event(
        &self,
        controller_terminal_event_id: &arkret_wire::EventId,
    ) -> crate::ServiceResult<Option<coland_storage::AgentCleanupRecord>> {
        Ok(self
            .persistence
            .agent_membership_cascades()
            .agent_cleanup_intent_for_terminal_event(controller_terminal_event_id)
            .await?)
    }

    pub async fn incomplete_agent_cleanup_intents(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        limit: usize,
    ) -> crate::ServiceResult<Vec<coland_storage::AgentCleanupRecord>> {
        Ok(self
            .persistence
            .agent_membership_cascades()
            .incomplete_agent_cleanup_intents(now, limit)
            .await?)
    }

    pub async fn device_revocation_gate_status(
        &self,
        selector: &coland_storage::DeviceRevocationGateSelector,
    ) -> crate::ServiceResult<coland_storage::DeviceRevocationGateStatus> {
        Ok(self
            .persistence
            .device_revocations()
            .gate_status(selector)
            .await?)
    }

    pub async fn applet_managed_device_authority(
        &self,
        account: &arkret_wire::AccountId,
        device_id: &arkret_wire::DeviceId,
        now: chrono::DateTime<chrono::Utc>,
    ) -> crate::ServiceResult<Option<coland_storage::AppletManagedDeviceAuthority>> {
        Ok(self
            .persistence
            .device_revocations()
            .applet_managed_device_authority(account, device_id, now)
            .await?)
    }

    pub async fn applet_managed_event_producer(
        &self,
        event: &arkret_wire::Event,
        now: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<Option<coland_storage::AppletManagedDeviceAuthority>> {
        self.persistence
            .device_revocations()
            .applet_managed_event_producer(event, now)
            .await
    }

    pub async fn consume_applet_managed_device_nonce(
        &self,
        expected: &coland_storage::AppletManagedDeviceAuthority,
        metadata: &arkret_models_integration::AppletManagedDeviceMetadata,
        retain_until: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<coland_storage::AppletManagedDeviceAuthority> {
        self.persistence
            .device_revocations()
            .consume_applet_managed_device_nonce(expected, metadata, retain_until)
            .await
    }

    pub async fn pcr_device_generation(
        &self,
        account: &arkret_wire::AccountId,
    ) -> crate::ServiceResult<Option<coland_storage::PcrDeviceGeneration>> {
        Ok(self
            .persistence
            .device_revocations()
            .pcr_device_generation(account)
            .await?)
    }

    pub async fn pcr_device_admission(
        &self,
        account: &arkret_wire::AccountId,
        device_id: &arkret_wire::DeviceId,
        now: chrono::DateTime<chrono::Utc>,
    ) -> crate::ServiceResult<arkret_wire::DeviceRevocationAdmissionDecision> {
        Ok(self
            .persistence
            .device_revocations()
            .pcr_device_admission(account, device_id, now)
            .await?)
    }

    pub async fn pcr_device_authorization_key(
        &self,
        account: &arkret_wire::AccountId,
        device_id: &arkret_wire::DeviceId,
    ) -> crate::ServiceResult<Option<arkret_wire::DidKey>> {
        Ok(self
            .persistence
            .device_revocations()
            .pcr_device_authorization_key(account, device_id)
            .await?)
    }

    pub async fn push_registration_handoff_for_local_route(
        &self,
        source_station_id: &arkret_wire::DidCoreId,
        local_route: &coland_storage::PushRegistrationHandoffRouteLocator,
    ) -> crate::ServiceResult<Option<coland_storage::PushRegistrationHandoffIntentRecord>> {
        Ok(self
            .persistence
            .push_registration_handoffs()
            .lookup_local_route_intent(source_station_id, local_route)
            .await?)
    }

    pub async fn reserve_push_hard_logout_journal(
        &self,
        record: &coland_storage::PushHardLogoutJournalRecord,
    ) -> crate::ServiceResult<coland_storage::PushHardLogoutJournalRecord> {
        Ok(self
            .persistence
            .push_registration_handoffs()
            .reserve_hard_logout_journal(record)
            .await?)
    }

    pub async fn push_hard_logout_journal(
        &self,
        grant_token_digest: &str,
    ) -> crate::ServiceResult<Option<coland_storage::PushHardLogoutJournalRecord>> {
        Ok(self
            .persistence
            .push_registration_handoffs()
            .hard_logout_journal(grant_token_digest)
            .await?)
    }

    pub async fn pending_confirmed_push_hard_logouts(
        &self,
        after_digest: Option<&str>,
        limit: usize,
    ) -> crate::ServiceResult<Vec<coland_storage::PushHardLogoutJournalRecord>> {
        Ok(self
            .persistence
            .push_registration_handoffs()
            .pending_confirmed_hard_logouts(after_digest, limit)
            .await?)
    }

    pub async fn mark_push_hard_logout_auth_confirmed(
        &self,
        grant_token_digest: &str,
    ) -> crate::ServiceResult<()> {
        Ok(self
            .persistence
            .push_registration_handoffs()
            .mark_hard_logout_auth_confirmed(grant_token_digest)
            .await?)
    }

    pub async fn mark_push_hard_logout_completed(
        &self,
        grant_token_digest: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> crate::ServiceResult<()> {
        Ok(self
            .persistence
            .push_registration_handoffs()
            .mark_hard_logout_completed(grant_token_digest, now)
            .await?)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "An atomic handoff binds both routes, source authority, replay proof and current time."
    )]
    pub async fn ensure_push_registration_handoff_intent(
        &self,
        source_station_id: &arkret_wire::DidCoreId,
        local_route: &coland_storage::PushRegistrationHandoffRouteLocator,
        device_authorization: &coland_storage::DeviceRevocationGateSelector,
        client_input_digest: &arkret_wire::Hash,
        request: &arkret::PushRegistrationHandoffRequestBody,
        session_revocation_ref: Option<&str>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> crate::ServiceResult<coland_storage::PushRegistrationHandoffIntentWrite> {
        Ok(self
            .persistence
            .push_registration_handoffs()
            .ensure_desired_intent(
                source_station_id,
                local_route,
                device_authorization,
                client_input_digest,
                request,
                session_revocation_ref,
                now,
            )
            .await?)
    }

    pub async fn begin_public_push_unregistration(
        &self,
        account_id: &arkret_wire::AccountId,
        device_id: &arkret_wire::DeviceId,
        push_key: Option<&str>,
        app_id: Option<&str>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> crate::ServiceResult<Vec<coland_storage::PushRegistrationHandoffIntentRecord>> {
        Ok(self
            .persistence
            .push_registration_handoffs()
            .begin_public_push_unregistration(account_id, device_id, push_key, app_id, now)
            .await?)
    }

    pub async fn begin_public_push_account_deactivation(
        &self,
        account_id: &arkret_wire::AccountId,
        now: chrono::DateTime<chrono::Utc>,
    ) -> crate::ServiceResult<usize> {
        Ok(self
            .persistence
            .push_registration_handoffs()
            .begin_public_push_account_deactivation(account_id, now)
            .await?)
    }

    pub async fn awaiting_public_push_revocations(
        &self,
        source_station_id: &arkret_wire::DidCoreId,
        after: Option<&coland_storage::PushRegistrationHandoffRetryCursor>,
        limit: usize,
    ) -> crate::ServiceResult<Vec<coland_storage::PushRegistrationHandoffIntentRecord>> {
        Ok(self
            .persistence
            .push_registration_handoffs()
            .list_awaiting_revoked_intents(source_station_id, after, limit)
            .await?)
    }

    pub async fn expire_public_push_registrations(
        &self,
        source_station_id: &arkret_wire::DidCoreId,
        now: chrono::DateTime<chrono::Utc>,
        after: Option<&coland_storage::PushRegistrationHandoffExpiryCursor>,
        limit: usize,
    ) -> crate::ServiceResult<coland_storage::PushRegistrationHandoffExpiryPage> {
        Ok(self
            .persistence
            .push_registration_handoffs()
            .expire_public_push_registrations(source_station_id, now, after, limit)
            .await?)
    }

    pub async fn commit_verified_push_registration_handoff_receipt(
        &self,
        source_station_id: &arkret_wire::DidCoreId,
        registration_id: &arkret::PushRegistrationId,
        expected_request_digest: &arkret_wire::Hash,
        receipt: &arkret::PushRegistrationInstallationReceipt,
        now: chrono::DateTime<chrono::Utc>,
    ) -> crate::ServiceResult<coland_storage::PushRegistrationHandoffReceiptWrite> {
        Ok(self
            .persistence
            .push_registration_handoffs()
            .commit_verified_receipt(
                source_station_id,
                registration_id,
                expected_request_digest,
                receipt,
                now,
            )
            .await?)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn commit_verified_push_registration_handoff(
        &self,
        source_station_id: &arkret_wire::DidCoreId,
        local_route: &coland_storage::PushRegistrationHandoffRouteLocator,
        registration_id: &arkret::PushRegistrationId,
        expected_request_digest: &arkret_wire::Hash,
        receipt: &arkret::PushRegistrationInstallationReceipt,
        authorization: &coland_storage::DeviceRevocationGateSelector,
        registration: &arkret::PushRegistrationRecord,
        session_revocation_ref: Option<&str>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> crate::ServiceResult<coland_storage::PushRegistrationHandoffReceiptWrite> {
        Ok(self
            .persistence
            .push_registration_handoffs()
            .commit_verified_active_receipt_and_push_route(
                source_station_id,
                local_route,
                registration_id,
                expected_request_digest,
                receipt,
                authorization,
                registration,
                session_revocation_ref,
                now,
            )
            .await?)
    }

    pub async fn device_revocation_targets(
        &self,
        selector: &coland_storage::DeviceRevocationGateSelector,
    ) -> crate::ServiceResult<Vec<coland_storage::DeviceRevocationTargetRecord>> {
        Ok(self
            .persistence
            .device_revocations()
            .list_targets(selector)
            .await?)
    }

    pub async fn linearize_device_revocation_gate(
        &self,
        request: coland_storage::DeviceRevocationGateLinearizationRequest,
    ) -> crate::ServiceResult<coland_storage::DeviceRevocationGateLinearization> {
        Ok(self
            .persistence
            .device_revocations()
            .linearize_gate(request)
            .await?)
    }

    pub async fn pending_device_revocation_cleanup_intents(
        &self,
        limit: usize,
    ) -> crate::ServiceResult<Vec<coland_storage::DeviceRevocationCleanupIntent>> {
        Ok(self
            .persistence
            .device_revocations()
            .pending_cleanup_intents(limit)
            .await?)
    }

    pub async fn complete_device_revocation_material_cleanup(
        &self,
        proposal_event_id: &arkret_wire::EventId,
        completed_at: chrono::DateTime<chrono::Utc>,
    ) -> crate::ServiceResult<bool> {
        Ok(self
            .persistence
            .device_revocations()
            .complete_material_cleanup(proposal_event_id, completed_at)
            .await?)
    }

    pub async fn complete_device_revocation_mls_obligation(
        &self,
        proposal_event_id: &arkret_wire::EventId,
        completed_at: chrono::DateTime<chrono::Utc>,
    ) -> crate::ServiceResult<bool> {
        Ok(self
            .persistence
            .device_revocations()
            .complete_mls_obligation(proposal_event_id, completed_at)
            .await?)
    }

    pub async fn idempotency_record(
        &self,
        principal_id: &arkret_identifiers::DidCoreId,
        idempotency_key: &str,
    ) -> crate::ServiceResult<Option<coland_storage::IdempotencyRecord>> {
        Ok(self
            .persistence
            .idempotency_keys()
            .get(
                &arkret_wire::ActorId::service(principal_id.clone()),
                crate::jobs::INTERNAL_IDEMPOTENCY_OPERATION,
                idempotency_key,
            )
            .await?)
    }

    pub async fn scoped_idempotency_record(
        &self,
        authenticated_actor: &arkret_wire::ActorId,
        operation_id: &str,
        idempotency_key: &str,
    ) -> crate::ServiceResult<Option<coland_storage::IdempotencyRecord>> {
        Ok(self
            .persistence
            .idempotency_keys()
            .get(authenticated_actor, operation_id, idempotency_key)
            .await?)
    }

    pub async fn record_idempotency(
        &self,
        record: &coland_storage::IdempotencyRecord,
    ) -> crate::ServiceResult<()> {
        self.persistence.idempotency_keys().record(record).await?;
        Ok(())
    }

    pub async fn complete_idempotency_reservation(
        &self,
        expected: &coland_storage::IdempotencyRecord,
        completed: &coland_storage::IdempotencyRecord,
    ) -> crate::ServiceResult<bool> {
        Ok(self
            .persistence
            .idempotency_keys()
            .complete_reservation(expected, completed)
            .await?)
    }

    pub async fn stored_service_route_keys(
        &self,
        after: Option<&coland_storage::ServiceRouteStoredKey>,
        limit: usize,
    ) -> crate::ServiceResult<Vec<coland_storage::ServiceRouteStoredKey>> {
        Ok(self
            .persistence
            .service_routes()
            .list_stored_route_keys(after, limit)
            .await?)
    }

    pub async fn stored_service_route_quarantine(
        &self,
        service_id: &arkret_wire::DidCoreId,
        service_kind: &str,
        limit: usize,
    ) -> crate::ServiceResult<Vec<coland_storage::ServiceResolutionForkEvidence>> {
        Ok(self
            .persistence
            .service_routes()
            .quarantine_evidence(service_id, service_kind, limit)
            .await?)
    }

    pub async fn service_route_cache(
        &self,
        service_id: &arkret_wire::DidCoreId,
        service_kind: &str,
    ) -> crate::ServiceResult<Option<arkret_models_identity::VerifiedServiceRoute>> {
        Ok(self
            .persistence
            .service_routes()
            .route_cache(service_id, service_kind)
            .await?)
    }

    pub async fn service_route_method_state(
        &self,
        service_id: &arkret_wire::DidCoreId,
        service_kind: &str,
    ) -> crate::ServiceResult<Option<arkret_models_identity::ServiceMethodState>> {
        Ok(self
            .persistence
            .service_routes()
            .method_state(service_id, service_kind)
            .await?)
    }

    pub async fn stored_service_identity(
        &self,
    ) -> crate::ServiceResult<Option<arkret_identity::service_identity::StoredDidCoreIdentity>>
    {
        Ok(self.persistence.service_identity().get().await?)
    }

    pub async fn store_service_identity(
        &self,
        identity: arkret_identity::service_identity::StoredDidCoreIdentity,
    ) -> crate::ServiceResult<()> {
        self.persistence.service_identity().put(identity).await?;
        Ok(())
    }

    pub async fn principal_resolution_by_account_id(
        &self,
        account_id: &arkret_wire::AccountId,
    ) -> crate::ServiceResult<Option<coland_storage::PrincipalResolutionRecord>> {
        Ok(self
            .persistence
            .principal_resolutions()
            .by_account_id(account_id)
            .await?)
    }

    pub async fn current_principal(
        &self,
        account_id: &arkret_wire::AccountId,
    ) -> crate::ServiceResult<coland_storage::CurrentPrincipalRead> {
        Ok(self
            .persistence
            .principal_resolutions()
            .current_principal(account_id)
            .await?)
    }

    pub async fn principal_resolution_for_realm(
        &self,
        pcr_realm_id: &arkret_wire::RealmId,
    ) -> crate::ServiceResult<Option<coland_storage::PrincipalResolutionRecord>> {
        Ok(self
            .persistence
            .principal_resolutions()
            .for_realm(pcr_realm_id)
            .await?)
    }

    pub async fn compare_and_set_principal_resolution(
        &self,
        expected_current_event_ref: Option<&str>,
        next: coland_storage::PrincipalResolutionRecord,
    ) -> crate::ServiceResult<coland_storage::PrincipalResolutionCasResult> {
        Ok(self
            .persistence
            .principal_resolutions()
            .compare_and_set(expected_current_event_ref, next)
            .await?)
    }

    pub async fn principal_resolution_history(
        &self,
        account_id: &arkret_wire::AccountId,
        after_event_ref: Option<&str>,
        limit: usize,
    ) -> crate::ServiceResult<Vec<arkret_wire::Event>> {
        Ok(self
            .persistence
            .principal_resolutions()
            .history_newest_first(account_id, after_event_ref, limit)
            .await?)
    }

    pub async fn service_registration(
        &self,
        key: &arkret_models_identity::service_identity::ServiceRegistrationKey,
    ) -> crate::ServiceResult<
        Option<arkret_models_identity::service_identity::ServiceRegistrationOutcome>,
    > {
        Ok(self
            .persistence
            .webvh()
            .get_service_registration(key)
            .await?)
    }

    pub async fn webvh_history(&self, did: &str) -> crate::ServiceResult<Vec<DidLogEvent>> {
        Ok(self
            .persistence
            .webvh()
            .list_log_events(did)
            .await?
            .into_iter()
            .map(|record| DidLogEvent {
                event_digest: record.event_digest,
                did: record.did,
                seq: record.seq,
                operation: record.operation,
                created_at: record.created_at,
            })
            .collect())
    }

    /// Append one successor entry to a DID this deployment hosts, comparing the
    /// current head so a concurrent writer cannot be overwritten.
    ///
    /// `commit_service_registration` is inception-only. Everything after it -
    /// authorizing a delegated assertion key, retiring one, moving an endpoint -
    /// arrives here.
    pub async fn commit_webvh_log_operation(
        &self,
        expected_current_head: Option<String>,
        document: DidDocumentState,
        event: DidLogEvent,
        service_identity: Option<coland_storage::ServiceIdentitySuccessor>,
    ) -> crate::ServiceResult<coland_storage::WebvhLogCommitOutcome> {
        let document = coland_storage::WebvhDocumentRecord {
            did: document.did,
            did_document: document.did_document,
            key_log_head: document.key_log_head,
            seq: document.seq,
            method_evidence: document.method_evidence,
            fetched_at: document.fetched_at,
            expires_at: document.expires_at,
            updated_at: document.updated_at,
        };
        let event = coland_storage::WebvhLogRecord {
            event_digest: event.event_digest,
            did: event.did,
            seq: event.seq,
            operation: event.operation,
            created_at: event.created_at,
        };
        Ok(self
            .persistence
            .webvh()
            .commit_log_operation(expected_current_head, document, event, service_identity)
            .await?)
    }

    pub async fn commit_service_registration(
        &self,
        key: arkret_models_identity::service_identity::ServiceRegistrationKey,
        outcome: arkret_models_identity::service_identity::ServiceRegistrationOutcome,
        document: DidDocumentState,
        event: DidLogEvent,
    ) -> crate::ServiceResult<ServiceRegistrationCommitResult> {
        let document = coland_storage::WebvhDocumentRecord {
            did: document.did,
            did_document: document.did_document,
            key_log_head: document.key_log_head,
            seq: document.seq,
            method_evidence: document.method_evidence,
            fetched_at: document.fetched_at,
            expires_at: document.expires_at,
            updated_at: document.updated_at,
        };
        let event = coland_storage::WebvhLogRecord {
            event_digest: event.event_digest,
            did: event.did,
            seq: event.seq,
            operation: event.operation,
            created_at: event.created_at,
        };
        Ok(
            match self
                .persistence
                .webvh()
                .commit_service_registration(key, outcome, document, event)
                .await?
            {
                coland_storage::ServiceRegistrationCommitOutcome::Created(outcome) => {
                    ServiceRegistrationCommitResult::Created(outcome)
                }
                coland_storage::ServiceRegistrationCommitOutcome::Existing(outcome) => {
                    ServiceRegistrationCommitResult::Existing(outcome)
                }
                coland_storage::ServiceRegistrationCommitOutcome::Conflict => {
                    ServiceRegistrationCommitResult::Conflict
                }
            },
        )
    }

    pub async fn seed_demo_identity(&self) -> crate::ServiceResult<()> {
        let now = chrono::Utc::now();
        let account = coland_storage::AccountRecord {
            pk: coland_storage::AccountPk(0),
            principal_id: arkret_wire::DidCoreId::new("ak:did_core:web:alice.example".to_owned())
                .expect("demo principal id is canonical"),
            station_id: arkret_wire::DidCoreId::new("ak:did_core:web:server.example".to_owned())
                .expect("demo Station id is canonical"),
            localpart: "alice".to_owned(),
            display_name: Some("Alice Example".to_owned()),
            bio: None,
            avatar_blob_ref: None,
            created_at: now,
        };
        self.persistence.accounts().put(&account).await?;
        self.persistence
            .realm_meta()
            .put(
                "ak:realm:AezgkQb6OtCT0VrUyihcuY6ih8wmyafofZG6EmHBpM7e",
                &coland_storage::RealmMetaRecord {
                    owner: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                        account.principal_id,
                        account.station_id,
                    ))
                    .to_string(),
                    deleted: false,
                    discoverability: "public".to_owned(),
                    history_access: "all_history_for_current_members".to_owned(),
                    preview_policy: None,
                    preview_policy_digest: None,
                    asset_privacy_policy: None,
                    asset_privacy_policy_digest: None,
                    encryption_profile: None,
                    plaintext_visible_services: BTreeSet::new(),
                    plaintext_visible_service_classes: BTreeMap::new(),
                    minimal_metadata_realm: false,
                    created_at: now,
                    updated_at: now,
                },
            )
            .await?;
        Ok(())
    }

    pub fn new<P>(persistence: Arc<P>) -> Self
    where
        P: PersistenceStore + 'static,
    {
        Self { persistence }
    }

    #[doc(hidden)]
    pub fn from_shared(persistence: Arc<dyn PersistenceStore>) -> Self {
        Self { persistence }
    }

    /// Read the immutable device instance captured when a local session was created.
    pub async fn session_device_authorization(
        &self,
        token: &str,
    ) -> PersistenceResult<Option<coland_storage::DeviceRevocationGateSelector>> {
        self.persistence
            .sessions()
            .device_authorization(token)
            .await
    }

    pub async fn revoke_local_devices(
        &self,
        actor: &str,
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<usize> {
        self.persistence.devices().revoke_actor(actor, at).await
    }

    pub fn member_identity_store(&self) -> &dyn coland_storage::MemberIdentityStore {
        self.persistence.member_identity()
    }

    /// Server-internal seen-source ledger behind the per-holder new-source
    /// quota (`identity/consent-model.md` section 6.1.1.4). One ledger serves
    /// all three converging surfaces -- private invite delivery,
    /// `ak.self.consent.command.request.v1` and a stranger's first Contact
    /// request -- so a rotated pairwise DID cannot buy a fresh budget on
    /// whichever surface is cheapest. It is reachable only from the admission
    /// chokepoint and from account erasure; no operation projects it onto the
    /// wire.
    pub fn invite_new_source_ledger_store(
        &self,
    ) -> &dyn coland_storage::InviteNewSourceLedgerStore {
        self.persistence.invite_new_source_ledger()
    }

    /// Charge the shared first-contact quota and CAS one holder-private
    /// Consent request entry in the same durable transaction.
    pub async fn admit_consent_request_quarantine(
        &self,
        input: coland_storage::ConsentRequestQuarantineInput,
    ) -> PersistenceResult<coland_storage::ConsentRequestQuarantineOutcome> {
        self.persistence
            .consent_request_quarantine()
            .admit(input)
            .await
    }

    pub fn event_services(&self) -> PersistenceEventServices {
        build_persistence_event_services(self.persistence.clone())
    }

    pub fn delivery_service(
        &self,
        object_storage: Arc<dyn ObjectStoragePort>,
        push_target_hmac_key: [u8; 32],
    ) -> DeliveryService {
        build_persistence_delivery_service(
            self.persistence.clone(),
            object_storage,
            push_target_hmac_key,
        )
    }

    pub fn identity_services(
        &self,
        did_resolver: Arc<dyn DidResolverPort>,
    ) -> PersistenceIdentityServices {
        build_persistence_identity_services(self.persistence.clone(), did_resolver)
    }

    pub fn operational_services(
        &self,
        runtime_settings: Arc<dyn RuntimeSettingsPort>,
        runtime_health: Arc<dyn RuntimeHealthPort>,
    ) -> PersistenceOperationalServices {
        build_persistence_operational_services(
            self.persistence.clone(),
            runtime_settings,
            runtime_health,
        )
    }

    pub async fn hydrate_realm_directory(&self) -> PersistenceResult<RealmDirectoryIndex> {
        let mut realms = RealmDirectoryIndex::new();
        hydrate_realms_from_canonical_events(self.persistence.as_ref(), &mut realms).await?;
        Ok(realms)
    }

    pub async fn hydrate_realm_directory_entry(
        &self,
        realm_id: &RealmId,
    ) -> PersistenceResult<Option<RealmDirectoryEntry>> {
        let mut realms = RealmDirectoryIndex::new();
        hydrate_realm_from_canonical_events(self.persistence.as_ref(), &mut realms, realm_id)
            .await?;
        Ok(realms.get(realm_id).cloned())
    }

    pub async fn hydrate_projection(
        &self,
        projection: &ProjectionService,
        projection_adapter: &dyn HydrationProjectionAdapter,
        realm_ids: impl IntoIterator<Item = RealmId>,
    ) -> PersistenceResult<()> {
        projection
            .hydrate_from_persistence(self.persistence.as_ref(), projection_adapter, realm_ids)
            .await
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn shared_for_tests(&self) -> Arc<dyn PersistenceStore> {
        self.persistence.clone()
    }
}

#[async_trait::async_trait]
impl coland_storage::DeviceRevocationStore for PersistenceHandle {
    async fn applet_managed_event_producer(
        &self,
        event: &arkret_wire::Event,
        now: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<Option<coland_storage::AppletManagedDeviceAuthority>> {
        self.persistence
            .device_revocations()
            .applet_managed_event_producer(event, now)
            .await
    }

    async fn consume_applet_managed_device_nonce(
        &self,
        expected: &coland_storage::AppletManagedDeviceAuthority,
        metadata: &arkret_models_integration::AppletManagedDeviceMetadata,
        retain_until: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<coland_storage::AppletManagedDeviceAuthority> {
        self.persistence
            .device_revocations()
            .consume_applet_managed_device_nonce(expected, metadata, retain_until)
            .await
    }

    async fn applet_managed_device_authority(
        &self,
        account: &arkret_wire::AccountId,
        device_id: &arkret_wire::DeviceId,
        now: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<Option<coland_storage::AppletManagedDeviceAuthority>> {
        self.persistence
            .device_revocations()
            .applet_managed_device_authority(account, device_id, now)
            .await
    }

    async fn pcr_device_generation(
        &self,
        account: &arkret_wire::AccountId,
    ) -> PersistenceResult<Option<coland_storage::PcrDeviceGeneration>> {
        self.persistence
            .device_revocations()
            .pcr_device_generation(account)
            .await
    }
    async fn pcr_device_admission(
        &self,
        account: &arkret_wire::AccountId,
        device_id: &arkret_wire::DeviceId,
        now: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<arkret_wire::DeviceRevocationAdmissionDecision> {
        self.persistence
            .device_revocations()
            .pcr_device_admission(account, device_id, now)
            .await
    }
    async fn pcr_device_authorization_key(
        &self,
        account: &arkret_wire::AccountId,
        device_id: &arkret_wire::DeviceId,
    ) -> PersistenceResult<Option<arkret_wire::DidKey>> {
        self.persistence
            .device_revocations()
            .pcr_device_authorization_key(account, device_id)
            .await
    }
    async fn gate_status(
        &self,
        selector: &coland_storage::DeviceRevocationGateSelector,
    ) -> PersistenceResult<coland_storage::DeviceRevocationGateStatus> {
        self.persistence
            .device_revocations()
            .gate_status(selector)
            .await
    }

    async fn list_targets(
        &self,
        selector: &coland_storage::DeviceRevocationGateSelector,
    ) -> PersistenceResult<Vec<coland_storage::DeviceRevocationTargetRecord>> {
        self.persistence
            .device_revocations()
            .list_targets(selector)
            .await
    }

    async fn target_for_event(
        &self,
        event_id: &arkret_wire::EventId,
    ) -> PersistenceResult<Option<coland_storage::DeviceRevocationTargetRecord>> {
        self.persistence
            .device_revocations()
            .target_for_event(event_id)
            .await
    }

    async fn linearize_gate(
        &self,
        request: coland_storage::DeviceRevocationGateLinearizationRequest,
    ) -> PersistenceResult<coland_storage::DeviceRevocationGateLinearization> {
        self.persistence
            .device_revocations()
            .linearize_gate(request)
            .await
    }

    async fn commit_revocation(
        &self,
        transition: &coland_storage::DeviceRevocationTransition,
    ) -> PersistenceResult<coland_storage::DeviceRevocationTransitionDecision> {
        self.persistence
            .device_revocations()
            .commit_revocation(transition)
            .await
    }

    async fn pending_cleanup_intents(
        &self,
        limit: usize,
    ) -> PersistenceResult<Vec<coland_storage::DeviceRevocationCleanupIntent>> {
        self.persistence
            .device_revocations()
            .pending_cleanup_intents(limit)
            .await
    }

    async fn complete_material_cleanup(
        &self,
        event_id: &arkret_wire::EventId,
        completed_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<bool> {
        self.persistence
            .device_revocations()
            .complete_material_cleanup(event_id, completed_at)
            .await
    }

    async fn complete_mls_obligation(
        &self,
        event_id: &arkret_wire::EventId,
        completed_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<bool> {
        self.persistence
            .device_revocations()
            .complete_mls_obligation(event_id, completed_at)
            .await
    }
}

/// Let the composition root install the route resolver over the exact same
/// persistence registry as the rest of the application. No route-safety
/// state is copied into an HTTP-local adapter.
#[async_trait::async_trait]
impl coland_storage::ServiceRouteStore for PersistenceHandle {
    async fn list_stored_route_keys(
        &self,
        after: Option<&coland_storage::ServiceRouteStoredKey>,
        limit: usize,
    ) -> PersistenceResult<Vec<coland_storage::ServiceRouteStoredKey>> {
        self.persistence
            .service_routes()
            .list_stored_route_keys(after, limit)
            .await
    }

    async fn quarantine_evidence(
        &self,
        service_id: &arkret_wire::DidCoreId,
        service_kind: &str,
        limit: usize,
    ) -> PersistenceResult<Vec<coland_storage::ServiceResolutionForkEvidence>> {
        self.persistence
            .service_routes()
            .quarantine_evidence(service_id, service_kind, limit)
            .await
    }

    async fn method_state(
        &self,
        service_id: &arkret_wire::DidCoreId,
        service_kind: &str,
    ) -> PersistenceResult<Option<arkret_models_identity::ServiceMethodState>> {
        self.persistence
            .service_routes()
            .method_state(service_id, service_kind)
            .await
    }

    async fn publish_route_cache(
        &self,
        evidence: arkret_models_identity::AuthenticatedServiceResolution,
        route: arkret_models_identity::VerifiedServiceRoute,
    ) -> PersistenceResult<coland_storage::MonotonicRouteWrite> {
        self.persistence
            .service_routes()
            .publish_route_cache(evidence, route)
            .await
    }

    async fn quarantine_fork(
        &self,
        evidence: coland_storage::ServiceResolutionForkEvidence,
    ) -> PersistenceResult<()> {
        self.persistence
            .service_routes()
            .quarantine_fork(evidence)
            .await
    }

    async fn is_quarantined(
        &self,
        service_id: &arkret_wire::DidCoreId,
        service_kind: &str,
    ) -> PersistenceResult<bool> {
        self.persistence
            .service_routes()
            .is_quarantined(service_id, service_kind)
            .await
    }

    async fn route_cache(
        &self,
        service_id: &arkret_wire::DidCoreId,
        service_kind: &str,
    ) -> PersistenceResult<Option<arkret_models_identity::VerifiedServiceRoute>> {
        self.persistence
            .service_routes()
            .route_cache(service_id, service_kind)
            .await
    }

    async fn evict_route_cache(
        &self,
        service_id: &arkret_wire::DidCoreId,
        service_kind: &str,
    ) -> PersistenceResult<()> {
        self.persistence
            .service_routes()
            .evict_route_cache(service_id, service_kind)
            .await
    }
}
