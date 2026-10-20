//! Current governance-Station application boundary.

mod mls_roster;
use arkret_models_collaboration::authority_commit::{
    AccountDeviceHistoricalSignerFact, AuthorityForwardBranch, AuthorityHandoffRequest,
    DirectConversationFoundingAcceptanceOutcome, DirectConversationFoundingFederationSubmission,
    DirectConversationFoundingUnitSubmission, HistoricalProducerSignerFact,
    MembershipCompensationAcceptanceOutcome, MembershipCompensationFederationSubmission,
    MembershipCompensationUnitSubmission, OrdinaryRealmBootstrapAcceptanceOutcome,
    OrdinaryRealmBootstrapUnitSubmission, PeerAuthorityForwardEventRequest,
    PeerAuthorityForwardMlsRequest, PeerAuthorityForwardOutcome, PeerAuthoritySubmitOutcome,
    PeerAuthoritySubmitRequest, PeerCommittedReplicationOutcome, PeerCommittedReplicationRequest,
    PeerRegisteredAtomicUnit, PeerRegisteredAtomicUnitOutcome,
    PeerRegisteredAtomicUnitOutcomeValue, SelfAuthoritySubmitOutcome, SelfAuthoritySubmitRequest,
};
use arkret_models_collaboration::exact_current_results::{
    ExactCurrentResultsReadOutcome, ExactCurrentResultsReadRequestBody,
};
use arkret_models_collaboration::principal_operations::PcrGenesisAdmissionInput;
use arkret_models_collaboration::strand_watch_operations::{
    StrandWatchCurrentOutcome, StrandWatchCurrentRequestBody,
};
use arkret_wire::{
    AuthorityBundleRequest, AuthoritySubmitOutcome, CommitStreamHead, CommitStreamRef,
    DetachedSignatureContext, DidCoreId, DidUrl, Event, EventAdmissionSubmission,
    MlsCommitSubmission, RealmAuthorityBundle, RealmAuthorityCurrentAssertion,
    RealmAuthorityHandoff, RealmAuthorityTransition, RealmCommit, RealmCommitId,
    RealmStateSnapshot, StreamScanDirection, StreamScanOutcome, StreamScanRequest,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coland_storage::{
    AuthorityCommitStore, AuthorityCommitTransaction, AuthorityCommitWriteOutcome,
    CurrentRealmAuthority, ForwardAttemptStatus, OrdinaryRealmBootstrapCommitOutcome,
    OrdinaryRealmBootstrapCommitUnit, PcrGenesisCommitOutcome, PcrGenesisCommitUnit,
    QueuedEventRecord, SelfProducerCommitGuard,
};
use ed25519_dalek::SigningKey;
pub use mls_roster::{MlsRosterAuthorityApplicationRead, MlsRosterAuthorityPreflight};
use serde::Serialize;

use crate::persistence::PersistenceHandle;
use crate::{ServiceError, ServiceResult};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthorityEventAdmissionOutcome {
    Committed(RealmCommit),
    Duplicate(RealmCommit),
    NotCurrentAuthority,
}

#[derive(Serialize)]
struct RealmCommitIdentityBody<'a> {
    realm_id: &'a arkret_wire::RealmId,
    stream_ref: &'a CommitStreamRef,
    stream_position: u64,
    previous_commit_ref: &'a Option<RealmCommitId>,
    event_ref: &'a arkret_wire::EventId,
    governance_generation: u64,
    authority_ref: &'a arkret_wire::RealmCommitAuthorityRef,
    #[serde(serialize_with = "arkret_wire::serde_helpers::serialize_canonical_timestamp")]
    committed_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    producer_signer_fact_digest: Option<&'a arkret_wire::Hash>,
}

#[derive(Serialize)]
struct RealmCommitUnsignedBody<'a> {
    commit_id: &'a RealmCommitId,
    realm_id: &'a arkret_wire::RealmId,
    stream_ref: &'a CommitStreamRef,
    stream_position: u64,
    previous_commit_ref: &'a Option<RealmCommitId>,
    event_ref: &'a arkret_wire::EventId,
    governance_generation: u64,
    authority_ref: &'a arkret_wire::RealmCommitAuthorityRef,
    #[serde(serialize_with = "arkret_wire::serde_helpers::serialize_canonical_timestamp")]
    committed_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    producer_signer_fact_digest: Option<&'a arkret_wire::Hash>,
}

#[derive(Serialize)]
struct RealmSnapshotIdentityBody<'a> {
    realm_id: &'a arkret_wire::RealmId,
    governance_generation: u64,
    visible_stream_heads: &'a [CommitStreamHead],
    current_state_entries: &'a [arkret_wire::TypedCurrentRow],
    retention_and_history_floor: &'a arkret_wire::RetentionAndHistoryFloor,
    #[serde(serialize_with = "arkret_wire::serde_helpers::serialize_canonical_timestamp")]
    created_at: DateTime<Utc>,
}

#[derive(Serialize)]
struct RealmSnapshotUnsignedBody<'a> {
    snapshot_id: &'a arkret_wire::RealmSnapshotId,
    realm_id: &'a arkret_wire::RealmId,
    governance_generation: u64,
    visible_stream_heads: &'a [CommitStreamHead],
    current_state_entries: &'a [arkret_wire::TypedCurrentRow],
    retention_and_history_floor: &'a arkret_wire::RetentionAndHistoryFloor,
    #[serde(serialize_with = "arkret_wire::serde_helpers::serialize_canonical_timestamp")]
    created_at: DateTime<Utc>,
}

#[derive(Serialize)]
struct RealmAuthorityAssertionUnsignedBody<'a> {
    realm_id: &'a arkret_wire::RealmId,
    current_generation: u64,
    current_service_id: &'a DidCoreId,
    last_handoff_ref: &'a Option<arkret_wire::RealmAuthorityHandoffId>,
    realm_stream_head: &'a CommitStreamHead,
    nonce: &'a arkret_wire::Base64UrlString,
    #[serde(serialize_with = "arkret_wire::serde_helpers::serialize_canonical_timestamp")]
    expires_at: DateTime<Utc>,
}

pub fn build_signed_realm_state_snapshot(
    material: &coland_storage::RealmStateSnapshotMaterial,
    verification_method: DidUrl,
    signing_key: &SigningKey,
    created_at: DateTime<Utc>,
) -> ServiceResult<RealmStateSnapshot> {
    if material.visible_stream_heads.is_empty()
        || !material
            .visible_stream_heads
            .windows(2)
            .all(|pair| pair[0].stream_ref < pair[1].stream_ref)
    {
        return Err(ServiceError::SchemaViolation(
            "Realm snapshot requires sorted, unique visible stream heads".to_owned(),
        ));
    }
    let created_at = arkret_canonical::normalize_timestamp_canonical(created_at);
    let identity = RealmSnapshotIdentityBody {
        realm_id: &material.realm_id,
        governance_generation: material.governance_generation,
        visible_stream_heads: &material.visible_stream_heads,
        current_state_entries: &material.current_state_entries,
        retention_and_history_floor: &material.retention_and_history_floor,
        created_at,
    };
    let identity_bytes = arkret_canonical::canonical_json_bytes(&identity)
        .map_err(|error| ServiceError::Internal(error.to_string()))?;
    let snapshot_id =
        arkret_wire::RealmSnapshotId::from_digest(arkret_canonical::sha256_bytes(&identity_bytes));
    let unsigned = RealmSnapshotUnsignedBody {
        snapshot_id: &snapshot_id,
        realm_id: &material.realm_id,
        governance_generation: material.governance_generation,
        visible_stream_heads: &material.visible_stream_heads,
        current_state_entries: &material.current_state_entries,
        retention_and_history_floor: &material.retention_and_history_floor,
        created_at,
    };
    let signature = arkret_signatures::detached_object::sign_detached_object(
        &unsigned,
        DetachedSignatureContext::RealmSnapshot,
        verification_method,
        created_at,
        signing_key,
    )
    .map_err(|error| ServiceError::Internal(error.to_string()))?;
    Ok(RealmStateSnapshot {
        snapshot_id,
        realm_id: material.realm_id.clone(),
        governance_generation: material.governance_generation,
        visible_stream_heads: material.visible_stream_heads.clone(),
        current_state_entries: material.current_state_entries.clone(),
        retention_and_history_floor: material.retention_and_history_floor.clone(),
        created_at,
        signature,
    })
}

/// Verify both genesis Event signatures against keys pinned by the exact
/// registration anchor and founding device descriptor, never current DID
/// resolution. The short-lived control-proof time window is checked by the
/// authenticated peer ingress before a fresh admission.
fn validate_pcr_genesis_producer_proofs(
    submission: &PcrGenesisAdmissionInput,
) -> ServiceResult<()> {
    use arkret_models_collaboration::events_payloads::DeviceAuthorizePayload;
    use arkret_models_identity::PrincipalRegistrationAnchor;

    let invalid = |detail: String| ServiceError::SchemaViolation(detail);
    let anchor = arkret_identity::validate_principal_registration_anchor(
        &submission.principal_registration_anchor,
    )
    .map_err(|error| invalid(format!("PCR registration anchor is invalid: {error}")))?;
    arkret_signatures::webvh::verify_identity_creation_control_proof(
        &anchor,
        &submission.identity_creation_control_proof,
    )
    .map_err(|error| invalid(format!("PCR identity creation proof is invalid: {error}")))?;
    let PrincipalRegistrationAnchor::WebvhRegistration {
        registration_did_operation,
        ..
    } = &submission.principal_registration_anchor;
    arkret_signatures::webvh::verify_registration_did_evidence_draft(
        registration_did_operation,
        &submission.registration_did_evidence.draft(),
    )
    .map_err(|error| {
        invalid(format!(
            "PCR frozen registration evidence is invalid: {error}"
        ))
    })?;

    let create = submission.genesis_unit.create();
    let authorize = submission.genesis_unit.founding_authorize();
    let device: DeviceAuthorizePayload = serde_json::from_value(serde_json::Value::Object(
        authorize.payload.clone().into_iter().collect(),
    ))
    .map_err(|error| invalid(format!("PCR founding device payload is invalid: {error}")))?;
    arkret_signatures::verify_device_authorize_possession(
        &device,
        &arkret_wire::AccountId::new(
            submission.principal_id.clone(),
            submission.account_authority_id.clone(),
        ),
    )
    .map_err(|error| {
        invalid(format!(
            "PCR founding device possession is invalid: {error}"
        ))
    })?;

    let root_key = arkret_signatures::PublicKeyMaterial::Ed25519Multibase {
        value: anchor.root_public_key_multibase.clone(),
    };
    let device_multibase = device
        .device_public_key_did
        .as_str()
        .strip_prefix("did:key:")
        .ok_or_else(|| invalid("PCR founding device key is not did:key".to_owned()))?;
    let device_key = arkret_signatures::PublicKeyMaterial::Ed25519Multibase {
        value: device_multibase.to_owned(),
    };
    let root_method = format!(
        "did:key:{}#{}",
        anchor.root_public_key_multibase, anchor.root_public_key_multibase
    );
    let device_method = format!("{}#{}", submission.did, device.device_id);
    for (event, expected_method, key) in [
        (create, root_method.as_str(), &root_key),
        (authorize, device_method.as_str(), &device_key),
    ] {
        let proof = event
            .producer_proof
            .as_ref()
            .ok_or_else(|| invalid("PCR genesis Event lacks its producer proof".to_owned()))?;
        if proof.verification_method.as_str() != expected_method {
            return Err(invalid(
                "PCR genesis producer method differs from its pinned key".to_owned(),
            ));
        }
        let bytes = arkret_signatures::EventProofBuilder::new()
            .envelope_bytes(event)
            .map_err(|error| invalid(format!("PCR Event canonicalization failed: {error}")))?;
        arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
            proof,
            &bytes,
            &event.actor_id,
            key,
            arkret_canonical::DigestSuite::Sha256,
        )
        .map_err(|error| invalid(format!("PCR Event producer signature is invalid: {error}")))?;
    }
    Ok(())
}

/// Judge Event-carried validity windows against the signed `committed_at`
/// of the Commit that would cover the Event.
///
/// `constraint-schema.md` §9.2.6: an `ak.agent.action_approve` confirmation
/// is admissible only while its covering `committed_at <= expires_at`,
/// inclusive with zero tolerance. Envelope `created_at` and the Station's
/// current time never participate, and a refusal happens before any write,
/// so no nonce is allocated. Exact retries return their stored Commit before
/// reaching this point and are never re-judged.
fn ensure_commit_time_admits_event(
    event: &Event,
    committed_at: DateTime<Utc>,
) -> ServiceResult<()> {
    if event.kind != arkret_wire::EventKind::AgentActionApprove {
        return Ok(());
    }
    let payload: arkret_models_collaboration::events_payloads::agent::AgentActionApprovePayload =
        serde_json::to_value(&event.payload)
            .and_then(serde_json::from_value)
            .map_err(|error| {
                ServiceError::SchemaViolation(format!(
                    "ak.agent.action_approve payload is invalid: {error}"
                ))
            })?;
    if !payload.admits_commit_at(committed_at) {
        return Err(ServiceError::Conflict(format!(
            "{}: ak.agent.action_approve covering committed_at is after expires_at",
            coland_storage::ConflictCode::FailedPrecondition.as_str()
        )));
    }
    Ok(())
}

fn build_signed_event_commit(
    event: &Event,
    authority: &CurrentRealmAuthority,
    head: Option<&CommitStreamHead>,
    verification_method: DidUrl,
    signing_key: &SigningKey,
    committed_at: DateTime<Utc>,
    producer_signer_fact: Option<&HistoricalProducerSignerFact>,
) -> ServiceResult<RealmCommit> {
    let stream_ref = CommitStreamRef::from_scope(&event.scope_ref, Some(event.realm_id.clone()))
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    if head.is_some_and(|value| value.stream_ref != stream_ref) {
        return Err(ServiceError::Internal(
            "authority store returned a head for the wrong stream".to_owned(),
        ));
    }
    let (stream_position, previous_commit_ref) = match head {
        Some(head) => (
            head.stream_position.checked_add(1).ok_or_else(|| {
                ServiceError::Internal("authority stream position overflow".to_owned())
            })?,
            Some(head.commit_id.clone()),
        ),
        None => (0, None),
    };
    let committed_at = arkret_canonical::normalize_timestamp_canonical(committed_at);
    ensure_commit_time_admits_event(event, committed_at)?;
    let producer_signer_fact_digest = producer_signer_fact
        .map(|fact| {
            fact.validate_event_binding(event, event.realm_id.digest_suite_code().digest_suite())
                .and_then(|_| fact.digest())
        })
        .transpose()
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    let identity_body = RealmCommitIdentityBody {
        realm_id: &event.realm_id,
        stream_ref: &stream_ref,
        stream_position,
        previous_commit_ref: &previous_commit_ref,
        event_ref: &event.event_id,
        governance_generation: authority.generation,
        authority_ref: &authority.authority_ref,
        committed_at,
        producer_signer_fact_digest: producer_signer_fact_digest.as_ref(),
    };
    // `commit_id` is the typed content address of the closed commit body.
    // Like every self-identifying object, its identity preimage excludes the
    // identity field itself as well as the detached signature.
    let identity_bytes = arkret_canonical::canonical_json_bytes(&identity_body)
        .map_err(|error| ServiceError::Internal(error.to_string()))?;
    let commit_id = RealmCommitId::from_digest(arkret_canonical::sha256_bytes(&identity_bytes));
    let unsigned_body = RealmCommitUnsignedBody {
        commit_id: &commit_id,
        realm_id: &event.realm_id,
        stream_ref: &stream_ref,
        stream_position,
        previous_commit_ref: &previous_commit_ref,
        event_ref: &event.event_id,
        governance_generation: authority.generation,
        authority_ref: &authority.authority_ref,
        committed_at,
        producer_signer_fact_digest: producer_signer_fact_digest.as_ref(),
    };
    let signature = arkret_signatures::detached_object::sign_detached_object(
        &unsigned_body,
        DetachedSignatureContext::RealmCommit,
        verification_method,
        committed_at,
        signing_key,
    )
    .map_err(|error| ServiceError::Internal(error.to_string()))?;
    let commit = RealmCommit {
        commit_id,
        realm_id: event.realm_id.clone(),
        stream_ref,
        stream_position,
        previous_commit_ref,
        event_ref: event.event_id.clone(),
        governance_generation: authority.generation,
        authority_ref: authority.authority_ref.clone(),
        committed_at,
        producer_signer_fact_digest,
        signature,
    };
    commit
        .validate_shape()
        .map_err(|error| ServiceError::Internal(error.to_string()))?;
    Ok(commit)
}

/// Durable queued-to-committed lifecycle used by the governance Station.
///
/// Signature verification, policy evaluation, MLS installation, and commit
/// signing happen before [`Self::install_commit`]. The store then performs one
/// atomic authority-generation check, stream append, Event state transition,
/// and Welcome enqueue.
#[derive(Clone)]
pub struct AuthorityCommitApplication {
    persistence: PersistenceHandle,
    recipient_queue_capacity: usize,
}

impl AuthorityCommitApplication {
    pub async fn check_call_media_release(
        &self,
        request: &arkret_models_collaboration::objects::media::CallMediaTokenExchangeRequestBody,
        issuer: &arkret_wire::DidCoreId,
    ) -> ServiceResult<bool> {
        Ok(self
            .store()
            .check_call_media_release(request, issuer)
            .await?)
    }
    pub async fn call_current_cut(
        &self,
        realm: &arkret_wire::RealmId,
        call: &arkret_wire::CallId,
        actor: &arkret_wire::ActorId,
    ) -> ServiceResult<Option<coland_storage::CallCurrentCut>> {
        Ok(self.store().call_current_cut(realm, call, actor).await?)
    }
    pub async fn realm_media_service_current(
        &self,
        realm: &arkret_wire::RealmId,
    ) -> ServiceResult<Option<arkret_models_collaboration::events_payloads::RealmMediaServiceValue>>
    {
        Ok(self.store().realm_media_service_current(realm).await?)
    }
    pub async fn morph_list_for_actor(
        &self,
        realm: &arkret_wire::RealmId,
        actor: &arkret_wire::ActorId,
        station: &arkret_wire::DidCoreId,
        include_terminal: bool,
    ) -> ServiceResult<
        Option<arkret_models_collaboration::objects::query_projection::ProjectionMorphList>,
    > {
        Ok(self
            .store()
            .morph_list_for_actor(realm, actor, station, include_terminal)
            .await?)
    }

    pub async fn document_morph_for_actor(
        &self,
        realm: &arkret_wire::RealmId,
        morph: &arkret_wire::MorphId,
        actor: &arkret_wire::ActorId,
        station: &arkret_wire::DidCoreId,
    ) -> ServiceResult<
        Option<
            arkret_models_collaboration::objects::query_projection::DocumentMorphProjectionOutcome,
        >,
    > {
        Ok(self
            .store()
            .document_morph_for_actor(realm, morph, actor, station)
            .await?)
    }

    pub async fn owned_agent_authorization_check(
        &self,
        caller: &arkret_wire::ActorId,
        station: &arkret_wire::DidCoreId,
        request: &arkret_models_collaboration::governance::authorization::AuthzCheckRequestBody,
    ) -> ServiceResult<
        Option<arkret_models_collaboration::governance::authorization::AuthzCheckOutcome>,
    > {
        Ok(self
            .store()
            .owned_agent_authorization_check(caller, station, request)
            .await?)
    }

    pub async fn acquire_committed_content_delivery(
        &self,
        account: &arkret_wire::AccountId,
        station: &arkret_wire::DidCoreId,
        input: &coland_storage::AccountContentDeliveryInput,
    ) -> ServiceResult<Option<Box<dyn coland_storage::AccountContentDeliveryGuard>>> {
        Ok(self
            .store()
            .acquire_committed_content_delivery(account, station, input)
            .await?)
    }
    /// Native fixed reply preparation, separate from the final Event UOW.
    pub async fn acquire_native_message_reply_preparation(
        &self,
        request: coland_storage::NativeMessageReplyPreparation<'_>,
    ) -> ServiceResult<Box<dyn coland_storage::AccountContentDeliveryGuard>> {
        Ok(self
            .store()
            .acquire_native_message_reply_preparation(request)
            .await?)
    }

    /// Sign the exact Event at a cut locked by a specialized admission unit.
    /// The unit must install this Commit with its domain facts atomically.
    #[expect(
        clippy::too_many_arguments,
        reason = "Signing binds the Event and all verified authority and producer facts at one cut."
    )]
    pub fn sign_event_commit_at_authority_cut(
        &self,
        event: &Event,
        authority: &CurrentRealmAuthority,
        head: Option<&CommitStreamHead>,
        verification_method: DidUrl,
        signing_key: &SigningKey,
        committed_at: DateTime<Utc>,
        producer_signer_fact: Option<&HistoricalProducerSignerFact>,
    ) -> ServiceResult<RealmCommit> {
        build_signed_event_commit(
            event,
            authority,
            head,
            verification_method,
            signing_key,
            committed_at,
            producer_signer_fact,
        )
    }

    pub fn new(persistence: PersistenceHandle, recipient_queue_capacity: usize) -> Self {
        Self {
            persistence,
            recipient_queue_capacity,
        }
    }

    pub async fn account_device_signer_fact(
        &self,
        event: &Event,
        commit: &RealmCommit,
    ) -> ServiceResult<Option<AccountDeviceHistoricalSignerFact>> {
        Ok(self
            .store()
            .account_device_signer_fact(event, commit)
            .await?)
    }

    pub async fn prepare_account_device_signer_fact(
        &self,
        event: &Event,
        admitted_at: DateTime<Utc>,
    ) -> ServiceResult<Option<AccountDeviceHistoricalSignerFact>> {
        Ok(self
            .store()
            .prepare_account_device_signer_fact(event, admitted_at)
            .await?)
    }

    pub async fn producer_signer_fact(
        &self,
        event: &Event,
        commit: &RealmCommit,
    ) -> ServiceResult<Option<HistoricalProducerSignerFact>> {
        Ok(self.store().producer_signer_fact(event, commit).await?)
    }
    pub async fn prepare_service_signer_fact(
        &self,
        event: &Event,
        guard: &coland_storage::AppletEventProducerGuard,
        at: DateTime<Utc>,
    ) -> ServiceResult<arkret_models_collaboration::authority_commit::ServiceHistoricalSignerFact>
    {
        Ok(self
            .store()
            .prepare_service_signer_fact(event, guard, at)
            .await?)
    }

    pub async fn retain_registered_pair_forward(
        &self,
        request: &arkret_models_collaboration::authority_commit::AuditPairedEventUnitSubmission,
        outcome: Option<
            &arkret_models_collaboration::authority_commit::AuditPairedEventAcceptanceOutcome,
        >,
    ) -> ServiceResult<()> {
        Ok(self
            .store()
            .retain_registered_pair_forward(request, outcome)
            .await?)
    }

    pub async fn registered_audit_result(
        &self,
        event_id: &arkret_wire::EventId,
    ) -> ServiceResult<Option<coland_storage::RegisteredAuditResult>> {
        Ok(self.store().registered_audit_result(event_id).await?)
    }

    pub async fn watch_audit_read_disclosure(
        &self,
        request: &arkret_models_collaboration::strand_watch_operations::WatchAuditReadRequest,
        outcome: &arkret_models_collaboration::strand_watch_operations::WatchAuditReadOutcome,
        issuer: &DidCoreId,
    ) -> ServiceResult<()> {
        Ok(self
            .store()
            .watch_audit_read_disclosure(request, outcome, issuer)
            .await?)
    }

    pub async fn watch_audit_read_delivery_guard(
        &self,
        request: &arkret_models_collaboration::strand_watch_operations::WatchAuditReadRequest,
        outcome: &arkret_models_collaboration::strand_watch_operations::WatchAuditReadOutcome,
        issuer: &DidCoreId,
        expires_at: DateTime<Utc>,
    ) -> ServiceResult<Box<dyn coland_storage::AccountContentDeliveryGuard>> {
        Ok(self
            .store()
            .watch_audit_read_delivery_guard(request, outcome, issuer, expires_at)
            .await?)
    }

    pub async fn install_committed_audit_pair(
        &self,
        request: &arkret_models_collaboration::authority_commit::AuditPairedEventFederationSubmission,
        replicas: &[coland_storage::CommittedReplica; 2],
    ) -> ServiceResult<arkret_models_collaboration::authority_commit::AggregateAcceptanceStatus>
    {
        Ok(self
            .store()
            .install_committed_audit_pair(request, replicas)
            .await?)
    }

    fn store(&self) -> &dyn AuthorityCommitStore {
        self.persistence.authority_commit_store()
    }

    pub async fn install_genesis_authority(
        &self,
        authority: &CurrentRealmAuthority,
    ) -> ServiceResult<()> {
        self.store().install_genesis_authority(authority).await?;
        Ok(())
    }

    /// Optional authoring preparation may read current membership only while
    /// this service is the verified governing Station. This read grants no
    /// Event authority; admission still checks the current commit cut.
    pub async fn local_current_member_joined(
        &self,
        realm_id: &arkret_wire::RealmId,
        member: &arkret_wire::ActorId,
        service_id: &DidCoreId,
    ) -> ServiceResult<bool> {
        Ok(self
            .store()
            .local_current_member_joined(realm_id, member, service_id)
            .await?)
    }

    /// Current joined membership in this service's accepted state, governed
    /// here or held as a verified committed replica. Grants no Event
    /// authority by itself.
    pub async fn accepted_current_member_joined(
        &self,
        realm_id: &arkret_wire::RealmId,
        member: &arkret_wire::ActorId,
    ) -> ServiceResult<bool> {
        Ok(self
            .store()
            .accepted_current_member_joined(realm_id, member)
            .await?)
    }

    pub async fn accepted_ordinary_realm(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> ServiceResult<bool> {
        Ok(self.store().accepted_ordinary_realm(realm_id).await?)
    }

    /// The accepted Realm root controller and current joined members held
    /// here, governed or replicated.
    pub async fn accepted_realm_roster(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> ServiceResult<Option<coland_storage::AcceptedRealmRoster>> {
        Ok(self.store().accepted_realm_roster(realm_id).await?)
    }

    /// The accepted Agent join and its controller's exact current generation.
    pub async fn accepted_effective_agent_member_joined(
        &self,
        realm_id: &arkret_wire::RealmId,
        agent: &arkret_wire::ActorId,
        controller: &arkret_wire::AccountId,
    ) -> ServiceResult<bool> {
        Ok(self
            .store()
            .accepted_effective_agent_member_joined(realm_id, agent, controller)
            .await?)
    }

    /// Whether `actor` reads `realm_id` here: a current joined member in this
    /// service's accepted state, or the owner of its principal-control Realm.
    /// Grants no Event authority by itself.
    pub async fn accepted_realm_reader(
        &self,
        realm_id: &arkret_wire::RealmId,
        actor: &arkret_wire::ActorId,
    ) -> ServiceResult<bool> {
        Ok(self.store().accepted_realm_reader(realm_id, actor).await?)
    }

    /// The Realm's current plaintext-visible service declaration in this
    /// service's accepted state.
    pub async fn accepted_plaintext_visible_services(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> ServiceResult<
        Option<
            arkret_models_collaboration::governance::plaintext_visibility::PlaintextVisibleServicesPayload,
        >,
    >{
        Ok(self
            .store()
            .accepted_plaintext_visible_services(realm_id)
            .await?)
    }

    pub async fn queue_event(&self, event: &Event, queued_at: DateTime<Utc>) -> ServiceResult<()> {
        event.validate_for_submit_structural().map_err(|error| {
            crate::ServiceError::SchemaViolation(format!("invalid producer Event: {error}"))
        })?;
        self.store().queue_event(event, queued_at).await?;
        Ok(())
    }

    pub async fn retain_forwarded_submission(
        &self,
        event: &Event,
        submission: &arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest,
        at: DateTime<Utc>,
    ) -> ServiceResult<()> {
        self.store()
            .retain_forwarded_submission(event, submission, at)
            .await?;
        Ok(())
    }

    pub async fn retain_forwarded_acceptance(
        &self,
        event: &Event,
        commit: &arkret_wire::RealmCommit,
        at: DateTime<Utc>,
    ) -> ServiceResult<()> {
        self.store()
            .retain_forwarded_acceptance(event, commit, at)
            .await?;
        Ok(())
    }

    pub async fn freeze_forwarded_peer_request(
        &self,
        event: &Event,
        request: &arkret_models_collaboration::authority_commit::PeerAuthoritySubmitRequest,
        at: DateTime<Utc>,
    ) -> ServiceResult<Box<arkret_models_collaboration::authority_commit::PeerAuthoritySubmitRequest>>
    {
        Ok(self
            .store()
            .freeze_forwarded_peer_request(event, request, at)
            .await?)
    }

    pub async fn record_forward_attempt(
        &self,
        event_id: &arkret_wire::EventId,
        status: ForwardAttemptStatus,
        reason_code: Option<&str>,
        attempted_at: DateTime<Utc>,
    ) -> ServiceResult<()> {
        self.store()
            .record_forward_attempt(event_id, status, reason_code, attempted_at)
            .await?;
        Ok(())
    }

    pub async fn finalize_mls_rejection(
        &self,
        event: &Event,
        authority: &CurrentRealmAuthority,
        reason_code: &str,
        native: Option<(
            coland_storage::ManagedMlsRefusalSource<'_>,
            &coland_storage::IdempotencyRecord,
        )>,
    ) -> ServiceResult<AuthoritySubmitOutcome> {
        Ok(self
            .store()
            .finalize_mls_rejection(event, authority, reason_code, native)
            .await?)
    }

    pub async fn queued_event(
        &self,
        event_id: &arkret_wire::EventId,
    ) -> ServiceResult<Option<QueuedEventRecord>> {
        Ok(self.store().queued_event(event_id).await?)
    }

    pub async fn install_commit(
        &self,
        transaction: &AuthorityCommitTransaction,
    ) -> ServiceResult<AuthorityCommitWriteOutcome> {
        // The service configuration, never the producer's submission, sets
        // the queue bound for a Commit carrying recipient-private Welcome.
        let mut transaction = transaction.clone();
        transaction.recipient_queue_capacity = self.recipient_queue_capacity;
        transaction.validate().map_err(|error| {
            crate::ServiceError::SchemaViolation(format!("invalid authority transaction: {error}"))
        })?;
        Ok(self.store().commit_transaction(&transaction).await?)
    }

    pub async fn ordinary_realm_bootstrap_replay(
        &self,
        submission: &OrdinaryRealmBootstrapUnitSubmission,
        exact_request_body: &[u8],
    ) -> ServiceResult<Option<Vec<arkret_wire::RealmCommit>>> {
        Ok(self
            .store()
            .ordinary_realm_bootstrap_replay(submission, exact_request_body)
            .await?)
    }

    /// Install an ordinary Realm genesis unit through one durable authority
    /// transaction. The caller must first perform session, producer-proof,
    /// policy and MLS validation and construct every signed Commit; the store
    /// enforces the ordered unit and exact-byte replay under one DB lock.
    pub async fn admit_ordinary_realm_bootstrap_unit(
        &self,
        unit: &OrdinaryRealmBootstrapCommitUnit,
        queued_at: DateTime<Utc>,
    ) -> ServiceResult<OrdinaryRealmBootstrapCommitOutcome> {
        unit.validate().map_err(|error| {
            ServiceError::SchemaViolation(format!("invalid ordinary Realm bootstrap unit: {error}"))
        })?;
        Ok(self
            .store()
            .admit_ordinary_realm_bootstrap_unit(unit, queued_at)
            .await?)
    }

    /// Commit a self bootstrap only while every signed Event still has its
    /// preflight producer authorization at the durable admission cut.
    pub async fn admit_self_ordinary_realm_bootstrap_unit(
        &self,
        unit: &OrdinaryRealmBootstrapCommitUnit,
        producer_guards: &[SelfProducerCommitGuard],
        queued_at: DateTime<Utc>,
    ) -> ServiceResult<OrdinaryRealmBootstrapCommitOutcome> {
        unit.validate().map_err(|error| {
            ServiceError::SchemaViolation(format!("invalid ordinary Realm bootstrap unit: {error}"))
        })?;
        if producer_guards.len() != unit.transactions.len() {
            return Err(ServiceError::SchemaViolation(
                "ordinary Realm bootstrap requires one producer guard per Event".to_owned(),
            ));
        }
        Ok(self
            .store()
            .admit_self_ordinary_realm_bootstrap_unit(unit, producer_guards, queued_at)
            .await?)
    }

    /// Sign the four consecutive genesis-stream Commits of a caller-authored
    /// Direct Conversation founding unit without publishing them. The caller
    /// has authenticated the founder's session and verified every producer.
    pub async fn prepare_direct_conversation_founding_unit(
        &self,
        submission: DirectConversationFoundingUnitSubmission,
        authority: &CurrentRealmAuthority,
        verification_method: DidUrl,
        signing_key: &SigningKey,
        committed_at: DateTime<Utc>,
    ) -> ServiceResult<coland_storage::DirectConversationFoundingCommitUnit> {
        let mut previous_head: Option<CommitStreamHead> = None;
        let mut transactions = Vec::with_capacity(4);
        for submitted in &submission.events {
            let producer_signer_fact = self
                .store()
                .prepare_account_device_signer_fact(&submitted.event, committed_at)
                .await?
                .map(Into::into);
            let commit = build_signed_event_commit(
                &submitted.event,
                authority,
                previous_head.as_ref(),
                verification_method.clone(),
                signing_key,
                committed_at,
                producer_signer_fact.as_ref(),
            )?;
            previous_head = Some(CommitStreamHead {
                stream_ref: commit.stream_ref.clone(),
                stream_position: commit.stream_position,
                commit_id: commit.commit_id.clone(),
            });
            transactions.push(AuthorityCommitTransaction {
                expected_authority: authority.clone(),
                event: submitted.event.clone(),
                commit,
                producer_signer_fact,
                mls_state: None,
                welcomes: Vec::new(),
                recipient_queue_capacity: self.recipient_queue_capacity,
            });
        }
        let transactions: [AuthorityCommitTransaction; 4] = transactions
            .try_into()
            .map_err(|_| ServiceError::Internal("four founding Commits expected".to_owned()))?;
        Ok(coland_storage::DirectConversationFoundingCommitUnit {
            submission,
            transactions,
        })
    }

    /// Admit a prepared Direct Conversation founding unit in one transaction.
    pub async fn admit_self_direct_conversation_founding_unit(
        &self,
        unit: &coland_storage::DirectConversationFoundingCommitUnit,
        producer_guards: &[SelfProducerCommitGuard; 4],
        queued_at: DateTime<Utc>,
    ) -> ServiceResult<coland_storage::DirectConversationFoundingCommitOutcome> {
        Ok(self
            .store()
            .admit_self_direct_conversation_founding_unit(unit, producer_guards, queued_at)
            .await?)
    }

    pub async fn materialize_peer_direct_conversation_founding_unit(
        &self,
        unit: &coland_storage::DirectConversationFoundingCommitUnit,
        evidence: &arkret_models_collaboration::objects::direct_conversation::DirectConversationFoundingAuthorityEvidence,
        local_station: &arkret_wire::DidCoreId,
        received_at: DateTime<Utc>,
    ) -> ServiceResult<arkret_models_collaboration::authority_commit::AggregateAcceptanceStatus>
    {
        Ok(self
            .store()
            .materialize_peer_direct_conversation_founding_unit(
                unit,
                evidence,
                local_station,
                received_at,
            )
            .await?)
    }

    /// The Direct Conversation admission table's verdict for `event` at one
    /// read-only cut of its Realm.
    pub async fn direct_conversation_admission(
        &self,
        event: &Event,
    ) -> ServiceResult<coland_storage::DirectConversationAdmissionCut> {
        Ok(self.store().direct_conversation_admission(event).await?)
    }

    pub async fn direct_conversation_pending_peer_claim_query(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> ServiceResult<Option<coland_storage::DirectConversationPendingPeerClaimQuery>> {
        Ok(self
            .store()
            .direct_conversation_pending_peer_claim_query(realm_id)
            .await?)
    }

    /// Atomically publish both PCR genesis Events and Commits, the identity
    /// resolution current result and the founding device current result.
    pub async fn admit_pcr_genesis_unit(
        &self,
        unit: &PcrGenesisCommitUnit,
        queued_at: DateTime<Utc>,
    ) -> ServiceResult<PcrGenesisCommitOutcome> {
        unit.validate().map_err(|error| {
            ServiceError::SchemaViolation(format!("invalid PCR genesis unit: {error}"))
        })?;
        Ok(self.store().admit_pcr_genesis_unit(unit, queued_at).await?)
    }

    /// Resolve an exact durable retry before checking a now-expired producer
    /// proof. This grants no fresh admission: altered bytes or a reused key
    /// fail as a duplicate conflict in the same receipt ledger as the writer.
    pub async fn pcr_genesis_replay(
        &self,
        submission: &PcrGenesisAdmissionInput,
        exact_request_body: &[u8],
    ) -> ServiceResult<
        Option<arkret_models_collaboration::principal_operations::PcrGenesisAdmissionOutcome>,
    > {
        submission
            .validate()
            .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
        if serde_json::from_slice::<PcrGenesisAdmissionInput>(exact_request_body)
            .ok()
            .as_ref()
            != Some(submission)
        {
            return Err(ServiceError::SchemaViolation(
                "PCR genesis exact request bytes differ from parsed submission".to_owned(),
            ));
        }
        Ok(self
            .store()
            .pcr_genesis_replay(submission, exact_request_body)
            .await?)
    }

    /// Prepare the two signed Station Commits before entering the durable unit.
    /// The caller authenticates the Account Authority relay and validates both
    /// producer proofs before invoking the matching admission method.
    pub fn prepare_pcr_genesis_unit(
        &self,
        submission: PcrGenesisAdmissionInput,
        exact_request_body: Vec<u8>,
        authority: &CurrentRealmAuthority,
        verification_method: DidUrl,
        signing_key: &SigningKey,
        committed_at: DateTime<Utc>,
    ) -> ServiceResult<PcrGenesisCommitUnit> {
        submission
            .validate()
            .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
        validate_pcr_genesis_producer_proofs(&submission)?;
        let events = [
            submission.genesis_unit.create(),
            submission.genesis_unit.founding_authorize(),
        ];
        let first = build_signed_event_commit(
            events[0],
            authority,
            None,
            verification_method.clone(),
            signing_key,
            committed_at,
            None,
        )?;
        let first_head = CommitStreamHead {
            stream_ref: first.stream_ref.clone(),
            stream_position: first.stream_position,
            commit_id: first.commit_id.clone(),
        };
        let second = build_signed_event_commit(
            events[1],
            authority,
            Some(&first_head),
            verification_method,
            signing_key,
            committed_at,
            None,
        )?;
        let transactions = [(events[0], first), (events[1], second)].map(|(event, commit)| {
            AuthorityCommitTransaction {
                expected_authority: authority.clone(),
                event: event.clone(),
                commit,
                producer_signer_fact: None,
                mls_state: None,
                welcomes: Vec::new(),
                recipient_queue_capacity: self.recipient_queue_capacity,
            }
        });
        let unit = PcrGenesisCommitUnit {
            submission,
            exact_request_body,
            transactions,
        };
        unit.validate()
            .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
        Ok(unit)
    }

    /// Prepare the complete ordered ordinary Realm bootstrap without writing
    /// anything. The HTTP authority adapter must first verify every producer
    /// proof and authorization at one authority cut, then pass this exact unit
    /// to `admit_ordinary_realm_bootstrap_unit` for atomic persistence.
    pub async fn prepare_ordinary_realm_bootstrap_unit(
        &self,
        submission: OrdinaryRealmBootstrapUnitSubmission,
        exact_request_body: Vec<u8>,
        authority: &CurrentRealmAuthority,
        verification_method: DidUrl,
        signing_key: &SigningKey,
        committed_at: DateTime<Utc>,
    ) -> ServiceResult<OrdinaryRealmBootstrapCommitUnit> {
        submission
            .validate()
            .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
        let genesis = &submission.events[0].event;
        if authority.realm_id != genesis.realm_id
            || authority.generation != 0
            || authority.authority_ref
                != arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                    genesis.event_id.clone(),
                )
        {
            return Err(ServiceError::SchemaViolation(
                "ordinary Realm bootstrap authority must be the genesis Event at generation zero"
                    .to_owned(),
            ));
        }
        let mut previous_head: Option<CommitStreamHead> = None;
        let mut transactions = Vec::with_capacity(submission.events.len());
        for (position, submitted) in submission.events.iter().enumerate() {
            let event = &submitted.event;
            let expected_scope = if position == 0 {
                arkret_wire::ScopeRef::RealmGenesis
            } else {
                arkret_wire::ScopeRef::Realm {
                    realm_id: genesis.realm_id.clone(),
                }
            };
            if event.scope_ref != expected_scope {
                return Err(ServiceError::SchemaViolation(
                    "ordinary Realm bootstrap Event must use the Realm stream".to_owned(),
                ));
            }
            let producer_signer_fact = self
                .store()
                .prepare_account_device_signer_fact(event, committed_at)
                .await?
                .map(Into::into);
            let commit = build_signed_event_commit(
                event,
                authority,
                previous_head.as_ref(),
                verification_method.clone(),
                signing_key,
                committed_at,
                producer_signer_fact.as_ref(),
            )?;
            previous_head = Some(CommitStreamHead {
                stream_ref: commit.stream_ref.clone(),
                stream_position: commit.stream_position,
                commit_id: commit.commit_id.clone(),
            });
            transactions.push(AuthorityCommitTransaction {
                expected_authority: authority.clone(),
                event: event.clone(),
                commit,
                producer_signer_fact,
                mls_state: None,
                welcomes: Vec::new(),
                recipient_queue_capacity: self.recipient_queue_capacity,
            });
        }
        let unit = OrdinaryRealmBootstrapCommitUnit {
            event_approvals: Vec::new(),
            submission,
            exact_request_body,
            transactions,
        };
        unit.validate()
            .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
        Ok(unit)
    }

    /// Sign the two PCR recovery Commits without publishing them. The caller
    /// passes this closed pair to `SecurityTransactionStore::commit_recovery_unit`;
    /// that one storage transaction rechecks the predecessor and installs both.
    pub fn prepare_recovery_unit_commits(
        &self,
        events: &[Event; 2],
        authority: &CurrentRealmAuthority,
        predecessor: &CommitStreamHead,
        verification_method: DidUrl,
        signing_key: &SigningKey,
        committed_at: DateTime<Utc>,
    ) -> ServiceResult<[AuthorityCommitTransaction; 2]> {
        let expected_stream = CommitStreamRef::Realm {
            realm_id: authority.realm_id.clone(),
        };
        if predecessor.stream_ref != expected_stream
            || events[0].kind != arkret_wire::EventKind::DeviceReanchor
            || events[1].kind != arkret_wire::EventKind::DeviceAuthorize
            || events.iter().any(|event| {
                event.realm_id != authority.realm_id
                    || event.scope_ref.realm_id() != &authority.realm_id
            })
        {
            return Err(ServiceError::SchemaViolation(
                "recovery Commit pair is not the exact PCR Realm Event unit".to_owned(),
            ));
        }
        let first = build_signed_event_commit(
            &events[0],
            authority,
            Some(predecessor),
            verification_method.clone(),
            signing_key,
            committed_at,
            None,
        )?;
        let first_head = CommitStreamHead {
            stream_ref: expected_stream,
            stream_position: first.stream_position,
            commit_id: first.commit_id.clone(),
        };
        let second = build_signed_event_commit(
            &events[1],
            authority,
            Some(&first_head),
            verification_method,
            signing_key,
            committed_at,
            None,
        )?;
        Ok([
            AuthorityCommitTransaction {
                expected_authority: authority.clone(),
                event: events[0].clone(),
                commit: first,
                producer_signer_fact: None,
                mls_state: None,
                welcomes: Vec::new(),
                recipient_queue_capacity: self.recipient_queue_capacity,
            },
            AuthorityCommitTransaction {
                expected_authority: authority.clone(),
                event: events[1].clone(),
                commit: second,
                producer_signer_fact: None,
                mls_state: None,
                welcomes: Vec::new(),
                recipient_queue_capacity: self.recipient_queue_capacity,
            },
        ])
    }

    /// Test fixture: commit one producer Event at its stream head through the
    /// kind-agnostic storage admission, with no domain admission unit. An
    /// exact retry of a committed Event returns its stored Commit.
    ///
    /// Production never admits an Event this way; it exists so tests can
    /// stand up committed state for kinds whose admission unit is not wired.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub async fn admit_event_for_test(
        &self,
        event: &Event,
        local_service_id: &DidCoreId,
        verification_method: DidUrl,
        signing_key: &SigningKey,
        committed_at: DateTime<Utc>,
    ) -> ServiceResult<AuthorityEventAdmissionOutcome> {
        if let Some(record) = self.store().committed_event(&event.event_id).await? {
            if record.event != *event {
                return Err(ServiceError::Conflict(
                    "event_id is already committed with different canonical content".to_owned(),
                ));
            }
            return Ok(AuthorityEventAdmissionOutcome::Duplicate(record.commit));
        }
        let transaction = self
            .prepare_self_event_transaction(
                event,
                local_service_id,
                verification_method,
                signing_key,
                committed_at,
            )
            .await?;
        match self
            .store()
            .admit_event_transaction(&transaction, committed_at)
            .await?
        {
            AuthorityCommitWriteOutcome::Committed => Ok(
                AuthorityEventAdmissionOutcome::Committed(transaction.commit),
            ),
            AuthorityCommitWriteOutcome::Duplicate => Err(ServiceError::Conflict(
                "a racing admission committed the same Event".to_owned(),
            )),
            AuthorityCommitWriteOutcome::StaleAuthority(_) => {
                Ok(AuthorityEventAdmissionOutcome::NotCurrentAuthority)
            }
        }
    }

    /// Prepare a single Event/RealmCommit for a larger atomic result unit.
    /// The caller must use the Event UoW, which rechecks the authority head and
    /// producer guard while installing current results and source effects.
    pub async fn prepare_self_event_transaction(
        &self,
        event: &Event,
        local_service_id: &DidCoreId,
        verification_method: DidUrl,
        signing_key: &SigningKey,
        committed_at: DateTime<Utc>,
    ) -> ServiceResult<AuthorityCommitTransaction> {
        self.prepare_self_event_transaction_with_signer_fact(
            event,
            local_service_id,
            verification_method,
            signing_key,
            committed_at,
            None,
        )
        .await
    }

    pub async fn prepare_self_event_transaction_with_signer_fact(
        &self,
        event: &Event,
        local_service_id: &DidCoreId,
        verification_method: DidUrl,
        signing_key: &SigningKey,
        committed_at: DateTime<Utc>,
        candidate: Option<&HistoricalProducerSignerFact>,
    ) -> ServiceResult<AuthorityCommitTransaction> {
        event.validate_for_submit_structural().map_err(|error| {
            ServiceError::SchemaViolation(format!("invalid producer Event: {error}"))
        })?;
        let authority = self
            .store()
            .current_authority(&event.realm_id)
            .await?
            .ok_or_else(|| ServiceError::Conflict("Realm authority is unavailable".to_owned()))?;
        if &authority.service_id != local_service_id {
            return Err(ServiceError::Conflict(
                "this Station is not the current Realm authority".to_owned(),
            ));
        }
        let stream_ref =
            CommitStreamRef::from_scope(&event.scope_ref, Some(event.realm_id.clone()))
                .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
        let head = self.store().stream_head(&stream_ref).await?;
        let producer_signer_fact = match candidate {
            Some(fact) => Some(fact.clone()),
            None => self
                .store()
                .prepare_account_device_signer_fact(event, committed_at)
                .await?
                .map(Into::into),
        };
        let commit = build_signed_event_commit(
            event,
            &authority,
            head.as_ref(),
            verification_method,
            signing_key,
            committed_at,
            producer_signer_fact.as_ref(),
        )?;
        let transaction = AuthorityCommitTransaction {
            expected_authority: authority,
            event: event.clone(),
            commit,
            producer_signer_fact,
            mls_state: None,
            welcomes: Vec::new(),
            recipient_queue_capacity: self.recipient_queue_capacity,
        };
        transaction.validate().map_err(|error| {
            ServiceError::SchemaViolation(format!("invalid authority transaction: {error}"))
        })?;
        Ok(transaction)
    }

    pub async fn prepare_registered_event_transactions(
        &self,
        events: &[arkret_wire::Event],
        local_service_id: &DidCoreId,
        verification_method: DidUrl,
        signing_key: &SigningKey,
        committed_at: DateTime<Utc>,
        facts: &[Option<HistoricalProducerSignerFact>],
    ) -> ServiceResult<Vec<AuthorityCommitTransaction>> {
        if events.is_empty() || events.len() != facts.len() {
            return Err(ServiceError::SchemaViolation(
                "registered unit has inconsistent slots".to_owned(),
            ));
        }
        let mut transactions: Vec<AuthorityCommitTransaction> = Vec::with_capacity(events.len());
        for (event, fact) in events.iter().zip(facts) {
            let mut transaction = self
                .prepare_self_event_transaction_with_signer_fact(
                    event,
                    local_service_id,
                    verification_method.clone(),
                    signing_key,
                    committed_at,
                    fact.as_ref(),
                )
                .await?;
            if let Some(previous) = transactions.last() {
                if transaction.expected_authority != previous.expected_authority
                    || transaction.commit.stream_ref != previous.commit.stream_ref
                {
                    return Err(ServiceError::Conflict(
                        "stale_authority: registered unit crossed a governing cut".to_owned(),
                    ));
                }
                transaction.commit = build_signed_event_commit(
                    event,
                    &transaction.expected_authority,
                    Some(&arkret_wire::CommitStreamHead {
                        stream_ref: previous.commit.stream_ref.clone(),
                        stream_position: previous.commit.stream_position,
                        commit_id: previous.commit.commit_id.clone(),
                    }),
                    verification_method.clone(),
                    signing_key,
                    committed_at,
                    transaction.producer_signer_fact.as_ref(),
                )?;
                transaction
                    .validate()
                    .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
            }
            transactions.push(transaction);
        }
        Ok(transactions)
    }

    /// Prepare the position-zero Commit of a Realm this Station would create
    /// by admitting `event`, its genesis. Only a unit that installs the new
    /// Realm authority in the same transaction may use it.
    pub fn prepare_genesis_transaction(
        &self,
        event: &Event,
        local_service_id: &DidCoreId,
        verification_method: DidUrl,
        signing_key: &SigningKey,
        committed_at: DateTime<Utc>,
    ) -> ServiceResult<AuthorityCommitTransaction> {
        event.validate_for_submit_structural().map_err(|error| {
            ServiceError::SchemaViolation(format!("invalid producer Event: {error}"))
        })?;
        if event.scope_ref != arkret_wire::ScopeRef::RealmGenesis {
            return Err(ServiceError::SchemaViolation(
                "a Realm genesis must use the genesis scope".to_owned(),
            ));
        }
        let authority = CurrentRealmAuthority {
            realm_id: event.realm_id.clone(),
            generation: 0,
            service_id: local_service_id.clone(),
            authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                event.event_id.clone(),
            ),
            last_handoff_ref: None,
        };
        let commit = build_signed_event_commit(
            event,
            &authority,
            None,
            verification_method,
            signing_key,
            committed_at,
            None,
        )?;
        let transaction = AuthorityCommitTransaction {
            expected_authority: authority,
            event: event.clone(),
            commit,
            producer_signer_fact: None,
            mls_state: None,
            welcomes: Vec::new(),
            recipient_queue_capacity: self.recipient_queue_capacity,
        };
        transaction.validate().map_err(|error| {
            ServiceError::SchemaViolation(format!("invalid authority transaction: {error}"))
        })?;
        Ok(transaction)
    }

    /// [`Self::prepare_self_event_transaction`] for an `ak.mls.genesis` or
    /// `ak.mls.commit`: the transaction also installs the public transition
    /// the caller verified and queues every verified Welcome of the Commit.
    #[allow(clippy::too_many_arguments)]
    pub async fn prepare_self_mls_transaction(
        &self,
        event: &Event,
        mls_state: coland_storage::MlsStateInstallation,
        welcomes: Vec<coland_storage::VerifiedMlsWelcome>,
        local_service_id: &DidCoreId,
        verification_method: DidUrl,
        signing_key: &SigningKey,
        committed_at: DateTime<Utc>,
    ) -> ServiceResult<AuthorityCommitTransaction> {
        self.prepare_self_mls_transaction_with_signer_fact(
            event,
            mls_state,
            welcomes,
            local_service_id,
            verification_method,
            signing_key,
            committed_at,
            None,
        )
        .await
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "Atomic MLS preparation binds state installation and authenticated signer facts to the Event."
    )]
    pub async fn prepare_self_mls_transaction_with_signer_fact(
        &self,
        event: &Event,
        mls_state: coland_storage::MlsStateInstallation,
        welcomes: Vec<coland_storage::VerifiedMlsWelcome>,
        local_service_id: &DidCoreId,
        verification_method: DidUrl,
        signing_key: &SigningKey,
        committed_at: DateTime<Utc>,
        candidate: Option<&HistoricalProducerSignerFact>,
    ) -> ServiceResult<AuthorityCommitTransaction> {
        event.validate_for_submit_structural().map_err(|error| {
            ServiceError::SchemaViolation(format!("invalid producer Event: {error}"))
        })?;
        let authority = self
            .store()
            .current_authority(&event.realm_id)
            .await?
            .ok_or_else(|| ServiceError::Conflict("Realm authority is unavailable".to_owned()))?;
        if &authority.service_id != local_service_id {
            return Err(ServiceError::Conflict(
                "this Station is not the current Realm authority".to_owned(),
            ));
        }
        let stream_ref =
            CommitStreamRef::from_scope(&event.scope_ref, Some(event.realm_id.clone()))
                .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
        let head = self.store().stream_head(&stream_ref).await?;
        let producer_signer_fact = match candidate {
            Some(fact) => Some(fact.clone()),
            None => self
                .store()
                .prepare_account_device_signer_fact(event, committed_at)
                .await?
                .map(Into::into),
        };
        let commit = build_signed_event_commit(
            event,
            &authority,
            head.as_ref(),
            verification_method,
            signing_key,
            committed_at,
            producer_signer_fact.as_ref(),
        )?;
        let transaction = AuthorityCommitTransaction {
            expected_authority: authority,
            event: event.clone(),
            commit,
            producer_signer_fact,
            mls_state: Some(mls_state),
            welcomes,
            recipient_queue_capacity: self.recipient_queue_capacity,
        };
        transaction.validate().map_err(|error| {
            ServiceError::SchemaViolation(format!("invalid MLS authority transaction: {error}"))
        })?;
        Ok(transaction)
    }

    /// Admit one `accepted_device` authorization relayed by this Station's
    /// Account Authority through the registered accepted-device unit.
    ///
    /// An exact retry of an accepted Event returns its stored Commit before
    /// any authority read; the unit itself rechecks the approving device,
    /// generation, target history and every signature at the locked PCR cut.
    pub async fn admit_applet_managed_device_authorization(
        &self,
        event: &Event,
        carrier: &coland_storage::AppletControlCarrier,
        local_service_id: &DidCoreId,
        verification_method: DidUrl,
        signing_key: &SigningKey,
    ) -> ServiceResult<AuthorityEventAdmissionOutcome> {
        event
            .validate_for_submit_structural()
            .map_err(|e| ServiceError::SchemaViolation(e.to_string()))?;
        // Prepare does not consult a Device for this Principal-signed branch.
        // The accepting unit proves the original Service even on replay.
        let transaction = self
            .prepare_self_event_transaction(
                event,
                local_service_id,
                verification_method,
                signing_key,
                Utc::now(),
            )
            .await?;
        Ok(
            match self
                .store()
                .admit_applet_managed_device_authorization(&transaction, carrier)
                .await?
            {
                coland_storage::AcceptedDeviceAuthorizationOutcome::Committed(commit) => {
                    AuthorityEventAdmissionOutcome::Committed(commit)
                }
                coland_storage::AcceptedDeviceAuthorizationOutcome::Duplicate(commit) => {
                    AuthorityEventAdmissionOutcome::Duplicate(commit)
                }
            },
        )
    }

    pub async fn admit_accepted_device_authorization(
        &self,
        event: &Event,
        local_service_id: &DidCoreId,
        verification_method: DidUrl,
        signing_key: &SigningKey,
        committed_at: DateTime<Utc>,
    ) -> ServiceResult<AuthorityEventAdmissionOutcome> {
        event.validate_for_submit_structural().map_err(|error| {
            ServiceError::SchemaViolation(format!("invalid producer Event: {error}"))
        })?;
        if let Some(record) = self.store().committed_event(&event.event_id).await? {
            if record.event != *event {
                return Err(ServiceError::Conflict(format!(
                    "{}: event_id is already committed with different canonical content",
                    coland_storage::ConflictCode::DuplicateConflict
                )));
            }
            return Ok(AuthorityEventAdmissionOutcome::Duplicate(record.commit));
        }
        let Some(authority) = self.store().current_authority(&event.realm_id).await? else {
            return Ok(AuthorityEventAdmissionOutcome::NotCurrentAuthority);
        };
        if &authority.service_id != local_service_id {
            return Ok(AuthorityEventAdmissionOutcome::NotCurrentAuthority);
        }
        let transaction = self
            .prepare_self_event_transaction(
                event,
                local_service_id,
                verification_method,
                signing_key,
                committed_at,
            )
            .await?;
        Ok(
            match self
                .store()
                .admit_accepted_device_authorization(&transaction, committed_at)
                .await?
            {
                coland_storage::AcceptedDeviceAuthorizationOutcome::Committed(commit) => {
                    AuthorityEventAdmissionOutcome::Committed(commit)
                }
                coland_storage::AcceptedDeviceAuthorizationOutcome::Duplicate(commit) => {
                    AuthorityEventAdmissionOutcome::Duplicate(commit)
                }
            },
        )
    }

    pub async fn current_authority(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> ServiceResult<Option<CurrentRealmAuthority>> {
        Ok(self.store().current_authority(realm_id).await?)
    }

    pub async fn sidecar_context_prepare_current(
        &self,
        realm: &arkret_wire::RealmId,
        controller: &arkret_wire::AccountId,
        context: &arkret_models_collaboration::sidecar_operations::SidecarContextRef,
    ) -> ServiceResult<
        Option<(
            arkret_wire::EventId,
            Option<coland_storage::AgentSidecarContextRecord>,
        )>,
    > {
        Ok(self
            .store()
            .sidecar_context_prepare_current(realm, controller, context)
            .await?)
    }

    pub async fn sidecar_participant_authority_cut(
        &self,
        realm_id: &arkret_wire::RealmId,
        sidecar_id: &arkret_wire::SidecarId,
        controller: &arkret_wire::AccountId,
    ) -> ServiceResult<
        Option<arkret_models_collaboration::agent_sidecar::SidecarParticipantAuthorityCut>,
    > {
        Ok(self
            .store()
            .sidecar_participant_authority_cut(realm_id, sidecar_id, controller)
            .await?)
    }

    /// Record a verified remote current authority of a Realm this Station
    pub async fn sidecar_access_cut(
        &self,
        realm: &arkret_wire::RealmId,
        sidecar: &arkret_wire::SidecarId,
        controller: &arkret_wire::AccountId,
        device: &arkret_wire::DeviceId,
    ) -> ServiceResult<
        Option<(
            arkret_models_collaboration::agent_sidecar::SidecarParticipantAuthorityCut,
            Vec<arkret_wire::DidCoreId>,
            Option<arkret_wire::MlsGroupCurrent>,
            bool,
        )>,
    > {
        Ok(self
            .store()
            .sidecar_access_cut(realm, sidecar, controller, device)
            .await?)
    }

    /// Record a verified remote current authority of a Realm this Station
    /// does not govern.
    pub async fn record_remote_authority(
        &self,
        authority: &CurrentRealmAuthority,
        local_service_id: &arkret_wire::DidCoreId,
    ) -> ServiceResult<()> {
        Ok(self
            .store()
            .record_remote_authority(authority, local_service_id)
            .await?)
    }

    /// Whether a frozen Realm fanout intent is still owed at the current cut.
    pub async fn realm_fanout_still_owed(
        &self,
        event: &Event,
        local_service_id: &arkret_wire::DidCoreId,
        peer: &arkret_wire::DidCoreId,
        witnesses: &[coland_storage::RealmFanoutAuthorityWitness],
        at: DateTime<Utc>,
    ) -> ServiceResult<bool> {
        Ok(self
            .store()
            .realm_fanout_still_owed(event, local_service_id, peer, witnesses, at)
            .await?)
    }

    /// Store one verified committed replica (`federation.md` §4.1.1).
    pub async fn install_committed_replica(
        &self,
        replica: &coland_storage::CommittedReplica,
    ) -> ServiceResult<coland_storage::CommittedReplicaOutcome> {
        Ok(self.store().install_committed_replica(replica).await?)
    }

    pub async fn install_committed_peer_replica(
        &self,
        replica: &coland_storage::CommittedReplica,
        receipt: &coland_storage::IdempotencyRecord,
    ) -> ServiceResult<(coland_storage::CommittedReplicaOutcome, bool)> {
        Ok(self
            .store()
            .install_committed_peer_replica(replica, receipt)
            .await?)
    }

    /// Queue the re-verified Welcomes of an exactly held replica Commit.
    pub async fn queue_replicated_welcomes(
        &self,
        event: &arkret_wire::Event,
        commit: &arkret_wire::RealmCommit,
        genesis_event_ref: Option<&arkret_wire::EventId>,
        welcomes: &[coland_storage::VerifiedMlsWelcome],
        at: chrono::DateTime<chrono::Utc>,
    ) -> ServiceResult<coland_storage::CommittedReplicaOutcome> {
        Ok(self
            .store()
            .queue_replicated_welcomes(event, commit, genesis_event_ref, welcomes, at)
            .await?)
    }

    /// Store one verified withheld Commit as a continuity-only chain node.
    pub async fn install_committed_chain_node(
        &self,
        node: &coland_storage::CommittedChainNode,
    ) -> ServiceResult<coland_storage::CommittedReplicaOutcome> {
        Ok(self.store().install_committed_chain_node(node).await?)
    }

    pub async fn replica_stream_anchor(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> ServiceResult<Option<coland_storage::ReplicaStreamAnchor>> {
        Ok(self.store().replica_stream_anchor(realm_id).await?)
    }

    pub async fn pending_franking_proofs(
        &self,
        receiver: &arkret_wire::DidCoreId,
    ) -> ServiceResult<Vec<coland_storage::PendingFrankingProof>> {
        Ok(self.store().pending_franking_proofs(receiver).await?)
    }

    pub async fn fix_franking_proof(
        &self,
        prepared: &coland_storage::PreparedFrankingProof,
    ) -> ServiceResult<arkret_wire::Event> {
        Ok(self.store().fix_franking_proof(prepared).await?)
    }

    pub async fn complete_franking_proof(
        &self,
        realm: &arkret_wire::RealmId,
        target: &arkret_wire::EventId,
        proof_event: &arkret_wire::EventId,
    ) -> ServiceResult<()> {
        Ok(self
            .store()
            .complete_franking_proof(realm, target, proof_event)
            .await?)
    }

    pub async fn replica_stream_has_hosted_member(
        &self,
        stream: &arkret_wire::CommitStreamRef,
        local_service_id: &arkret_wire::DidCoreId,
    ) -> ServiceResult<Option<bool>> {
        Ok(self
            .store()
            .replica_stream_has_hosted_member(stream, local_service_id)
            .await?)
    }

    pub async fn require_held_replica_write_lifecycle(
        &self,
        event: &arkret_wire::Event,
    ) -> ServiceResult<()> {
        Ok(self
            .store()
            .require_held_replica_write_lifecycle(event)
            .await?)
    }

    pub async fn replica_anchor_for_stream(
        &self,
        stream: &arkret_wire::CommitStreamRef,
    ) -> ServiceResult<Option<coland_storage::ReplicaStreamAnchor>> {
        Ok(self.store().replica_anchor_for_stream(stream).await?)
    }

    pub async fn accepted_own_leave_bound_result(
        &self,
        event: &arkret_wire::Event,
        commit: &arkret_wire::RealmCommit,
        account: &arkret_wire::AccountId,
        local_service: &arkret_wire::DidCoreId,
    ) -> ServiceResult<bool> {
        Ok(self
            .store()
            .accepted_own_leave_bound_result(event, commit, account, local_service)
            .await?)
    }

    pub async fn circle_views_for_actor(
        &self,
        realm_id: &arkret_wire::RealmId,
        actor: &arkret_wire::ActorId,
    ) -> ServiceResult<Vec<arkret_models_collaboration::governance::circle::CircleView>> {
        Ok(self.store().circle_views_for_actor(realm_id, actor).await?)
    }

    pub async fn circle_reads_for_actor(
        &self,
        realm_id: &arkret_wire::RealmId,
        actor: &arkret_wire::ActorId,
    ) -> ServiceResult<Vec<arkret_models_collaboration::governance::circle::CircleReadView>> {
        Ok(self.store().circle_reads_for_actor(realm_id, actor).await?)
    }

    pub async fn circle_view_for_actor(
        &self,
        circle_id: &arkret_wire::CircleId,
        actor: &arkret_wire::ActorId,
    ) -> ServiceResult<Option<arkret_models_collaboration::governance::circle::CircleView>> {
        Ok(self.store().circle_view_for_actor(circle_id, actor).await?)
    }

    pub async fn circle_read_for_actor(
        &self,
        circle_id: &arkret_wire::CircleId,
        actor: &arkret_wire::ActorId,
    ) -> ServiceResult<Option<arkret_models_collaboration::governance::circle::CircleReadView>>
    {
        Ok(self.store().circle_read_for_actor(circle_id, actor).await?)
    }

    pub async fn replica_authorization_head(
        &self,
        stream: &arkret_wire::CommitStreamRef,
    ) -> ServiceResult<Option<arkret_wire::CommitStreamHead>> {
        Ok(self.store().replica_authorization_head(stream).await?)
    }

    pub async fn replica_bootstrap_readers(
        &self,
        stream: &arkret_wire::CommitStreamRef,
        local_service: &arkret_wire::DidCoreId,
    ) -> ServiceResult<Vec<(arkret_wire::AccountId, arkret_wire::RealmCommit)>> {
        Ok(self
            .store()
            .replica_bootstrap_readers(stream, local_service)
            .await?)
    }

    pub async fn pending_replica_streams(
        &self,
    ) -> ServiceResult<Vec<arkret_wire::CommitStreamRef>> {
        Ok(self.store().pending_replica_streams().await?)
    }

    pub async fn pending_replica_stream_anchors(&self) -> ServiceResult<Vec<arkret_wire::RealmId>> {
        Ok(self.store().pending_replica_stream_anchors().await?)
    }

    /// Install a verified bootstrap snapshot as a pending replica stream's
    /// typed current (`federation.md` §4.1.1).
    pub async fn install_replica_anchor(
        &self,
        install: &coland_storage::ReplicaAnchorInstall,
    ) -> ServiceResult<()> {
        Ok(self.store().install_replica_anchor(install).await?)
    }

    pub async fn held_stream_head_commit(
        &self,
        stream_ref: &CommitStreamRef,
    ) -> ServiceResult<Option<arkret_wire::RealmCommit>> {
        Ok(self.store().held_stream_head_commit(stream_ref).await?)
    }

    pub async fn member_station_bootstrap_material(
        &self,
        realm_id: &arkret_wire::RealmId,
        account: &arkret_wire::AccountId,
        membership_commit_id: &RealmCommitId,
    ) -> ServiceResult<Option<coland_storage::RealmStateSnapshotMaterial>> {
        Ok(self
            .store()
            .member_station_bootstrap_material(realm_id, account, membership_commit_id)
            .await?)
    }

    pub async fn member_station_bootstrap_floor(
        &self,
        realm_id: &arkret_wire::RealmId,
        account: &arkret_wire::AccountId,
        membership_commit_id: &RealmCommitId,
    ) -> ServiceResult<Option<u64>> {
        Ok(self
            .store()
            .member_station_bootstrap_floor(realm_id, account, membership_commit_id)
            .await?)
    }

    pub async fn stream_head(
        &self,
        stream_ref: &CommitStreamRef,
    ) -> ServiceResult<Option<CommitStreamHead>> {
        Ok(self.store().stream_head(stream_ref).await?)
    }

    pub async fn realm_stream_heads(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> ServiceResult<Option<coland_storage::RealmStreamCut>> {
        Ok(self.store().realm_stream_heads(realm_id).await?)
    }

    pub async fn committed_event(
        &self,
        event_id: &arkret_wire::EventId,
    ) -> ServiceResult<Option<coland_storage::CommittedEventRecord>> {
        Ok(self.store().committed_event(event_id).await?)
    }

    pub async fn historical_self_pcr_producer_signer_key(
        &self,
        realm_id: &arkret_wire::RealmId,
        selector: &arkret_models_identity::SignerKeyQuerySelector,
        recipient: &arkret_wire::AccountId,
    ) -> ServiceResult<Option<arkret_models_identity::SignerKeyQueryOutcome>> {
        Ok(self
            .store()
            .historical_self_pcr_producer_signer_key(realm_id, selector, recipient)
            .await?)
    }

    pub async fn historical_producer_signer_key(
        &self,
        realm_id: &arkret_wire::RealmId,
        selector: &arkret_models_identity::SignerKeyQuerySelector,
    ) -> crate::ServiceResult<Option<arkret_models_identity::SignerKeyQueryOutcome>> {
        Ok(self
            .store()
            .historical_producer_signer_key(realm_id, selector)
            .await?)
    }

    pub async fn signal_recipient_realms(
        &self,
        actor: &arkret_wire::ActorId,
    ) -> ServiceResult<Vec<arkret_wire::RealmId>> {
        Ok(self.store().signal_recipient_realms(actor).await?)
    }

    pub async fn signal_scope_authority(
        &self,
        query: coland_storage::SignalScopeAuthorityQuery<'_>,
    ) -> ServiceResult<Option<coland_storage::SignalScopeAuthority>> {
        Ok(self.store().signal_scope_authority(query).await?)
    }

    pub async fn committed_event_by_commit_id(
        &self,
        commit_id: &RealmCommitId,
    ) -> ServiceResult<Option<coland_storage::CommittedEventRecord>> {
        Ok(self.store().committed_event_by_commit_id(commit_id).await?)
    }

    pub async fn current_mimi_room_binding(
        &self,
        room_uri: &arkret_wire::MimiRoomUri,
    ) -> ServiceResult<Option<coland_storage::MimiRoomBindingCurrentRecord>> {
        Ok(self.store().current_mimi_room_binding(room_uri).await?)
    }

    pub async fn agent_owner_direct_scope(
        &self,
        realm: &arkret_wire::RealmId,
        agent: &arkret_wire::AccountId,
        controller: &arkret_wire::AccountId,
    ) -> ServiceResult<bool> {
        Ok(self
            .store()
            .agent_owner_direct_scope(realm, agent, controller)
            .await?)
    }

    pub async fn current_agent_result(
        &self,
        realm_id: &arkret_wire::RealmId,
        selector: &arkret_wire::CurrentSelector,
    ) -> ServiceResult<Option<arkret_wire::TypedCurrentRow>> {
        Ok(self
            .store()
            .current_agent_result(realm_id, selector)
            .await?)
    }

    pub async fn realm_state_snapshot_material(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> ServiceResult<Option<coland_storage::RealmStateSnapshotMaterial>> {
        Ok(self.store().realm_state_snapshot_material(realm_id).await?)
    }

    pub async fn realm_state_snapshot_material_for_account(
        &self,
        realm_id: &arkret_wire::RealmId,
        account: &arkret_wire::AccountId,
    ) -> ServiceResult<Option<coland_storage::RealmStateSnapshotMaterial>> {
        Ok(self
            .store()
            .realm_state_snapshot_material_for_account(realm_id, account)
            .await?)
    }

    pub async fn account_continuation_heads_covered(
        &self,
        realm_id: &arkret_wire::RealmId,
        account: &arkret_wire::AccountId,
        minimum_heads: &[arkret_wire::CommitStreamHead],
    ) -> ServiceResult<bool> {
        Ok(self
            .store()
            .account_continuation_heads_covered(realm_id, account, minimum_heads)
            .await?)
    }

    pub async fn direct_conversation_replica_cut(
        &self,
        realm_id: &arkret_wire::RealmId,
        account: &arkret_wire::AccountId,
        pair_key: &arkret_wire::Hash,
        participants: &[arkret_wire::ActorId; 2],
    ) -> ServiceResult<Option<coland_storage::DirectConversationReplicaCut>> {
        Ok(self
            .store()
            .direct_conversation_replica_cut(realm_id, account, pair_key, participants)
            .await?)
    }

    pub async fn object_projection_lists_for_actor(
        &self,
        realm_id: &arkret_wire::RealmId,
        actor: &arkret_wire::ActorId,
        include_terminal: bool,
    ) -> ServiceResult<
        Option<(
            arkret_models_collaboration::objects::query_projection::ProjectionSpaceList,
            arkret_models_collaboration::objects::query_projection::ProjectionStrandList,
        )>,
    > {
        Ok(self
            .store()
            .object_projection_lists_for_actor(realm_id, actor, include_terminal)
            .await?)
    }

    pub async fn object_projection_delivery_for_actor(
        &self,
        realm_id: &arkret_wire::RealmId,
        actor: &arkret_wire::ActorId,
        include_terminal: bool,
    ) -> ServiceResult<
        Option<(
            arkret_models_collaboration::objects::query_projection::ProjectionSpaceList,
            arkret_models_collaboration::objects::query_projection::ProjectionStrandList,
            arkret_models_collaboration::sync_frames::current_results::AccountCurrentView,
        )>,
    > {
        Ok(self
            .store()
            .object_projection_delivery_for_actor(realm_id, actor, include_terminal)
            .await?)
    }

    pub async fn realm_lifecycle_for_actor(
        &self,
        realm: &arkret_wire::RealmId,
        actor: &arkret_wire::ActorId,
    ) -> ServiceResult<
        Option<arkret_models_collaboration::governance::realm_governance::RealmLifecycleView>,
    > {
        Ok(self.store().realm_lifecycle_for_actor(realm, actor).await?)
    }

    pub async fn realm_export_for_actor(
        &self,
        realm_id: &arkret_wire::RealmId,
        actor: &arkret_wire::ActorId,
        station: &arkret_wire::DidCoreId,
    ) -> ServiceResult<
        Option<(
            arkret_models_collaboration::governance::realm_governance::RealmExport,
            Vec<arkret_wire::CommittedEventView>,
        )>,
    > {
        Ok(self
            .store()
            .realm_export_for_actor(realm_id, actor, station)
            .await?)
    }

    /// The effective scope of a Strand `actor` currently reads from durable
    /// current, governed here or held as a verified replica.
    pub async fn visible_strand_scope_for_actor(
        &self,
        realm_id: &arkret_wire::RealmId,
        strand_id: &arkret_wire::StrandId,
        actor: &arkret_wire::ActorId,
    ) -> ServiceResult<Option<arkret_wire::ScopeRef>> {
        Ok(self
            .store()
            .visible_strand_scope_for_actor(realm_id, strand_id, actor)
            .await?)
    }

    /// Materialize, tenure-check, sign, capacity-check and issue one complete
    /// Snapshot to `account` in a single durable cut held by the store. The
    /// signature is made with the Station's current service method only while
    /// that cut proves `issuer` holds the Realm's governing term.
    pub async fn issue_realm_state_snapshot_for_account(
        &self,
        realm_id: &arkret_wire::RealmId,
        account: &arkret_wire::AccountId,
        issuer: &DidCoreId,
        verification_method: &DidUrl,
        signing_key: &SigningKey,
        created_at: DateTime<Utc>,
    ) -> ServiceResult<Option<RealmStateSnapshot>> {
        let sign = |material: &coland_storage::RealmStateSnapshotMaterial| {
            build_signed_realm_state_snapshot(
                material,
                verification_method.clone(),
                signing_key,
                created_at,
            )
            .map_err(|error| coland_storage::PersistenceError::Internal(error.to_string()))
        };
        Ok(self
            .store()
            .issue_realm_state_snapshot_for_account(realm_id, account, issuer, &sign)
            .await?)
    }

    /// Sign only the complete exact-scope material proved for this Device by
    /// the owning store's current PCR/business transaction.
    pub async fn issue_realm_state_snapshot_for_applet_device(
        &self,
        endpoint: &coland_storage::AppletManagedDeviceScopeGuard,
        issuer: &DidCoreId,
        credential_expires_at: DateTime<Utc>,
        verification_method: &DidUrl,
        signing_key: &SigningKey,
        created_at: DateTime<Utc>,
    ) -> ServiceResult<Option<RealmStateSnapshot>> {
        let sign = |material: &coland_storage::RealmStateSnapshotMaterial| {
            build_signed_realm_state_snapshot(
                material,
                verification_method.clone(),
                signing_key,
                created_at,
            )
            .map_err(|error| coland_storage::PersistenceError::Internal(error.to_string()))
        };
        Ok(self
            .store()
            .issue_realm_state_snapshot_for_applet_device(
                endpoint,
                issuer,
                credential_expires_at,
                &sign,
            )
            .await?)
    }

    /// Archive the original governing object after peer authority and
    /// cryptographic verification, without granting local signing authority.
    /// Return the retained original selected by the store's same-cut policy.
    pub async fn install_verified_account_snapshot(
        &self,
        account: &arkret_wire::AccountId,
        issuer: &DidCoreId,
        snapshot: &RealmStateSnapshot,
        minimum: &coland_storage::RealmStateSnapshotMaterial,
    ) -> ServiceResult<RealmStateSnapshot> {
        coland_storage::enforce_inline_realm_state_snapshot_capacity(snapshot)?;
        Ok(self
            .store()
            .install_verified_account_snapshot(account, issuer, snapshot, minimum)
            .await?)
    }

    /// Return the exact original object issued to `account`, after the store
    /// re-proves its disclosure at the read cut. A current head is never a
    /// substitute for a missing or no-longer-disclosable reference.
    pub async fn issued_realm_state_snapshot(
        &self,
        realm_id: &arkret_wire::RealmId,
        account: &arkret_wire::AccountId,
        snapshot_id: &arkret_wire::RealmSnapshotId,
        issuer: &DidCoreId,
    ) -> ServiceResult<Option<RealmStateSnapshot>> {
        Ok(self
            .store()
            .issued_realm_state_snapshot(realm_id, account, snapshot_id, issuer)
            .await?)
    }

    /// Freeze one Account Realm-stream window at a single proved cut; see
    /// [`coland_storage::AuthorityCommitStore::freeze_account_realm_window`].
    /// The frozen head is issued to the Account with the Station's current
    /// service method, exactly like `/head`.
    pub async fn freeze_account_realm_window(
        &self,
        request: &coland_storage::AccountRealmWindowRequest,
        verification_method: &DidUrl,
        signing_key: &SigningKey,
        created_at: DateTime<Utc>,
    ) -> ServiceResult<Option<coland_storage::AccountRealmWindow>> {
        let sign = |material: &coland_storage::RealmStateSnapshotMaterial| {
            build_signed_realm_state_snapshot(
                material,
                verification_method.clone(),
                signing_key,
                created_at,
            )
            .map_err(|error| coland_storage::PersistenceError::Internal(error.to_string()))
        };
        Ok(self
            .store()
            .freeze_account_realm_window(request, &sign)
            .await?)
    }

    /// The reserved basis of a frozen window, or `None` once the by-ref
    /// guarantee is lost and the stream must be re-emitted as preview only.
    pub async fn account_window_basis(
        &self,
        realm_id: &arkret_wire::RealmId,
        account: &arkret_wire::AccountId,
        window_cursor: &str,
        stream_ref: &arkret_wire::CommitStreamRef,
        issuer: &DidCoreId,
        now_ms: i64,
    ) -> ServiceResult<
        Option<arkret_models_collaboration::sync_frames::account_sync::StreamWindowStartBasis>,
    > {
        Ok(self
            .store()
            .account_window_basis(realm_id, account, window_cursor, stream_ref, issuer, now_ms)
            .await?)
    }

    /// Keyset page over one independent commit stream.
    ///
    /// Paging uses a `stream_position` keyset inside one [`CommitStreamRef`].
    /// The direction selects either the forward or backward side of a position;
    /// `truncated` indicates whether another page exists in that direction.
    pub async fn scan_stream(
        &self,
        request: &StreamScanRequest,
    ) -> ServiceResult<StreamScanOutcome> {
        request.validate().map_err(|error| {
            crate::ServiceError::SchemaViolation(format!("invalid stream scan request: {error}"))
        })?;
        let outcome = self.store().scan_stream(request).await?;
        outcome.validate_for_request(request).map_err(|error| {
            crate::ServiceError::SchemaViolation(format!("invalid stream scan outcome: {error}"))
        })?;
        Ok(outcome)
    }

    /// `ak.self.committed_event.read.scan.v1`: authorization, readable
    /// interval, and page at one governing read cut. See
    /// [`coland_storage::AuthorityCommitStore::scan_stream_for_account`].
    pub async fn scan_stream_for_account(
        &self,
        request: &StreamScanRequest,
        account: &arkret_wire::AccountId,
        issuer: &DidCoreId,
    ) -> ServiceResult<coland_storage::AccountStreamScan> {
        request.validate().map_err(|error| {
            crate::ServiceError::SchemaViolation(format!("invalid stream scan request: {error}"))
        })?;
        let scan = self
            .store()
            .scan_stream_for_account(request, account, issuer)
            .await?;
        if let coland_storage::AccountStreamScan::Page(outcome) = &scan {
            outcome.validate_for_request(request).map_err(|error| {
                crate::ServiceError::Internal(format!("invalid stream scan outcome: {error}"))
            })?;
        }
        Ok(scan)
    }

    /// `ak.peer.committed_event.read.scan.v1`: the authenticated peer's
    /// replication right, interval, and page at one governing read cut. See
    /// [`coland_storage::AuthorityCommitStore::scan_stream_for_peer`].
    /// The committed Event `event_id` when `peer` holds the replication right
    /// on it at this governing cut (`federation.md` §4.1.1).
    pub async fn committed_event_for_peer(
        &self,
        event_id: &arkret_wire::EventId,
        peer: &DidCoreId,
        issuer: &DidCoreId,
    ) -> ServiceResult<Option<arkret_wire::CommittedEventFullView>> {
        Ok(self
            .store()
            .committed_event_for_peer(event_id, peer, issuer)
            .await?)
    }

    /// One repeatable-read authorization cut for a member's exact MLS
    /// Genesis material request. The caller's session Actor binding is
    /// checked by the self route before this storage read.
    pub async fn mls_member_group_state_material_read(
        &self,
        request: &arkret_models_collaboration::mls_group_state_material::MlsGroupStateMaterialRequestBody,
        issuer: &DidCoreId,
        source_peer: Option<&DidCoreId>,
    ) -> ServiceResult<coland_storage::MlsMemberGroupStateMaterialRead> {
        Ok(self
            .store()
            .mls_member_group_state_material_read(request, issuer, source_peer)
            .await?)
    }

    /// Install a peer-authenticated recipient Add proof against the exact
    /// accepted MLS Commit, Welcome and consumed Proposal at one PG cut.
    pub async fn install_mls_add_authority_attestation(
        &self,
        verified: &coland_storage::VerifiedMlsAddAuthorityAttestation,
        issuer: &DidCoreId,
    ) -> ServiceResult<arkret_models_collaboration::mls_roster_authority::MlsAttestAddOutcome> {
        Ok(self
            .store()
            .install_mls_add_authority_attestation(verified, issuer)
            .await?)
    }

    pub async fn mls_recipient_attestation(
        &self,
        commit: &arkret_wire::EventId,
        welcome: &arkret_wire::MlsWelcomeDeliveryId,
    ) -> ServiceResult<
        Option<arkret_models_collaboration::mls_roster_authority::MlsAttestAddRequestBody>,
    > {
        Ok(self
            .store()
            .mls_recipient_attestation(commit, welcome)
            .await?)
    }

    pub async fn pending_mls_recipient_attestations(
        &self,
        limit: usize,
    ) -> ServiceResult<
        Vec<arkret_models_collaboration::mls_roster_authority::MlsAttestAddRequestBody>,
    > {
        Ok(self
            .store()
            .pending_mls_recipient_attestations(limit)
            .await?)
    }

    pub async fn acknowledge_mls_recipient_attestation(
        &self,
        request: &arkret_models_collaboration::mls_roster_authority::MlsAttestAddRequestBody,
        digest: &arkret_wire::Hash,
        at: DateTime<Utc>,
    ) -> ServiceResult<()> {
        Ok(self
            .store()
            .acknowledge_mls_recipient_attestation(request, digest, at)
            .await?)
    }

    /// `ak.self.committed_event.resource.get.v1` on an ordinary Realm's Realm
    /// stream. See
    /// [`coland_storage::AuthorityCommitStore::committed_event_for_member`].
    pub async fn committed_event_for_member(
        &self,
        event_id: &arkret_wire::EventId,
        caller: &arkret_wire::ActorId,
        issuer: &DidCoreId,
    ) -> ServiceResult<coland_storage::MemberCommittedEventRead> {
        Ok(self
            .store()
            .committed_event_for_member(event_id, caller, issuer)
            .await?)
    }

    pub async fn scan_stream_for_peer(
        &self,
        request: &StreamScanRequest,
        peer: &DidCoreId,
        issuer: &DidCoreId,
    ) -> ServiceResult<coland_storage::PeerStreamScan> {
        request.validate().map_err(|error| {
            crate::ServiceError::SchemaViolation(format!("invalid stream scan request: {error}"))
        })?;
        let scan = self
            .store()
            .scan_stream_for_peer(request, peer, issuer)
            .await?;
        if let coland_storage::PeerStreamScan::Page(outcome) = &scan {
            outcome.validate_for_request(request).map_err(|error| {
                crate::ServiceError::Internal(format!("invalid stream scan outcome: {error}"))
            })?;
        }
        Ok(scan)
    }

    /// `ak.self.realm.read.streams.v1`: stream set, heads and floors at one
    /// governing read cut. See
    /// [`coland_storage::AuthorityCommitStore::list_realm_streams_for_account`].
    pub async fn list_realm_streams_for_account(
        &self,
        realm_id: &arkret_wire::RealmId,
        account: &arkret_wire::AccountId,
        issuer: &DidCoreId,
    ) -> ServiceResult<coland_storage::AccountRealmStreamList> {
        let listing = self
            .store()
            .list_realm_streams_for_account(realm_id, account, issuer)
            .await?;
        if let coland_storage::AccountRealmStreamList::Listed(streams) = &listing {
            arkret_wire::RealmStreamList::validate_rows(realm_id, streams).map_err(|error| {
                crate::ServiceError::Internal(format!("invalid realm stream list: {error}"))
            })?;
        }
        Ok(listing)
    }

    pub async fn realm_stream_subscription_cut(
        &self,
        realm_id: &arkret_wire::RealmId,
        account: &arkret_wire::AccountId,
        issuer: &DidCoreId,
    ) -> ServiceResult<coland_storage::AccountRealmStreamAuthorizationCut> {
        let cut = self
            .store()
            .realm_stream_subscription_cut(realm_id, account, issuer)
            .await?;
        if let coland_storage::AccountRealmStreamList::Listed(streams) = &cut.listing {
            arkret_wire::RealmStreamList::validate_rows(realm_id, streams)
                .map_err(|e| crate::ServiceError::Internal(e.to_string()))?;
            if cut
                .history_digest
                .as_ref()
                .is_none_or(|digest| digest.is_empty())
            {
                return Err(crate::ServiceError::Internal(
                    "subscription cut omits history binding".to_owned(),
                ));
            }
        }
        Ok(cut)
    }

    /// `ak.self.current_results.read.exact.v1` at one governing read cut. The
    /// answer is checked against the exact request and the cut's generation
    /// before it can leave the Station.
    pub async fn exact_current_result_for_account(
        &self,
        request: &ExactCurrentResultsReadRequestBody,
        account: &arkret_wire::AccountId,
        issuer: &DidCoreId,
    ) -> ServiceResult<coland_storage::SelfExactCurrentRead<ExactCurrentResultsReadOutcome>> {
        request.validate().map_err(|error| {
            crate::ServiceError::SchemaViolation(format!(
                "invalid exact current-result request: {error}"
            ))
        })?;
        let read = self
            .store()
            .exact_current_result_for_account(request, account, issuer)
            .await?;
        if let coland_storage::SelfExactCurrentRead::Answer(outcome) = &read {
            let generation = match outcome {
                ExactCurrentResultsReadOutcome::Present {
                    governance_generation,
                    ..
                }
                | ExactCurrentResultsReadOutcome::NeverWritten {
                    governance_generation,
                    ..
                } => *governance_generation,
            };
            outcome
                .validate_for_request(request, generation)
                .map_err(|error| {
                    crate::ServiceError::Internal(format!(
                        "invalid exact current-result outcome: {error}"
                    ))
                })?;
        }
        Ok(read)
    }

    /// `ak.self.strand.watch.read.current.v1` at one governing read cut.
    pub async fn strand_watch_current_for_account(
        &self,
        request: &StrandWatchCurrentRequestBody,
        account: &arkret_wire::AccountId,
        issuer: &DidCoreId,
    ) -> ServiceResult<coland_storage::SelfExactCurrentRead<StrandWatchCurrentOutcome>> {
        let read = self
            .store()
            .strand_watch_current_for_account(request, account, issuer)
            .await?;
        if let coland_storage::SelfExactCurrentRead::Answer(outcome) = &read {
            outcome.validate_for_request(request).map_err(|error| {
                crate::ServiceError::Internal(format!("invalid watch-current outcome: {error}"))
            })?;
        }
        Ok(read)
    }

    /// Visibility and accepted media service anchor behind
    /// `ak.self.media_service_binding.read.resolve.v1`.
    pub async fn media_service_anchor_for_account(
        &self,
        realm_id: &arkret_wire::RealmId,
        account: &arkret_wire::AccountId,
        issuer: &DidCoreId,
    ) -> ServiceResult<coland_storage::MediaServiceAnchorRead> {
        Ok(self
            .store()
            .media_service_anchor_for_account(realm_id, account, issuer)
            .await?)
    }

    pub async fn stage_agent_control_source(
        &self,
        full: &arkret_wire::CommittedEventFullView,
        dependency: &arkret_models_identity::AgentSignerDependency,
        history: &arkret_models_identity::AuthenticatedServiceResolution,
    ) -> ServiceResult<()> {
        self.store()
            .stage_agent_control_source(full, dependency, history)
            .await
            .map_err(Into::into)
    }

    pub async fn prepare_agent_origin_state(
        &self,
        event: &arkret_wire::Event,
        at: chrono::DateTime<chrono::Utc>,
    ) -> ServiceResult<arkret_models_identity::AgentAuthorityState> {
        Ok(self.store().prepare_agent_origin_state(event, at).await?)
    }

    pub async fn agent_origin_controller_gate_request(
        &self,
        event: &arkret_wire::Event,
        evidence: &arkret_models_identity::AgentAuthorityState,
    ) -> ServiceResult<arkret_wire::RequestId> {
        Ok(self
            .store()
            .agent_origin_controller_gate_request(event, evidence)
            .await?)
    }

    pub async fn retain_agent_forward_evidence_at_same_cut(
        &self,
        event: &arkret_wire::Event,
        evidence: &arkret_models_identity::AgentProducerEvidence,
        at: chrono::DateTime<chrono::Utc>,
    ) -> ServiceResult<()> {
        Ok(self
            .store()
            .retain_agent_forward_evidence_at_same_cut(event, evidence, at)
            .await?)
    }

    pub async fn handoff_originals(
        &self,
        realm_id: &arkret_wire::RealmId,
        through_generation: u64,
    ) -> ServiceResult<Vec<arkret_wire::CommittedEventFullView>> {
        // A retry still verifies the outgoing frozen cut even when the new
        // Station has already appended its own accepted Events.
        let mut originals = self.store().handoff_originals(realm_id).await?;
        originals.retain(|full| full.commit.governance_generation <= through_generation);
        Ok(originals)
    }

    pub async fn admit_pcr_governance_change(
        &self,
        transaction: &AuthorityCommitTransaction,
    ) -> ServiceResult<AuthorityCommitWriteOutcome> {
        Ok(self
            .store()
            .admit_pcr_governance_change(transaction)
            .await?)
    }

    pub async fn install_handoff(&self, request: &AuthorityHandoffRequest) -> ServiceResult<()> {
        request.validate_new_handoff().map_err(|error| {
            crate::ServiceError::SchemaViolation(format!("invalid authority handoff: {error}"))
        })?;
        let held = self
            .store()
            .authority_handoffs(&request.handoff.realm_id)
            .await?;
        let prior = request
            .authority_bundle
            .authority_transitions
            .iter()
            .take(
                request
                    .authority_bundle
                    .authority_transitions
                    .len()
                    .saturating_sub(1),
            )
            .map(|transition| transition.handoff.clone())
            .collect::<Vec<_>>();
        if held != prior
            && held
                != request
                    .authority_bundle
                    .authority_transitions
                    .iter()
                    .map(|transition| transition.handoff.clone())
                    .collect::<Vec<_>>()
        {
            return Err(crate::ServiceError::SchemaViolation(
                "handoff requires the complete exact installed authority history".into(),
            ));
        }
        let originals = self
            .handoff_originals(&request.handoff.realm_id, request.handoff.from_generation)
            .await?;
        request
            .validate_imported_signer_facts(&originals)
            .map_err(|error| {
                crate::ServiceError::SchemaViolation(format!(
                    "incomplete authority handoff: {error}"
                ))
            })?;
        self.store()
            .install_handoff_with_private_state(
                &request.handoff,
                &request.final_stream_heads,
                &request.snapshot,
                request.pcr_private_state.as_ref(),
            )
            .await?;
        Ok(())
    }

    pub async fn latest_snapshot(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> ServiceResult<Option<RealmStateSnapshot>> {
        Ok(self.store().latest_snapshot(realm_id).await?)
    }

    /// Build the bundle at one consistent authority cut. A concurrent Commit
    /// that moves the Realm stream head, or a handoff, while the bundle is
    /// assembled only means that cut is gone: the bundle is rebuilt at the
    /// newer cut. Persistent churn is a retryable `temporarily_unavailable`,
    /// never a conflict the caller could not resolve.
    pub async fn authority_bundle(
        &self,
        request: &AuthorityBundleRequest,
        local_service_id: &DidCoreId,
        current_route_record: serde_json::Value,
        verification_method: DidUrl,
        signing_key: &SigningKey,
        issued_at: DateTime<Utc>,
    ) -> ServiceResult<RealmAuthorityBundle> {
        request
            .validate()
            .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
        for _ in 0..AUTHORITY_BUNDLE_CUT_ATTEMPTS {
            if let Some(bundle) = self
                .authority_bundle_at_current_cut(
                    request,
                    local_service_id,
                    current_route_record.clone(),
                    verification_method.clone(),
                    signing_key,
                    issued_at,
                )
                .await?
            {
                return Ok(bundle);
            }
        }
        Err(ServiceError::Conflict(format!(
            "{}: Realm authority kept changing while building the bundle",
            coland_storage::ConflictCode::TemporarilyUnavailable
        )))
    }

    /// One bundle attempt; `None` when the authority cut moved underneath it.
    async fn authority_bundle_at_current_cut(
        &self,
        request: &AuthorityBundleRequest,
        local_service_id: &DidCoreId,
        current_route_record: serde_json::Value,
        verification_method: DidUrl,
        signing_key: &SigningKey,
        issued_at: DateTime<Utc>,
    ) -> ServiceResult<Option<RealmAuthorityBundle>> {
        let authority = self
            .store()
            .current_authority(&request.realm_id)
            .await?
            .ok_or_else(|| ServiceError::NotFound("Realm authority is unavailable".to_owned()))?;
        if &authority.service_id != local_service_id {
            return Err(ServiceError::NotFound(
                "no current authority bundle is available for this Realm here".to_owned(),
            ));
        }
        let stream_ref = CommitStreamRef::Realm {
            realm_id: request.realm_id.clone(),
        };
        let scan = self
            .scan_stream(&StreamScanRequest {
                realm_id: request.realm_id.clone(),
                stream_ref: stream_ref.clone(),
                direction: StreamScanDirection::After(None),
                limit: 1,
            })
            .await?;
        let first = scan.committed_events.first().ok_or_else(|| {
            ServiceError::NotFound("Realm genesis Commit is unavailable".to_owned())
        })?;
        let genesis_commit = first.commit().clone();
        let genesis_event = self
            .store()
            .committed_event(&genesis_commit.event_ref)
            .await?
            .ok_or_else(|| ServiceError::Internal("Realm genesis Event is missing".to_owned()))?
            .event;
        let handoffs = self.store().authority_handoffs(&request.realm_id).await?;
        let mut authority_transitions = Vec::with_capacity(handoffs.len());
        for handoff in handoffs {
            let pair = self
                .store()
                .committed_event(&handoff.change_event_ref)
                .await?
                .ok_or_else(|| {
                    ServiceError::Internal("authority change Event is missing".to_owned())
                })?;
            if pair.commit.commit_id != handoff.change_commit_id {
                return Err(ServiceError::Internal(
                    "authority change Commit does not match handoff".to_owned(),
                ));
            }
            authority_transitions.push(RealmAuthorityTransition {
                change_event: pair.event,
                change_commit: pair.commit,
                handoff,
            });
        }
        let realm_stream_head = self
            .store()
            .stream_head(&stream_ref)
            .await?
            .ok_or_else(|| ServiceError::Internal("Realm stream head is missing".to_owned()))?;
        let issued_at = arkret_canonical::normalize_timestamp_canonical(issued_at);
        let expires_at = issued_at + chrono::Duration::seconds(60);
        let assertion_body = RealmAuthorityAssertionUnsignedBody {
            realm_id: &request.realm_id,
            current_generation: authority.generation,
            current_service_id: &authority.service_id,
            last_handoff_ref: &authority.last_handoff_ref,
            realm_stream_head: &realm_stream_head,
            nonce: &request.nonce,
            expires_at,
        };
        let signature = arkret_signatures::detached_object::sign_detached_object(
            &assertion_body,
            DetachedSignatureContext::RealmAuthorityCurrentAssertion,
            verification_method,
            issued_at,
            signing_key,
        )
        .map_err(|error| ServiceError::Internal(error.to_string()))?;
        let bundle = RealmAuthorityBundle {
            realm_id: request.realm_id.clone(),
            genesis_event,
            genesis_commit,
            authority_transitions,
            current_generation: authority.generation,
            current_service_id: authority.service_id.clone(),
            current_route_record,
            realm_stream_head: realm_stream_head.clone(),
            bundle_issued_at: issued_at,
            current_assertion: RealmAuthorityCurrentAssertion {
                realm_id: request.realm_id.clone(),
                current_generation: authority.generation,
                current_service_id: authority.service_id.clone(),
                last_handoff_ref: authority.last_handoff_ref.clone(),
                realm_stream_head,
                nonce: request.nonce.clone(),
                expires_at,
                signature,
            },
        };
        bundle
            .validate_for_request(request, issued_at)
            .map_err(|error| ServiceError::Internal(error.to_string()))?;
        if self.store().current_authority(&request.realm_id).await? != Some(authority)
            || self.store().stream_head(&stream_ref).await?
                != Some(bundle.realm_stream_head.clone())
        {
            return Ok(None);
        }
        Ok(Some(bundle))
    }
}

/// Bundle builds attempted before a moving authority cut is reported as
/// `temporarily_unavailable`.
const AUTHORITY_BUNDLE_CUT_ATTEMPTS: usize = 4;

/// Wrap one `authority_forward` admission result in its closed branch.
fn authority_forward_outcome(
    outcome: AuthoritySubmitOutcome,
) -> ServiceResult<PeerAuthoritySubmitOutcome> {
    let outcome = PeerAuthoritySubmitOutcome::AuthorityForward(PeerAuthorityForwardOutcome {
        branch: AuthorityForwardBranch::AuthorityForward,
        outcome: arkret_models_collaboration::authority_commit::PeerAuthorityForwardOutcomeValue::Ordinary(outcome),
    });
    outcome.validate().map_err(|error| {
        ServiceError::Internal(format!(
            "authority_forward produced an invalid outcome: {error}"
        ))
    })?;
    Ok(outcome)
}

/// HTTP-facing protocol port.
///
/// The concrete Station implementation performs authorization and signing.
/// Self submissions carry the authenticated session through the service
/// boundary so authorization cannot be inferred from the Event body alone.
/// HTTP validates/deserializes current SDK DTOs before delegating.
#[derive(Clone, Debug, PartialEq)]
pub struct AuthenticatedPeerContext {
    /// Identity obtained from the verified peer HTTP Message Signature and
    /// its bound source-service-id header, never from the submission body.
    pub source_service_id: DidCoreId,
    /// Authenticated HTTP request metadata, never supplied by the peer body.
    pub replay_receipt: Option<coland_storage::IdempotencyRecord>,
}

#[async_trait]
pub trait AuthorityProtocolPort: Send + Sync {
    /// The caller supplies the mounted native transport identity, never a Session.
    /// Each implemented domain still owns its source, current and atomic gates.
    async fn submit_managed_device(
        &self,
        _metadata: &arkret_models_integration::AppletManagedDeviceMetadata,
        _authority: &coland_storage::AppletManagedDeviceAuthority,
        _request: SelfAuthoritySubmitRequest,
    ) -> ServiceResult<SelfAuthoritySubmitOutcome> {
        Err(ServiceError::UnsupportedEventKind(
            "managed Device submission has no accepting domain unit".into(),
        ))
    }

    async fn submit_self_event(
        &self,
        session: &crate::identity::SessionIdentityState,
        request: EventAdmissionSubmission,
    ) -> ServiceResult<AuthoritySubmitOutcome>;

    /// An accepted MLS result is forbidden until the MLS state, every Welcome,
    /// and its authority Commit are visible through one transaction.
    async fn submit_self_mls(
        &self,
        session: &crate::identity::SessionIdentityState,
        request: MlsCommitSubmission,
    ) -> ServiceResult<AuthoritySubmitOutcome>;

    async fn submit_self_direct_conversation_founding(
        &self,
        _session: &crate::identity::SessionIdentityState,
        _request: DirectConversationFoundingUnitSubmission,
    ) -> ServiceResult<DirectConversationFoundingAcceptanceOutcome> {
        Err(crate::ServiceError::internal(
            "Direct Conversation founding is not connected to the authority transaction path",
        ))
    }

    async fn submit_self_ordinary_realm_bootstrap(
        &self,
        _session: &crate::identity::SessionIdentityState,
        _request: OrdinaryRealmBootstrapUnitSubmission,
        _exact_request_body: &[u8],
    ) -> ServiceResult<OrdinaryRealmBootstrapAcceptanceOutcome> {
        Err(crate::ServiceError::internal(
            "ordinary Realm bootstrap is not connected to the authority transaction path",
        ))
    }

    async fn submit_self_audit_pair(
        &self,
        _session: &crate::identity::SessionIdentityState,
        _request: arkret_models_collaboration::authority_commit::AuditPairedEventUnitSubmission,
    ) -> ServiceResult<
        arkret_models_collaboration::authority_commit::AuditPairedEventAcceptanceOutcome,
    > {
        Err(crate::ServiceError::Conflict(
            "failed_precondition: audit pair admission unavailable".to_owned(),
        ))
    }

    async fn submit_peer_audit_pair(
        &self,
        _peer: &AuthenticatedPeerContext,
        _request: arkret_models_collaboration::authority_commit::PeerAuthorityForwardAtomicRequest,
    ) -> ServiceResult<
        arkret_models_collaboration::authority_commit::AuditPairedEventAcceptanceOutcome,
    > {
        Err(crate::ServiceError::Conflict(
            "failed_precondition: audit pair forwarding unavailable".to_owned(),
        ))
    }

    async fn replicate_peer_audit_pair(
        &self,
        _peer: &AuthenticatedPeerContext,
        _request: arkret_models_collaboration::authority_commit::AuditPairedEventFederationSubmission,
    ) -> ServiceResult<
        arkret_models_collaboration::authority_commit::AuditPairedEventAcceptanceOutcome,
    > {
        Err(crate::ServiceError::Conflict(
            "revision_unavailable: audit pair materialization unavailable".to_owned(),
        ))
    }

    async fn submit_self_membership_compensation(
        &self,
        _session: &crate::identity::SessionIdentityState,
        _request: MembershipCompensationUnitSubmission,
    ) -> ServiceResult<MembershipCompensationAcceptanceOutcome> {
        Err(crate::ServiceError::internal(
            "membership compensation is not connected to the authority transaction path",
        ))
    }

    /// Closed self-endpoint dispatcher. It validates both sides at the service
    /// boundary so a handler cannot return the response branch for a different
    /// request or degrade an aggregate into a partial ordinary outcome.
    async fn submit_self(
        &self,
        session: &crate::identity::SessionIdentityState,
        request: SelfAuthoritySubmitRequest,
        exact_request_body: &[u8],
    ) -> ServiceResult<SelfAuthoritySubmitOutcome> {
        request.validate().map_err(|error| {
            crate::ServiceError::SchemaViolation(format!(
                "invalid self authority submission: {error}"
            ))
        })?;
        let outcome = match request.clone() {
            SelfAuthoritySubmitRequest::Event(value) => {
                SelfAuthoritySubmitOutcome::Ordinary(self.submit_self_event(session, value).await?)
            }
            SelfAuthoritySubmitRequest::MlsCommit(value) => {
                SelfAuthoritySubmitOutcome::Ordinary(self.submit_self_mls(session, value).await?)
            }
            SelfAuthoritySubmitRequest::OrdinaryRealmBootstrap(value) => {
                SelfAuthoritySubmitOutcome::OrdinaryRealmBootstrap(
                    self.submit_self_ordinary_realm_bootstrap(session, value, exact_request_body)
                        .await?,
                )
            }
            SelfAuthoritySubmitRequest::DirectConversationFounding(value) => {
                SelfAuthoritySubmitOutcome::DirectConversationFounding(
                    self.submit_self_direct_conversation_founding(session, value)
                        .await?,
                )
            }
            SelfAuthoritySubmitRequest::AuditPairedEvent(value) => {
                SelfAuthoritySubmitOutcome::AuditPairedEvent(
                    self.submit_self_audit_pair(session, value).await?,
                )
            }
            SelfAuthoritySubmitRequest::MembershipCompensation(value) => {
                SelfAuthoritySubmitOutcome::MembershipCompensation(
                    self.submit_self_membership_compensation(session, value)
                        .await?,
                )
            }
        };
        outcome.validate_for_request(&request).map_err(|error| {
            crate::ServiceError::Internal(format!(
                "self authority dispatcher produced an invalid outcome: {error}"
            ))
        })?;
        Ok(outcome)
    }

    /// `authority_forward` of one ordinary Event to this governance Station.
    ///
    /// The implementation owns the whole branch order: an exact duplicate
    /// Event returns its original outcome first, then the Event-decided
    /// `producer_device_evidence` rule is enforced, then a cross-Station
    /// human-device producer is verified from that evidence before admission.
    async fn submit_peer_authority_forward_event(
        &self,
        _peer: &AuthenticatedPeerContext,
        _request: PeerAuthorityForwardEventRequest,
    ) -> ServiceResult<AuthoritySubmitOutcome> {
        Err(crate::ServiceError::internal(
            "authority_forward admission is not connected to this Station",
        ))
    }

    /// `authority_forward` of one MLS Commit submission; the Commit Event's
    /// producer decides the evidence rule exactly as for an ordinary Event.
    async fn submit_peer_authority_forward_mls(
        &self,
        _peer: &AuthenticatedPeerContext,
        _request: PeerAuthorityForwardMlsRequest,
    ) -> ServiceResult<AuthoritySubmitOutcome> {
        Err(crate::ServiceError::internal(
            "authority_forward MLS admission is not connected to this Station",
        ))
    }

    async fn submit_peer_committed_replication(
        &self,
        _peer: &AuthenticatedPeerContext,
        _request: PeerCommittedReplicationRequest,
    ) -> ServiceResult<PeerCommittedReplicationOutcome> {
        Err(crate::ServiceError::internal(
            "committed replication is not connected to durable replica persistence",
        ))
    }

    async fn submit_peer_direct_conversation_founding(
        &self,
        _peer: &AuthenticatedPeerContext,
        _request: DirectConversationFoundingFederationSubmission,
    ) -> ServiceResult<DirectConversationFoundingAcceptanceOutcome> {
        Err(crate::ServiceError::internal(
            "peer Direct Conversation founding is not connected to atomic materialization",
        ))
    }

    async fn submit_peer_membership_compensation(
        &self,
        _peer: &AuthenticatedPeerContext,
        _request: MembershipCompensationFederationSubmission,
    ) -> ServiceResult<MembershipCompensationAcceptanceOutcome> {
        Err(crate::ServiceError::internal(
            "peer membership compensation is not connected to atomic materialization",
        ))
    }

    /// Dispatch the closed peer carrier.
    ///
    /// `authority_forward` validates inside its branch, because an exact
    /// duplicate Event answers with its original outcome before the evidence
    /// rule and freshness are judged (device-lifecycle §8.2.2). Its outcome is
    /// therefore checked for shape and branch only. The other branches are
    /// validated as a whole before any work.
    async fn submit_peer(
        &self,
        peer: &AuthenticatedPeerContext,
        request: PeerAuthoritySubmitRequest,
    ) -> ServiceResult<PeerAuthoritySubmitOutcome> {
        match request {
            PeerAuthoritySubmitRequest::AuthorityForwardEvent(value) => {
                let outcome = self
                    .submit_peer_authority_forward_event(peer, value)
                    .await?;
                return authority_forward_outcome(outcome);
            }
            PeerAuthoritySubmitRequest::AuthorityForwardAtomic(value) => {
                let outcome = self.submit_peer_audit_pair(peer, value).await?;
                outcome
                    .validate()
                    .map_err(|error| ServiceError::Internal(error.to_string()))?;
                return Ok(PeerAuthoritySubmitOutcome::AuthorityForward(PeerAuthorityForwardOutcome { branch: AuthorityForwardBranch::AuthorityForward, outcome: arkret_models_collaboration::authority_commit::PeerAuthorityForwardOutcomeValue::AuditPairedEvent(outcome) }));
            }
            PeerAuthoritySubmitRequest::AuthorityForwardMls(value) => {
                let outcome = self.submit_peer_authority_forward_mls(peer, value).await?;
                return authority_forward_outcome(outcome);
            }
            _ => {}
        }
        request.validate().map_err(|error| {
            crate::ServiceError::SchemaViolation(format!(
                "invalid peer authority submission: {error}"
            ))
        })?;
        let outcome = match request.clone() {
            PeerAuthoritySubmitRequest::AuthorityForwardEvent(_)
            | PeerAuthoritySubmitRequest::AuthorityForwardMls(_)
            | PeerAuthoritySubmitRequest::AuthorityForwardAtomic(_) => {
                return Err(crate::ServiceError::internal(
                    "authority_forward is dispatched before whole-request validation",
                ));
            }
            PeerAuthoritySubmitRequest::CommittedReplication(value) => {
                PeerAuthoritySubmitOutcome::CommittedReplication(
                    self.submit_peer_committed_replication(peer, value).await?,
                )
            }
            PeerAuthoritySubmitRequest::RegisteredAtomicUnit(value) => {
                let branch = value.branch;
                let unit = match value.unit {
                    PeerRegisteredAtomicUnit::DirectConversationFounding(unit) => {
                        PeerRegisteredAtomicUnitOutcomeValue::DirectConversationFounding(
                            self.submit_peer_direct_conversation_founding(peer, unit)
                                .await?,
                        )
                    }
                    PeerRegisteredAtomicUnit::AuditPairedEvent(unit) => {
                        PeerRegisteredAtomicUnitOutcomeValue::AuditPairedEvent(
                            self.replicate_peer_audit_pair(peer, unit).await?,
                        )
                    }
                    PeerRegisteredAtomicUnit::MembershipCompensation(unit) => {
                        PeerRegisteredAtomicUnitOutcomeValue::MembershipCompensation(
                            self.submit_peer_membership_compensation(peer, unit).await?,
                        )
                    }
                };
                PeerAuthoritySubmitOutcome::RegisteredAtomicUnit(PeerRegisteredAtomicUnitOutcome {
                    branch,
                    outcome: unit,
                })
            }
        };
        outcome.validate_for_request(&request).map_err(|error| {
            crate::ServiceError::Internal(format!(
                "peer authority dispatcher produced an invalid outcome: {error}"
            ))
        })?;
        Ok(outcome)
    }

    /// `ak.self.committed_event.read.scan.v1` for the authenticated Account.
    async fn scan_stream_for_account(
        &self,
        account: &arkret_wire::AccountId,
        request: StreamScanRequest,
    ) -> ServiceResult<coland_storage::AccountStreamScan>;

    /// `ak.peer.committed_event.read.scan.v1` for the authenticated peer
    /// Station; its identity comes only from the verified transport.
    async fn scan_stream_for_peer(
        &self,
        peer: &AuthenticatedPeerContext,
        request: StreamScanRequest,
    ) -> ServiceResult<coland_storage::PeerStreamScan>;

    async fn authority_bundle(
        &self,
        request: AuthorityBundleRequest,
    ) -> ServiceResult<RealmAuthorityBundle>;

    async fn install_authority_handoff(
        &self,
        peer: &AuthenticatedPeerContext,
        request: AuthorityHandoffRequest,
    ) -> ServiceResult<RealmAuthorityHandoff>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_commit_identity_and_signature_cover_the_closed_body() {
        let genesis_event =
            arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x11; 32]);
        let realm_id = arkret_wire::RealmId::from_event_id(&genesis_event);
        let service_id =
            arkret_wire::DidCoreId::new("ak:did_core:web:station.example".to_owned()).unwrap();
        let event = arkret_wire::test_support::raw_event_at(
            arkret_wire::EventKind::MessageCreate.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            arkret_wire::DidCoreId::new("ak:did_core:web:alice.example".to_owned()).unwrap(),
            service_id.clone(),
            serde_json::json!({"body": "atomic admission"}),
            chrono::DateTime::parse_from_rfc3339("2026-09-20T08:00:00.123Z")
                .unwrap()
                .with_timezone(&Utc),
        )
        .unwrap();
        let authority = CurrentRealmAuthority {
            realm_id,
            generation: 3,
            service_id,
            authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                genesis_event,
            ),
            last_handoff_ref: None,
        };
        let signing_key = SigningKey::from_bytes(&[0x44; 32]);
        let committed_at = chrono::DateTime::parse_from_rfc3339("2026-09-20T08:00:01.456789Z")
            .unwrap()
            .with_timezone(&Utc);
        let commit = build_signed_event_commit(
            &event,
            &authority,
            None,
            DidUrl::new("did:web:station.example#notary-key").unwrap(),
            &signing_key,
            committed_at,
            None,
        )
        .unwrap();

        assert_eq!(commit.stream_position, 0);
        assert!(commit.previous_commit_ref.is_none());
        assert_eq!(commit.committed_at.timestamp_subsec_micros(), 456_000);
        let unsigned = arkret_canonical::unsigned_value(&commit, &["signature"]).unwrap();
        assert_eq!(
            commit.signature.signed_digest,
            arkret_signatures::detached_object::detached_object_signed_digest(&unsigned).unwrap(),
            "the signature must seal the exact wire Commit minus signature"
        );
        let replay = build_signed_event_commit(
            &event,
            &authority,
            None,
            DidUrl::new("did:web:station.example#notary-key").unwrap(),
            &signing_key,
            committed_at,
            None,
        )
        .unwrap();
        assert_eq!(commit, replay, "same closed input must produce one Commit");

        let whole_second = chrono::DateTime::parse_from_rfc3339("2026-09-20T08:00:02Z")
            .unwrap()
            .with_timezone(&Utc);
        let commit = build_signed_event_commit(
            &event,
            &authority,
            None,
            DidUrl::new("did:web:station.example#notary-key").unwrap(),
            &signing_key,
            whole_second,
            None,
        )
        .unwrap();
        let unsigned = arkret_canonical::unsigned_value(&commit, &["signature"]).unwrap();
        assert_eq!(
            commit.signature.signed_digest,
            arkret_signatures::detached_object::detached_object_signed_digest(&unsigned).unwrap(),
            "whole-second Commit must seal the exact wire body"
        );
    }

    #[test]
    fn signed_snapshot_identity_and_signature_cover_the_closed_body() {
        let genesis_event =
            arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x21; 32]);
        let realm_id = arkret_wire::RealmId::from_event_id(&genesis_event);
        let stream_ref = arkret_wire::CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        };
        let material = coland_storage::RealmStateSnapshotMaterial {
            realm_id: realm_id.clone(),
            governance_generation: 4,
            visible_stream_heads: vec![arkret_wire::CommitStreamHead {
                stream_ref: stream_ref.clone(),
                stream_position: 7,
                commit_id: arkret_wire::RealmCommitId::from_digest([0x22; 32]),
            }],
            current_state_entries: vec![arkret_wire::TypedCurrentRow::Value {
                selector: arkret_wire::CurrentSelector::RealmPolicyBundle,
                source_stream_ref: stream_ref.clone(),
                revision: arkret_wire::CurrentRevision {
                    commit_id: arkret_wire::RealmCommitId::from_digest([0x22; 32]),
                    stream_position: 7,
                },
                value: serde_json::json!({"policy": "closed"}),
            }],
            retention_and_history_floor: arkret_wire::RetentionAndHistoryFloor {
                history_access: arkret_wire::HistoryAccess::AllHistoryForCurrentMembers,
                stream_floors: vec![arkret_wire::StreamHistoryFloor {
                    stream_ref,
                    oldest_position: 2,
                }],
            },
        };
        let signing_key = SigningKey::from_bytes(&[0x45; 32]);
        let created_at = chrono::DateTime::parse_from_rfc3339("2026-09-22T08:00:01.456789Z")
            .unwrap()
            .with_timezone(&Utc);
        let snapshot = build_signed_realm_state_snapshot(
            &material,
            DidUrl::new("did:web:station.example#notary-key").unwrap(),
            &signing_key,
            created_at,
        )
        .unwrap();

        assert_eq!(snapshot.created_at.timestamp_subsec_micros(), 456_000);
        let identity = RealmSnapshotIdentityBody {
            realm_id: &snapshot.realm_id,
            governance_generation: snapshot.governance_generation,
            visible_stream_heads: &snapshot.visible_stream_heads,
            current_state_entries: &snapshot.current_state_entries,
            retention_and_history_floor: &snapshot.retention_and_history_floor,
            created_at: snapshot.created_at,
        };
        let expected_id =
            arkret_wire::RealmSnapshotId::from_digest(arkret_canonical::sha256_bytes(
                arkret_canonical::canonical_json_bytes(&identity).unwrap(),
            ));
        assert_eq!(snapshot.snapshot_id, expected_id);
        let unsigned = arkret_canonical::unsigned_value(&snapshot, &["signature"]).unwrap();
        assert_eq!(
            snapshot.signature.signed_digest,
            arkret_signatures::detached_object::detached_object_signed_digest(&unsigned).unwrap(),
            "the signature must seal the exact wire Snapshot minus signature"
        );

        let whole_second = chrono::DateTime::parse_from_rfc3339("2026-09-22T08:00:02Z")
            .unwrap()
            .with_timezone(&Utc);
        let snapshot = build_signed_realm_state_snapshot(
            &material,
            DidUrl::new("did:web:station.example#notary-key").unwrap(),
            &signing_key,
            whole_second,
        )
        .unwrap();
        let unsigned = arkret_canonical::unsigned_value(&snapshot, &["signature"]).unwrap();
        assert_eq!(
            snapshot.signature.signed_digest,
            arkret_signatures::detached_object::detached_object_signed_digest(&unsigned).unwrap(),
            "whole-second Snapshot must seal the exact wire body"
        );
    }
}
