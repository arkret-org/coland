use arkret_wire::OpaqueLocalId;

use super::{AccountPk, AgentPrincipalRecord, PersistenceResult, Value, async_trait};
/// Private vault coordinates; no disclosure bytes are stored in PostgreSQL.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentScopeCustodyRef {
    pub key_ref: String,
    pub content_digest: arkret_wire::Hash,
}

/// Original accepted sources verified when the confidential presentation arrived.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentScopeAcceptedBinding {
    pub controller_account: arkret_wire::AccountId,
    pub initial_resolution: arkret_models_identity::ResolutionCommitment,
    pub binding_resolution: arkret_models_identity::ResolutionCommitment,
    pub provision_ref: arkret_wire::CommittedEventRef,
    pub pcr_genesis_ref: arkret_wire::CommittedEventRef,
    pub requested_scope_digest: arkret_wire::Hash,
    pub verified_at: chrono::DateTime<chrono::Utc>,
}

/// Trusted process-only output of the verifier-private custody port. It cannot
/// be deserialized from a request or serialized into a public response.
#[derive(Clone)]
pub struct VerifiedAgentScopeEvidence {
    custody_ref: AgentScopeCustodyRef,
    command: arkret_models_collaboration::agent_scope::AgentKeyPairRequestBody,
    accepted_binding: AgentScopeAcceptedBinding,
    runtime_key_binding_digest: String,
    request_digest: String,
    accepted_authorization_ref: arkret_wire::CommittedEventRef,
}
impl std::fmt::Debug for VerifiedAgentScopeEvidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifiedAgentScopeEvidence([REDACTED])")
    }
}
impl VerifiedAgentScopeEvidence {
    /// Called only after vault integrity and the durable exact receipt match.
    pub fn from_verified_custody(
        custody_ref: AgentScopeCustodyRef,
        command: arkret_models_collaboration::agent_scope::AgentKeyPairRequestBody,
        accepted_binding: AgentScopeAcceptedBinding,
        runtime_key_binding_digest: String,
        request_digest: String,
        accepted_authorization_ref: arkret_wire::CommittedEventRef,
    ) -> Self {
        Self {
            custody_ref,
            command,
            accepted_binding,
            runtime_key_binding_digest,
            request_digest,
            accepted_authorization_ref,
        }
    }
    pub fn accepted_authorization_ref(&self) -> &arkret_wire::CommittedEventRef {
        &self.accepted_authorization_ref
    }
    pub fn custody_ref(&self) -> &AgentScopeCustodyRef {
        &self.custody_ref
    }
    pub fn command(&self) -> &arkret_models_collaboration::agent_scope::AgentKeyPairRequestBody {
        &self.command
    }
    pub fn accepted_binding(&self) -> &AgentScopeAcceptedBinding {
        &self.accepted_binding
    }
    pub fn runtime_key_binding_digest(&self) -> &str {
        &self.runtime_key_binding_digest
    }
    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }
}

/// AKP-0010 — agent participation policy persistence. Controller
/// selections (`ak.agent.participation.v1`) and the governance ceiling
/// projection are stored as JSON records. A selection record contains only
/// its agent/scope identity, CAS version and five independent selection bits;
/// governance policy is evaluated separately at action time.
#[async_trait]
pub trait AgentParticipationStore: Send + Sync {
    /// Atomically replace a controller selection when the stored version
    /// equals `expected_version`. Returns false without writing on mismatch.
    async fn compare_and_swap_selection(
        &self,
        record: Value,
        expected_version: u64,
    ) -> PersistenceResult<bool>;
    /// All selections for one agent.
    async fn list_selections(&self, agent_id: &str) -> PersistenceResult<Vec<Value>>;
    /// Ceiling rows whose scope_key is in `scope_keys`.
    async fn ceilings_for_scope_keys(&self, scope_keys: &[String])
    -> PersistenceResult<Vec<Value>>;
}
/// AKP-0008 — Agent principal persistence (provision /
/// list / get / lifecycle). The typed persistence model keeps database column
/// names, nullability, UUIDs, and timestamps checked at compile time. The wire
/// boundary projects it into `agent_projection`, dropping internal columns —
/// see `routing::identity::agents::agent_projection_from_record`.
#[derive(Clone, Debug)]
pub struct AgentRuntimeActivation {
    pub agent_id: String,
    pub approval_request_id: OpaqueLocalId,
    pub runtime_key_binding_digest: String,
    pub pairing_request_id: OpaqueLocalId,
    pub paired_request_digest: String,
    pub authorized_event_ref: String,
    pub authorized_verification_method: String,
    pub authorized_public_key_digest: String,
    /// Exact controller Event retained with its producer proof.
    pub frozen_authorize_event: arkret_wire::Event,
    pub scope_custody_ref: Option<AgentScopeCustodyRef>,
    /// Authority-signed commit that admitted `frozen_authorize_event`,
    /// together with the terminal lifecycle it settled. One `RealmCommit`
    /// carries exactly one `event_ref`, so this names both the Event and the
    /// commit that made it the activation precondition.
    pub authorize_ref: arkret_wire::CommittedEventRef,
    pub status: arkret_models_collaboration::agent_operations::AgentLifecycleState,
    pub authorized_key_event: arkret_wire::Event,
    pub signer_resolution_evidence_ref: Option<arkret_wire::SignerEvidenceRef>,
    pub current_signer_evidence: Option<
        arkret_models_identity::authenticated_signer_resolution_evidence::AuthenticatedSignerResolutionEvidence,
    >,
    pub authorized_at: chrono::DateTime<chrono::Utc>,
}
#[derive(Clone, Debug)]
pub struct AgentPairingCommitIntent {
    pub agent_id: String,
    pub approval_request_id: OpaqueLocalId,
    pub runtime_key_binding_digest: String,
    pub pairing_request_id: OpaqueLocalId,
    pub request_digest: String,
    pub authorize_event_id: String,
    pub key_authorization_event: arkret_wire::Event,
    pub scope_custody_ref: Option<AgentScopeCustodyRef>,
}
#[derive(Clone, Debug)]
pub struct AgentRuntimeApprovalWrite {
    pub agent_id: String,
    pub pairing_request_id: OpaqueLocalId,
    pub approval_request_id: OpaqueLocalId,
    pub approval_notification_id: String,
    pub approval_requested_at: chrono::DateTime<chrono::Utc>,
    pub proof_verified_at: chrono::DateTime<chrono::Utc>,
    pub controller_account_pk: AccountPk,
    pub recipient_id: String,
    pub runtime_key_binding_digest: String,
    pub runtime_public_key_digest: String,
    pub runtime_attestation_digest: String,
    pub runtime_key_request:
        arkret_models_collaboration::agent_scope::AgentRuntimeApprovalRequestBody,
}

/// Exact active-runtime snapshot that a durable Agent inbox write is allowed
/// to target.  `updated_at` is part of the guard so a pause, re-key, or
/// endpoint replacement that races delivery cannot receive the message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentRuntimeSnapshotGuard {
    pub agent_id: String,
    pub verification_method: String,
    pub authorized_event_ref: String,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct EnqueueAgentRuntimeMessage {
    pub request_key: String,
    pub request_digest: String,
    pub snapshot: AgentRuntimeSnapshotGuard,
    /// The exact repair/runtime envelope delivered to the Agent.  Storage
    /// compares this value on replay; a request digest alone is insufficient.
    pub content: serde_json::Value,
    pub enqueued_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AgentRuntimeMessageRecord {
    pub message_id: uuid::Uuid,
    pub request_key: String,
    pub request_digest: String,
    pub agent_id: String,
    pub verification_method: String,
    pub authorized_event_ref: String,
    pub content: serde_json::Value,
    pub enqueued_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum AgentRuntimeEnqueueOutcome {
    Stored(AgentRuntimeMessageRecord),
    Duplicate(AgentRuntimeMessageRecord),
    RequestConflict,
    SnapshotConflict,
}
/// Durable terminal outcome of one exact controller authorize command.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct AgentPairingReceipt {
    pub agent_id: String,
    pub controller_principal_id: String,
    pub request_digest: String,
    pub authorize_event_ref: String,
    pub pairing_request_id: OpaqueLocalId,
    pub approval_request_id: OpaqueLocalId,
    pub runtime_key_binding_digest: String,
    pub outcome: arkret_models_collaboration::agent_operations::AgentKeyPairOutcome,
    pub scope_custody_ref: Option<AgentScopeCustodyRef>,
}
/// Station-private preparation only. Reading this material grants no current
/// qualification; every operation rechecks the observed Accounts at its cut.
#[derive(Clone)]
pub struct ManagementReviewMaterial {
    pub request: arkret_models_integration::management_review::ManagementReviewRequestBody,
    pub outcome: arkret_models_integration::management_review::ManagementReviewOutcome,
    pub accounts: Vec<arkret_wire::AccountId>,
}

/// Process-only authenticated AA observations, never a caller wire proof or TTL.
#[derive(Clone)]
pub struct ManagementReviewCurrent {
    pub station_id: arkret_wire::DidCoreId,
    pub observations: Vec<crate::AccountStatusCurrentObservation>,
    pub applet_candidate: Option<Box<crate::AppletAuthoringCandidate>>,
    pub applet_event: Option<Box<AppletEventReviewCurrent>>,
}

/// Receiver-derived Service resolver material and Realm lock plan, never permission.
#[derive(Clone)]
pub struct AppletEventReviewCurrent {
    pub realm_id: arkret_wire::RealmId,
    pub service_did_document: arkret_identity::DidDocument,
}

impl std::fmt::Debug for ManagementReviewCurrent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ManagementReviewCurrent([REDACTED])")
    }
}

#[async_trait]
pub trait AgentStore: Send + Sync {
    /// In-process business preparation bound to the exact native original.
    /// This material is never exposed through the private lookup operation.
    async fn management_review_event_material(
        &self,
        event: &arkret_wire::Event,
        request_id: &str,
        signatures: &[arkret_wire::ApprovalSignature],
    ) -> PersistenceResult<ManagementReviewMaterial> {
        let _ = (event, request_id, signatures);
        Err(crate::PersistenceError::NotFound(
            "management review not found".into(),
        ))
    }
    /// Confidential in-process material for the historical signature resolver.
    async fn management_review_material(
        &self,
        caller: &arkret_wire::ActorId,
        request_id: &str,
        new_signatures: &[arkret_wire::ApprovalSignature],
    ) -> PersistenceResult<ManagementReviewMaterial> {
        let _ = (caller, request_id, new_signatures);
        Err(crate::PersistenceError::NotFound(
            "management review not found".into(),
        ))
    }
    /// Private management intent only: never commits its candidate Event.
    async fn management_review_request(
        &self,
        caller: &arkret_wire::ActorId,
        request: &arkret_models_integration::management_review::ManagementReviewRequestBody,
        producer: Option<&crate::SelfProducerCommitGuard>,
        current: &ManagementReviewCurrent,
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<arkret_models_integration::management_review::ManagementReviewOutcome>
    {
        let _ = (caller, request, producer, at, current);
        Err(crate::PersistenceError::Conflict(
            "unsupported_feature: management review persistence is unavailable".into(),
        ))
    }
    async fn management_review_status(
        &self,
        caller: &arkret_wire::ActorId,
        request: &arkret_models_integration::management_review::ManagementReviewLookupRequestBody,
        current: &ManagementReviewCurrent,
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<arkret_models_integration::management_review::ManagementReviewOutcome>
    {
        let _ = (caller, request, at, current);
        Err(crate::PersistenceError::NotFound(
            "management review not found".into(),
        ))
    }
    async fn management_review_decide(
        &self,
        caller: &arkret_wire::ActorId,
        request: &arkret_models_integration::management_review::ManagementReviewDecisionRequestBody,
        methods: &[crate::ApprovalHistoricalMethod],
        current: &ManagementReviewCurrent,
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<arkret_models_integration::management_review::ManagementReviewOutcome>
    {
        let _ = (caller, request, methods, at, current);
        Err(crate::PersistenceError::NotFound(
            "management review not found".into(),
        ))
    }
    async fn pairing_receipt(
        &self,
        event_id: &str,
    ) -> PersistenceResult<Option<AgentPairingReceipt>>;
    async fn qualified_scope_receipt_for_pairing(
        &self,
        agent_id: &str,
        pairing_request_id: &str,
    ) -> PersistenceResult<Option<AgentPairingReceipt>>;
    /// Bounded durable scan; cursor wraps after an empty page.
    async fn pending_pairings_after(
        &self,
        after_id: &str,
        limit: usize,
    ) -> PersistenceResult<Vec<AgentPrincipalRecord>>;
    async fn put(&self, record: AgentPrincipalRecord) -> PersistenceResult<()>;
    async fn get(&self, agent_id: &str) -> PersistenceResult<Option<AgentPrincipalRecord>>;
    async fn get_by_pairing_request_id(
        &self,
        pairing_request_id: &str,
    ) -> PersistenceResult<Option<AgentPrincipalRecord>>;
    async fn list_for_controller(
        &self,
        controller_principal_id: &str,
    ) -> PersistenceResult<Vec<AgentPrincipalRecord>>;
    async fn set_state(
        &self,
        agent_id: &str,
        state: arkret_models_collaboration::agent_operations::AgentLifecycleState,
        changed_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<bool>;
    async fn activate_runtime_if_current(
        &self,
        activation: &AgentRuntimeActivation,
    ) -> PersistenceResult<bool>;
    /// Durably bind the one open pairing handle to the exact final request
    /// before Event admission. Exact retries are idempotent; a different
    /// request or Event id cannot replace an existing intent.
    async fn put_pairing_commit_intent_if_compatible(
        &self,
        intent: &AgentPairingCommitIntent,
    ) -> PersistenceResult<Option<AgentPrincipalRecord>>;
    /// Clear the retained approval/notification correlation only after the
    /// terminal account-notification delta is durable. Retaining it across the
    /// activation write makes a crash between those writes reconcilable.
    async fn clear_runtime_approval_notification_if_current(
        &self,
        agent_id: &str,
        approval_request_id: &str,
    ) -> PersistenceResult<bool>;
    async fn put_runtime_approval_if_compatible(
        &self,
        write: &AgentRuntimeApprovalWrite,
    ) -> PersistenceResult<Option<AgentPrincipalRecord>>;
    /// Check exact replay first, then atomically validate the unique current
    /// active runtime snapshot and append one inbox message.
    async fn enqueue_runtime_message_if_current(
        &self,
        command: &EnqueueAgentRuntimeMessage,
    ) -> PersistenceResult<AgentRuntimeEnqueueOutcome>;
}
