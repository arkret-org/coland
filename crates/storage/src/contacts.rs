mod completion_plan;

use arkret_models_collaboration::contact_operations::RequestAcceptanceReceipt;
use arkret_wire::ActorId;
use coland_domain::identity::ContactRecord;

use super::{PersistenceResult, Utc, Value, async_trait};

/// Principal-private, non-canonical mirror of one fully verified inbound
/// `ak.contact.requested` carrier. It never participates in Realm reduction,
/// authority signing or current materialization.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ContactVerifiedMirrorRecord {
    pub target_holder_principal_id: String,
    pub request_event_id: String,
    pub request_digest: String,
    pub canonical_event_bytes: Vec<u8>,
    pub source_receipt: RequestAcceptanceReceipt,
    pub issuer_id: String,
    pub verified_at: chrono::DateTime<Utc>,
}

#[async_trait]
pub trait ContactVerifiedMirrorStore: Send + Sync {
    async fn get(
        &self,
        target_holder_principal_id: &str,
        request_event_id: &str,
    ) -> PersistenceResult<Option<ContactVerifiedMirrorRecord>>;
    /// CAS-insert one verified mirror. An exact replay is success; the same
    /// holder/Event key with different bytes, digest, receipt, or issuer is a
    /// conflict and MUST NOT overwrite the original evidence.
    async fn put_verified(&self, record: &ContactVerifiedMirrorRecord) -> PersistenceResult<()>;
}

/// Non-authorizing business inputs retained before the source producer has
/// been authenticated. Values already in the Event payload are not mirrored.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContactCompletionDraft {
    pub event: arkret_wire::Event,
    pub operation_id: arkret_wire::ProtocolOperationId,
    pub holder: arkret_models_collaboration::contact_operations::ContactPeer,
    pub action: ContactCompletionAction,
    pub response_binding: ContactCompletionBinding,
    pub target: ContactDeliveryTarget,
    pub local_mirror_target: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum ContactCompletionAction {
    Request {
        slot_version: u64,
        slot_predecessor: Option<arkret_wire::Hash>,
    },
    Response {
        request_receipt: Box<RequestAcceptanceReceipt>,
        absence:
            Box<arkret_models_collaboration::contact_operations::OutgoingSlotAbsenceTranscript>,
    },
    Reject {
        request_receipt: Box<RequestAcceptanceReceipt>,
    },
    ScopeUpdate,
    Tombstone,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContactCompletionIntent {
    pub plan: ContactCompletionDraft,
    pub producer_signer: arkret_models_collaboration::contact_operations::ContactProducerSigner,
    pub confirmation: ContactCompletionConfirmation,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum ContactCompletionConfirmation {
    Pending,
    Committed { accepted_at: chrono::DateTime<Utc> },
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContactCompletionBinding {
    pub authenticated_actor: ActorId,
    pub idempotency_key: String,
    pub request_hash: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContactDeliveryTarget {
    pub contact_address: arkret_models_collaboration::governance::peer_contact::PeerContactAddress,
    pub introduction_evidence:
        Option<arkret_models_collaboration::governance::peer_contact::ContactIntroductionEvidence>,
    pub idempotency_key: arkret_wire::IdempotencyKey,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum ContactCompletionResult {
    Accepted {
        outcome: Box<arkret_models_collaboration::contact_operations::ContactAcceptedOutcome>,
    },
    Rejected {
        problem: arkret_wire::problem_details::Problem,
    },
}
#[derive(Clone, Debug)]
pub struct ContactCompletionState {
    pub event: arkret_wire::Event,
    pub result: Option<ContactCompletionResult>,
}

impl ContactCompletionDraft {
    pub fn bind_producer(
        self,
        producer_signer: arkret_models_collaboration::contact_operations::ContactProducerSigner,
    ) -> PersistenceResult<ContactCompletionIntent> {
        let intent = ContactCompletionIntent {
            plan: self,
            producer_signer,
            confirmation: ContactCompletionConfirmation::Pending,
        };
        intent.validate_event_binding()?;
        Ok(intent)
    }
}
impl ContactCompletionIntent {
    pub fn requires_delivery(&self) -> bool {
        self.plan.target.contact_address.delivery_station_id()
            != self.plan.holder.delivery_station_id()
    }
    pub fn accepted_at(&self) -> PersistenceResult<chrono::DateTime<Utc>> {
        match self.confirmation {
            ContactCompletionConfirmation::Committed { accepted_at } => Ok(accepted_at),
            ContactCompletionConfirmation::Pending => {
                Err(crate::PersistenceError::SchemaViolation(
                    "Contact completion is not confirmed".into(),
                ))
            }
        }
    }
    pub fn validate_event_binding(&self) -> PersistenceResult<()> {
        use arkret_wire::EventKind;
        let invalid = |message: &str| crate::PersistenceError::SchemaViolation(message.into());
        self.producer_signer
            .validate_for_event(&self.plan.event, &self.plan.holder)
            .map_err(|error| invalid(&error.to_string()))?;
        let Some(proof) = self.plan.event.producer_proof.as_ref() else {
            return Err(invalid("Contact requires one authenticated producer proof"));
        };
        if &proof.verification_method != self.producer_signer.verification_method()
            || self.plan.holder.contact_actor_id() != self.plan.event.actor_id
        {
            return Err(invalid(
                "Contact completion producer/holder differs from its exact Event",
            ));
        }
        let kind = match self.plan.action {
            ContactCompletionAction::Request { .. } => EventKind::ContactRequested,
            ContactCompletionAction::Response { .. } => EventKind::ContactAccepted,
            ContactCompletionAction::Reject { .. } => EventKind::ContactRejected,
            ContactCompletionAction::ScopeUpdate => EventKind::ContactScopeUpdate,
            ContactCompletionAction::Tombstone => EventKind::ContactTombstone,
        };
        if self.plan.event.kind != kind
            || (kind == EventKind::ContactRequested)
                != self.plan.target.introduction_evidence.is_some()
        {
            return Err(invalid(
                "Contact completion action differs from its Event or introduction",
            ));
        }
        let peer: arkret_models_collaboration::contact_operations::ContactPeer =
            serde_json::from_value(
                self.plan
                    .event
                    .payload
                    .get("peer")
                    .cloned()
                    .ok_or_else(|| invalid("Contact peer is missing"))?,
            )
            .map_err(|error| invalid(&error.to_string()))?;
        if self.plan.target.contact_address.recipient != peer
            || peer.contact_actor_id() == self.plan.event.actor_id
            || proof.event_digest != self.plan.event.event_id.event_digest()
        {
            return Err(invalid(
                "Contact completion destination or producer digest differs from its Event",
            ));
        }
        if let ContactCompletionAction::Response {
            request_receipt, ..
        }
        | ContactCompletionAction::Reject { request_receipt } = &self.plan.action
        {
            let request_ref = self
                .plan
                .event
                .payload
                .get("request_event_ref")
                .and_then(Value::as_str);
            let request_digest = self
                .plan
                .event
                .payload
                .get("request_acceptance_receipt_digest")
                .and_then(Value::as_str);
            let expected_digest = request_receipt
                .computed_receipt_digest()
                .map_err(|error| invalid(&error.to_string()))?;
            if request_receipt.core.holder != peer
                || request_receipt.core.peer != self.plan.holder
                || request_ref != Some(request_receipt.core.request_event_ref.as_str())
                || request_digest != Some(expected_digest.as_str())
            {
                return Err(invalid(
                    "Contact response plan rebinds its authenticated request receipt",
                ));
            }
        }
        Ok(())
    }
    pub fn freeze_acceptance_time(&mut self, at: chrono::DateTime<Utc>) -> PersistenceResult<()> {
        if !matches!(self.confirmation, ContactCompletionConfirmation::Pending) {
            return Err(crate::PersistenceError::SchemaViolation(
                "Contact confirmation time is already fixed".into(),
            ));
        }
        // Freeze the same instant in the durable plan and signed transcript;
        // canonical wire timestamps cannot preserve sub-millisecond precision.
        let at = arkret_canonical::normalize_timestamp_canonical(at);
        if let ContactCompletionAction::Response { absence, .. } = &mut self.plan.action {
            absence.observed_at = at;
        }
        self.confirmation = ContactCompletionConfirmation::Committed { accepted_at: at };
        Ok(())
    }
}

/// Exact durable finality plus its fixed, authenticated producer and business plan.
#[derive(Clone, Debug)]
pub struct CommittedContactCompletionIntent {
    pub event_digest: arkret_wire::Hash,
    pub committed_ref: arkret_wire::CommittedEventRef,
    pub intent: ContactCompletionIntent,
}

/// Trait for contact storage operations.
#[async_trait]
pub trait ContactStore: Send + Sync {
    async fn completion_for_request(
        &self,
        actor: &ActorId,
        key: &str,
        request_hash: &str,
    ) -> PersistenceResult<Option<ContactCompletionState>>;

    /// Only exact committed commands are eligible. Pending/rejected commands
    /// never enter the HTTP outbox. Concurrent readers are safe: finalization
    /// rechecks the durable decision and fixes one immutable payload atomically.
    async fn committed_completion_intents(
        &self,
        limit: u16,
        after: Option<&arkret_wire::Hash>,
    ) -> PersistenceResult<Vec<CommittedContactCompletionIntent>>;
    /// The caller must have constructed the complete protocol confirmation
    /// before invoking this storage boundary. This method supplies no proof and
    /// never treats the local decision as a transferable authorization.
    /// Atomically freeze HTTP results, source evidence, optional outbox and intent.
    ///
    /// `counterpart_proof` is the requester direction's current proof this
    /// Station issued when it hosts both members of a normally accepted pair.
    async fn finalize_completion_intent(
        &self,
        ready: &CommittedContactCompletionIntent,
        result: &ContactCompletionResult,
        delivery: Option<&crate::FederationOutboxRecord>,
        counterpart_proof: Option<
            &arkret_models_collaboration::contact_operations::ContactCurrentProof,
        >,
    ) -> PersistenceResult<bool>;

    async fn get(
        &self,
        requester_id: &ActorId,
        target_id: &ActorId,
    ) -> PersistenceResult<Option<ContactRecord>>;
    async fn put(&self, record: &ContactRecord) -> PersistenceResult<()>;
    /// Replace one existing Contact row only when its durable revision still
    /// matches the revision the caller read. Callers must advance
    /// `record.updated_at`; `false` is a lost-race signal, never permission to
    /// overwrite newer receipt/evidence state.
    async fn put_if_updated_at(
        &self,
        expected_updated_at: chrono::DateTime<chrono::Utc>,
        record: &ContactRecord,
    ) -> PersistenceResult<bool>;
    async fn list_for_actor(&self, actor_id: &ActorId) -> PersistenceResult<Vec<ContactRecord>>;
    async fn delete(&self, requester_id: &ActorId, target_id: &ActorId) -> PersistenceResult<()>;
}
/// Durable backing for per-account private `invite_receive_policy` overrides
/// (spec `sync/invite-addressing.md` §5). The in-memory
/// `AppState::invite_receive_policies` map remains the working projection; this
/// store hydrates it on boot and is written through on policy changes
/// (`ak.self.invite_receive_policy.resource.replace.v1`,
/// `ak.self.contact.command.tombstone.v1(block_peer)`).
#[async_trait]
pub trait InviteReceivePolicyStore: Send + Sync {
    async fn get(
        &self,
        account_id: &arkret_wire::AccountId,
    ) -> PersistenceResult<
        Option<arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy>,
    >;
    async fn put(
        &self,
        account_id: &arkret_wire::AccountId,
        policy: &arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy,
    ) -> PersistenceResult<()>;
    async fn snapshot_all(
        &self,
    ) -> PersistenceResult<
        Vec<(
            arkret_wire::AccountId,
            arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy,
        )>,
    >;
}

/// Bind a policy to the complete authenticated storage owner, including its
/// Station coordinate. A caller cannot write another Account's policy payload.
pub fn validate_invite_policy_account(
    account_id: &arkret_wire::AccountId,
    policy: &arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy,
) -> PersistenceResult<()> {
    if &policy.account_id != account_id {
        return Err(super::PersistenceError::SchemaViolation(
            "invite receive policy does not match its Account owner".to_owned(),
        ));
    }
    account_id
        .validate()
        .map_err(|error| super::PersistenceError::SchemaViolation(error.to_string()))
}
/// Service-local correlation retained by the MIMI consent facade.
///
/// This is deliberately not a consent cell or a protocol Event. It only binds
/// the opaque `consent_id` returned by `request_consent` to the authenticated
/// requester_id, target, scope, transport source, and optional expiry so a later
/// caller-authored Event can be checked without disclosing holder-private
/// state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MimiConsentCorrelationRecord {
    pub consent_id: String,
    /// Canonical JSON of the complete requester `ActorId`, exactly as signed.
    pub requester_actor_id: String,
    /// Canonical JSON of the complete holder `AccountId`, exactly as signed.
    pub holder_account_id: String,
    pub purpose: String,
    pub strand_id: Option<String>,
    pub source_id: Option<String>,
    pub created_at: chrono::DateTime<Utc>,
    pub expires_at: Option<chrono::DateTime<Utc>>,
}

#[async_trait]
pub trait MimiConsentCorrelationStore: Send + Sync {
    async fn get(
        &self,
        consent_id: &str,
    ) -> PersistenceResult<Option<MimiConsentCorrelationRecord>>;
    async fn put(&self, record: &MimiConsentCorrelationRecord) -> PersistenceResult<()>;
}
#[doc(hidden)]
pub type ContactKey = (ActorId, ActorId);
