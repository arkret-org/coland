use std::collections::{BTreeMap, BTreeSet};

use arkret_identifiers::{BlobRef, Hash};
use arkret_models_collaboration::objects::blob::{BlobStorageEncryption, BlobVisibility};
use arkret_models_crypto::RecoveryIdentityModel;
use arkret_wire::{
    ActorId, CommitStreamHead, DidCoreId, EventId, FreshnessState, PlaintextDataClassKind,
    RealmCommitAuthorityRef, RealmId,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::DeviceRevocationGateSelector;

/// Service-local primary key of one row in `accounts`.
///
/// This integer never appears on the wire and must not be confused with the
/// protocol `AccountId` value `(station_id, principal_id)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AccountPk(pub i64);

impl AccountPk {
    pub const fn get(self) -> i64 {
        self.0
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentSessionRecord {
    pub granted_scope: Vec<String>,
    pub scope_details: Value,
    pub freshness_state: FreshnessState,
}

#[derive(Clone, Debug)]
pub struct SessionRecord {
    pub token_hash: String,
    /// Exact service-local account binding for this authenticated session.
    pub account_pk: AccountPk,
    pub actor: String,
    pub device_id: String,
    pub audience: String,
    /// Session signing key (JWK) bound by `ak.session.grant`, used to verify
    /// RFC 9421 PoP presentations on `/_arkret/self/*` (api-conventions.md
    /// §3.2). `None` for bearer-only / dev-login / OAuth-bridged sessions.
    pub session_public_key: Option<String>,
    pub agent_session: Option<AgentSessionRecord>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Clone, Debug)]
pub struct DeviceInventoryRecord {
    pub actor: String,
    pub device_id: String,
    pub display_name: Option<String>,
    pub verification_state: String,
    pub payload: Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Clone, Debug)]
pub struct AccountRecord {
    /// Service-local opaque account row primary key, minted by
    /// The composition root mints this identifier at account creation. Stable
    /// internal handle decoupled from the protocol principal identifier.
    pub pk: AccountPk,
    /// Stable protocol principal identifier (DB column `principal_id`).
    ///
    /// An ordinary account projection does not carry a W3C DID. Registration
    /// and resolution surfaces carry that evidence separately when required.
    pub principal_id: DidCoreId,
    /// Station component of the protocol AccountId.
    pub station_id: DidCoreId,
    /// Primary bare handle localpart (`alice` — never `@alice` or
    /// `alice:domain`). This is derived from `account_localparts`, not stored
    /// on the account row. Wire/display surfaces use [`AccountRecord::handle`]
    /// for the `@`-prefixed form.
    pub localpart: String,
    pub display_name: Option<String>,
    /// Free-form short description for directory rendering. Updated via
    /// `POST /_arkret/self/account/profile` (operationId
    /// `ak.self.account.command.update_profile.v1`).
    pub bio: Option<String>,
    /// Canonical content-addressed avatar Blob reference.
    pub avatar_blob_ref: Option<BlobRef>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl AccountRecord {
    /// `@<localpart>` form used by the product API, audit log and
    /// directory projections.
    pub fn handle(&self) -> String {
        if self.localpart.is_empty() {
            String::new()
        } else {
            format!("@{}", self.localpart)
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountLocalpartRecord {
    pub id: String,
    pub account_pk: AccountPk,
    pub localpart: String,
    pub is_primary: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct AccountLifecycleRecord {
    pub state: String,
    pub reason: Option<String>,
    pub changed_by: Option<arkret_wire::ActorId>,
    pub changed_at: chrono::DateTime<chrono::Utc>,
}

/// REC-1 (R3 spec-sync 2026-05-27, arkret-spec b47ff6ec) — accepted
/// recovery policy snapshot persisted by `RecoveryPolicyStore`.
///
/// Spec: `arkret-spec/spec/v1/artifacts/schemas/recovery-policy.schema.json`.
#[derive(Clone, Debug)]
pub struct RecoveryPolicyRecord {
    pub policy_id: String,
    pub account_id: arkret_wire::AccountId,
    pub version: u32,
    pub acceptance_basis: arkret_wire::RealmCommitId,
    pub trust_domain: String,

    pub supersedes: Option<String>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub issued_at: chrono::DateTime<chrono::Utc>,
    pub raw_payload: Value,
    pub accepted_at: chrono::DateTime<chrono::Utc>,
    /// Verification-method DID URL of the issuer. The full proof
    /// verification of the fixed canonical signature transcript is flagged
    /// `TODO(R4): wire accepted recovery-policy key resolver + signature
    /// validation through DidResolver chain`.
    pub verification_method: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoverySessionLifecycle {
    Pending,
    Verified,
    Completed,
    Rejected,
    Expired,
}

/// Authority snapshot frozen when the recovery session is opened. Recovery
/// completion is valid only while this generation remains current.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryAuthorityContext {
    pub realm_id: RealmId,
    pub authority_generation: u64,
    pub authority_ref: RealmCommitAuthorityRef,
    pub realm_stream_head: CommitStreamHead,
}

/// C-P2 (REC-1) — recovery session lifecycle record.
///
/// A session binds a requesting device to the principal's active recovery
/// policy snapshot + a server challenge, and transitions
/// `pending -> verified -> completed` (or `rejected` / `expired`). Proof
/// verification (C-P3) is what advances `pending -> verified`; completion
/// (C-P4) emits a `ak.device.authorize` + receipt.
#[derive(Clone, Debug)]
pub struct RecoverySessionRecord {
    pub request_id: String,
    pub create_intent_digest: String,
    pub recovery_session_id: String,
    pub session_grant_id: String,
    pub session_grant_cnf_jkt: String,
    pub principal_id: arkret_identifiers::DidCoreId,
    pub station_id: arkret_identifiers::DidCoreId,
    pub requesting_device_id: String,
    pub requesting_device_public_key_did: String,
    pub trust_domain: String,
    pub policy_id: String,
    pub policy_version: u32,
    pub identity_model: RecoveryIdentityModel,
    pub current_device_generation_ref: u64,
    pub accepted_stream_head: CommitStreamHead,
    /// Snapshot of the active policy at session-creation time (so a later policy
    /// rotation cannot retroactively change what this session was bound to).
    pub policy_payload: Value,
    /// Immutable publication authority derived from the policy's accepted
    /// basis and the identity model at session creation.
    pub authority_context: RecoveryAuthorityContext,
    /// Exact policy-derived publication authority frozen at session creation.
    pub publication_authority_context: arkret_models_crypto::PublicationAuthorityContext,
    pub publication_authority_context_digest: Hash,
    /// Server-issued anti-replay challenge the proof transcript MUST bind.
    pub challenge: String,
    /// Lifecycle state; canonical SDK enum (recovery-session.schema.json
    /// `#/$defs/session_state`), persisted as its snake_case wire name.
    pub state: RecoverySessionLifecycle,
    /// The submitted proof payload (recorded on `/proofs`; verified in C-P3).
    pub proof_payload: Option<Value>,
    pub transaction_id: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct SecurityTransactionRecord {
    pub canonical_request: Vec<u8>,
    pub resource: arkret_models_crypto::SecurityTransaction,
}

/// First durable request bytes for one security-transaction step.
///
/// This record is committed before any participant side effect. Replays must
/// present byte-identical input even when the participant accepted the first
/// attempt but its response was lost.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecurityTransactionStepAttemptRecord {
    pub transaction_id: String,
    pub step: arkret_models_crypto::SecurityTransactionStep,
    pub canonical_request: Vec<u8>,
}

/// First durable response for one accepted security-transaction step.
///
/// This is deliberately separate from the public transaction resource:
/// `accepted_steps` exposes only stable refs/digests, while response-loss
/// replay needs the exact canonical request and first response bytes/value.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecurityTransactionStepOutcomeRecord {
    pub transaction_id: String,
    pub step: arkret_models_crypto::SecurityTransactionStep,
    pub canonical_request: Vec<u8>,
    pub response: Value,
    pub participant_outcome: Option<Value>,
}

/// Durable monotonic progress for one transaction-bound backup-series erase.
///
/// The first canonical request is immutable. `outcome` may advance only by
/// moving planned objects from `remaining_backups` to `erased_backups`; an
/// erased object can never reappear after a retry or restart.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BackupSeriesEraseProgressRecord {
    pub transaction_id: String,
    pub canonical_request: Vec<u8>,
    pub outcome: crate::BackupSeriesEraseOutcome,
}

/// A revoked cursor authority recorded by `ak.self.account.command.revoke_cursor.v1`.
///
/// `scope` mirrors the wire enum: `this_cursor` matches the exact cursor by
/// `cursor_digest`; `same_device` / `same_session` match any cursor that
/// resolves to the same authenticated `(account_id, device_id)` binding —
/// Revocation binds the exact account and immutable issuance identity. Group
/// scopes additionally distinguish device and private issuing-session identity.
#[derive(Clone, Debug)]
pub struct CursorRevocation {
    /// sha256 hex of the verified immutable handle (used by `this_cursor`).
    pub cursor_digest: String,
    /// Exact authenticated account that requested the revocation.
    pub account_id: arkret_wire::AccountId,
    /// Bound device for `same_device` / `same_session` scope (the caller's
    /// session device); `None` for `this_cursor`.
    pub device_id: Option<String>,
    pub session_id: Option<String>,
    /// `this_cursor` | `same_device` | `same_session`.
    pub scope: String,
    /// Client-supplied revocation reason (audited).
    pub reason_code: String,
    pub revoked_at: chrono::DateTime<chrono::Utc>,
    /// GC horizon — the entry may be pruned after this instant.
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct WebvhDocumentRecord {
    pub did: String,
    pub did_document: Value,
    pub key_log_head: Option<String>,
    pub seq: u64,
    pub method_evidence: Value,
    /// Time this record was ingested by this node. High-risk verification
    /// paths compare `age = now - fetched_at` with the caller-provided
    /// `max_age` via `verify_did_document_freshness`. Writes are ingestion:
    /// `put_document` stamps this field with "now", so persisted records
    /// always carry freshness evidence.
    pub fetched_at: chrono::DateTime<chrono::Utc>,
    /// High-risk baseline expiry hint, usually `fetched_at + high-risk
    /// baseline TTL` (15 minutes). This is only a storage and cleanup-index
    /// hint per §3.4; actual freshness uses `age vs max_age`. Degraded
    /// read-only paths may use a larger `max_age` (24h) and mark records that
    /// have passed `expires_at`.
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct WebvhLogRecord {
    pub event_digest: String,
    pub did: String,
    pub seq: u64,
    pub operation: Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Actor-private account data row (`ak.account_data.set` storage).
///
/// One row per `(actor, account_data_key)`. `account_data_key` is the canonical wire key
/// (e.g. `ak.read_receipt.preferences`, `ak.contacts.actor.did:web:alice.example`,
/// `ak.contacts.realm.ak:realm:AZAySZA7XRDeJ9cO4MqaDWrJD-rqPk6Cudk7CCzsDQz1`). Coland
/// treats the `payload` as an opaque encrypted blob — no schema validation
/// happens server-side; clients are responsible for canonical encoding.
///
/// Spec: `discovery/client-preferences.md` §2 (storage model) and §3.7
/// (Realm remarks, `ak.contacts.realm.<realm_id>`).
#[derive(Clone, Debug)]
pub struct AccountDataRecord {
    pub actor: String,
    pub account_data_key: String,
    /// Monotonic CAS high-water mark for this key.
    pub revision: u64,
    pub payload: Value,
    /// Physical-delete requests store a versioned tombstone. The row remains
    /// so `revision` cannot go backwards or permit stale-value resurrection.
    pub tombstone: bool,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// One durable cursor-addressable change to an Account Data register.
#[derive(Clone, Debug)]
pub struct AccountDataChangeRecord {
    pub position: u64,
    pub record: AccountDataRecord,
}

#[derive(Clone, Debug)]
pub enum AccountDataCasResult {
    Applied(AccountDataRecord),
    Conflict(Option<AccountDataRecord>),
}

#[derive(Clone, Debug, PartialEq)]
pub struct RealmMetaRecord {
    pub owner: String,
    pub deleted: bool,
    pub discoverability: String,
    /// Current one-way history policy: `all_history_for_current_members` may
    /// tighten to `since_join`; widening is permanently forbidden.
    pub history_access: String,
    /// Effective `ak.realm.preview_policy.value` plus its canonical digest.
    /// Directory/object preview must fail closed when this is missing.
    pub preview_policy: Option<Value>,
    pub preview_policy_digest: Option<String>,
    /// Effective `ak.realm.asset_privacy_policy.value` plus its canonical
    /// digest. Blob presign/download re-checks this at response time.
    pub asset_privacy_policy: Option<Value>,
    pub asset_privacy_policy_digest: Option<String>,
    /// Optional encryption profile (`mls_rfc9420` / `plaintext`). Standard MLS
    /// is permanently pinned to `history_access=since_join`.
    pub encryption_profile: Option<String>,
    pub plaintext_visible_services: BTreeSet<String>,
    pub plaintext_visible_service_classes: BTreeMap<String, BTreeSet<PlaintextDataClassKind>>,
    /// SEC-08 — the Realm declared `ak.profile.mls.minimal_metadata_realm.v1`
    /// (`crypto-media/encryption-and-audit.md` §2.9). Projected from the
    /// canonical genesis `schema_refs[]` carrier on `ak.realm.create`. Once
    /// observed it latches true:
    /// coland is not the committer and never relaxes a minimal-metadata Realm
    /// back to a wider profile on its own. Drives the server-side
    pub minimal_metadata_realm: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl RealmMetaRecord {
    pub fn allows_plaintext_data_class(
        &self,
        service_id: &str,
        data_class: PlaintextDataClassKind,
    ) -> bool {
        self.plaintext_visible_service_classes
            .get(service_id)
            .is_some_and(|classes| classes.contains(&data_class))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct MessageRecord {
    pub event_id: String,
    pub message_id: String,
    pub realm_id: String,
    pub sender: String,
    pub thread_id: String,
    pub content: Value,
    pub encrypted: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct CanonicalEventRecord {
    pub event_id: String,
    pub actor_id: String,
    pub realm_id: Option<String>,
    pub kind: String,
    pub schema_id: String,
    pub digest_suite: arkret_canonical::DigestSuite,
    pub canonical_digest: String,
    /// Canonical bytes of the Event digest payload (the exact hash preimage),
    /// not canonical encoding of the whole envelope. Fields excluded from the
    /// digest payload, such as proofs/unsigned metadata, are validated by
    /// admission and cannot turn an otherwise identical identity into a hash
    /// collision.
    pub canonical_bytes: Vec<u8>,
    pub envelope: Value,
    pub received_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct ProjectionEventRecord {
    pub event_id: String,
    pub realm_id: String,
    /// Canonical Arkret event kind (e.g. `ak.message.create`).
    pub event_kind: String,
    pub operation_kind: String,
    pub operation_id: Option<String>,
    pub sender: Option<String>,
    pub payload: Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub received_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct DeviceMessageRecord {
    pub idempotency_key: String,
    pub sender: String,
    pub recipient: String,
    pub device_id: String,
    /// Private immutable authorization of the intended recipient instance.
    pub recipient_device_authorization: DeviceRevocationGateSelector,
    pub position: i64,
    /// The complete closed `DeviceMessageEnvelope` served to the recipient.
    /// The queue persists exactly this shape; its `sent_at` is the queue's
    /// materialized enqueue time and `recipient_*` must equal the row's
    /// recipient endpoint (see [`DeviceMessageRecord::validate_binding`]).
    pub envelope: arkret_models_collaboration::device_messages::DeviceMessageEnvelope,
}

impl DeviceMessageRecord {
    /// Closed binding between the queue row columns, the recipient's original
    /// device authorization, and the stored envelope. Writers and readers
    /// apply the same check so a queue row can never be served under another
    /// endpoint or with a repaired envelope.
    pub fn validate_binding(&self) -> Result<(), &'static str> {
        let source = &self.recipient_device_authorization;
        if source.principal_id.as_str() != self.recipient || source.device_id != self.device_id {
            return Err("queue recipient differs from its original authorization");
        }
        let envelope = &self.envelope;
        if envelope.recipient_account_id.principal_id != source.principal_id
            || envelope.recipient_account_id.station_id != source.station_id
            || envelope.recipient_device_id.as_str() != self.device_id
        {
            return Err("DeviceMessage envelope differs from its queue recipient");
        }
        if arkret_canonical::normalize_timestamp_canonical(envelope.sent_at) != envelope.sent_at {
            return Err("DeviceMessage sent_at is not a canonical millisecond timestamp");
        }
        Ok(())
    }
}

/// The two closed recipient-delivery objects share one ordered cursor and
/// cumulative ACK boundary. The endpoint selector is derived from the
/// authenticated session, never from a request query or payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecipientQueueSelector {
    HumanDevice {
        recipient: String,
        device_id: String,
    },
    AgentRuntime {
        agent_id: String,
        verification_method: String,
        authorization_event_ref: String,
    },
}

#[derive(Clone, Debug)]
pub struct RecipientDeliveryRecord {
    pub position: i64,
    pub delivery: arkret_models_collaboration::device_messages::RecipientDelivery,
}

#[derive(Clone, Debug)]
pub struct DeviceMessageIntentRecord {
    pub message_key: String,
    pub intent_digest: String,
}

#[derive(Clone, Debug)]
pub struct DeviceMessageBatchItemRecord {
    pub message_key: String,
    pub intent_digest: String,
    pub idempotency_expires_at: chrono::DateTime<chrono::Utc>,
    pub message: Option<DeviceMessageRecord>,
}

#[derive(Clone, Debug)]
pub struct DeviceMessageBatchRecord {
    pub request_key: String,
    pub request_digest: String,
    pub idempotency_expires_at: chrono::DateTime<chrono::Utc>,
    /// Maximum outstanding recipient deliveries per human device. Zero means
    /// unbounded. Checked under the same queue lock as insertion.
    pub per_device_queue_capacity: usize,
    pub target_snapshot_guard: Option<DeviceMessageTargetSnapshotGuard>,
    /// Sender device generation rechecked while holding the same persistence
    /// boundary as request/message idempotency and queue insertion.
    /// Required for local protected-subject writes. `None` is reserved for
    /// independently authenticated peer/internal fanout, whose sender device
    /// is not authoritative at this service.
    pub device_revocation_gate: Option<DeviceRevocationGateSelector>,
    /// The sending Agent endpoint's committed key authorization, rechecked as
    /// the single active current key in the same transaction. Exactly one of
    /// this and `device_revocation_gate` is present for a client send.
    pub sender_agent_guard: Option<AgentEndpointGuard>,
    pub items: Vec<DeviceMessageBatchItemRecord>,
}

/// An Agent runtime endpoint bound by its grant triple: the Agent, its
/// verification method and the accepted `ak.agent.key_authorize` that
/// authorized it in the Agent's PCR Realm.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentEndpointGuard {
    pub pcr_realm_id: arkret_wire::RealmId,
    pub agent_id: arkret_wire::DidCoreId,
    pub authorization_ref: arkret_wire::CommittedEventRef,
    pub verification_method: arkret_wire::DidUrl,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceMessageTargetSnapshotGuard {
    pub recipient: String,
    pub devices: Vec<(String, chrono::DateTime<chrono::Utc>)>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum DeviceMessageBatchInspection {
    Fresh {
        existing_message_outcomes: BTreeMap<String, bool>,
    },
    Duplicate(BTreeMap<String, bool>),
    RequestConflict,
    MessageConflict {
        message_key: String,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub enum DeviceMessageBatchCommitOutcome {
    Stored(BTreeMap<String, bool>),
    Duplicate(BTreeMap<String, bool>),
    RequestConflict,
    MessageConflict {
        message_key: String,
    },
    SnapshotConflict,
    DeviceRevocationPending,
    DeviceRevoked,
    /// The sending Agent endpoint is no longer the Agent's active current key.
    SenderAgentUnauthorized,
    QueueAtCapacity,
}

#[derive(Clone, Debug)]
pub struct BlobRecord {
    pub sha256: String,
    pub size_bytes: i64,
    pub storage_backend: String,
    pub storage_key: String,
    pub media_type: String,
    pub filename: Option<String>,
    pub realm_id: Option<String>,
    pub encryption: Option<BlobStorageEncryption>,
    pub legal_hold: bool,
    pub redacted: bool,
    pub visibility: BlobVisibility,
    pub uploaded_by: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Explicit outbound-delivery lifecycle for one `federation_outbox` row.
///
/// ```text
/// pending
///   -> leased
///   -> pending            retry scheduled / lease expired
///   -> delivered          peer accepted or duplicate
///   -> policy_suppressed  local egress policy denied the target
///   -> dead_lettered      terminal failure with an operator ledger entry
///   -> superseded         semantic resubmission replaced this attempt
/// ```
///
/// `delivered`, `policy_suppressed`, `dead_lettered` and `superseded` are
/// mutually exclusive terminal states. Business state is never inferred from a
/// sentinel status code or from a non-null completion timestamp.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum FederationOutboxState {
    Pending,
    PendingRoute,
    Leased,
    Delivered,
    CancelledAuthorityLost,
    PolicySuppressed,
    DeadLettered,
    Superseded,
}

impl FederationOutboxState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::PendingRoute => "pending_route",
            Self::Leased => "leased",
            Self::Delivered => "delivered",
            Self::CancelledAuthorityLost => "cancelled_authority_lost",
            Self::PolicySuppressed => "policy_suppressed",
            Self::DeadLettered => "dead_lettered",
            Self::Superseded => "superseded",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "pending_route" => Some(Self::PendingRoute),
            "leased" => Some(Self::Leased),
            "delivered" => Some(Self::Delivered),
            "cancelled_authority_lost" => Some(Self::CancelledAuthorityLost),
            "policy_suppressed" => Some(Self::PolicySuppressed),
            "dead_lettered" => Some(Self::DeadLettered),
            "superseded" => Some(Self::Superseded),
            _ => None,
        }
    }

    /// Whether the row has left the delivery pipeline for good. A terminal row
    /// is never claimed again; `policy_suppressed` only returns to `pending`
    /// through the explicit revalidation path (`sync/federation.md` §4.4).
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Delivered
                | Self::CancelledAuthorityLost
                | Self::PolicySuppressed
                | Self::DeadLettered
                | Self::Superseded
        )
    }
}

impl std::fmt::Display for FederationOutboxState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One exact accepted membership generation that authorized a distinct Realm
/// fanout target when the local Event was accepted. Routing is derived from
/// the complete ActorId; no transport binding is part of this authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmFanoutAuthorityWitness {
    pub member_id: arkret_wire::ActorId,
    pub membership_event_ref: String,
    pub circle_membership_event_ref: Option<arkret_wire::EventId>,
}

/// Durable metadata that distinguishes a Realm Event fanout obligation from
/// the generic federation outbox. It is frozen in the Event transaction and
/// never rewritten when membership later changes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmFanoutBinding {
    pub realm_id: String,
    pub source_event_ids: Vec<String>,
    pub authority_witnesses: Vec<RealmFanoutAuthorityWitness>,
}

impl RealmFanoutBinding {
    pub fn validate(&self) -> Result<(), String> {
        RealmId::new(self.realm_id.clone())
            .map_err(|error| format!("invalid Realm fanout Realm id: {error}"))?;
        if self.source_event_ids.is_empty() || self.authority_witnesses.is_empty() {
            return Err(
                "Realm fanout binding requires source Events and authority witnesses".to_owned(),
            );
        }
        let mut source_events = BTreeSet::new();
        for source_event_id in &self.source_event_ids {
            EventId::new(source_event_id.clone())
                .map_err(|error| format!("invalid Realm fanout source Event id: {error}"))?;
            if !source_events.insert(source_event_id) {
                return Err("Realm fanout source Event ids must be unique".to_owned());
            }
        }
        let mut witnesses = BTreeSet::new();
        for witness in &self.authority_witnesses {
            witness
                .member_id
                .validate()
                .map_err(|error| format!("invalid Realm fanout member id: {error}"))?;
            EventId::new(witness.membership_event_ref.clone())
                .map_err(|error| format!("invalid Realm fanout membership Event ref: {error}"))?;
            if !witnesses.insert((
                &witness.member_id,
                witness.membership_event_ref.as_str(),
                &witness.circle_membership_event_ref,
            )) {
                return Err("Realm fanout authority witnesses must be unique".to_owned());
            }
        }
        Ok(())
    }
}

/// G3.S0 — one outbound federation HTTP POST queued for the
/// `FederationDispatcher` background worker. See
/// `routing/federation/outbox.rs` for the worker loop and
/// the `federation_outbox` table in `migrations/00000000000000_initial/up.sql`
/// for the durable schema.
///
/// Timestamps are stored as unix-seconds (`i64`) to match the SQLite-style
/// schema defined in the spec subset; the Pg-backed store maps them to
/// `BIGINT`. The reason we don't use `TIMESTAMPTZ` here is so the SDK +
/// in-memory backend share the exact same numeric encoding the wire
/// receipts (`Idempotency-Key`, dispatcher logs) compare against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FederationOutboxRecord {
    /// ULID/UUID — primary key.
    pub id: String,
    /// Peer service identifier discovered from the configured federation endpoint.
    pub peer_id: DidCoreId,
    /// Historical candidate peer base URL. The dispatcher resolves the stable
    /// `peer_id` through the verified route store before every send; `None`
    /// means no deployment candidate was available at enqueue time.
    pub peer_url: Option<String>,
    /// Endpoint path on the peer, e.g. `/_arkret/peer/events`.
    pub endpoint: String,
    /// `Idempotency-Key` header value the dispatcher sends. Derived
    /// deterministically from `(origin, resource_kind, resource_id)` so
    /// transport retries collapse onto the same row server-side per
    /// `federation.md` §8.5. A semantic resubmission never reuses it.
    pub idempotency_key: String,
    /// Canonical request body the dispatcher POSTs verbatim.
    pub payload_json: String,
    /// Optional stable lane used by monotonic state replication. At most one
    /// unfinished row may exist for `(peer_id, coalescing_key)`; a higher
    /// `coalescing_position` atomically supersedes the older unfinished row.
    pub coalescing_key: Option<String>,
    /// Monotonic position within `coalescing_key` (account-status `status_seq`).
    pub coalescing_position: Option<i64>,
    /// Explicit lifecycle state — the single source of truth for whether this
    /// intent is still owed to the peer.
    pub state: FederationOutboxState,
    /// State replaced by `leased` while a worker owns the row. Required for
    /// exact read projection of pending_route versus pending_delivery.
    pub leased_from_state: Option<FederationOutboxState>,
    /// Present only for locally orchestrated Realm Event fanout.
    pub realm_fanout: Option<RealmFanoutBinding>,
    /// Number of completed transport attempts (excluding the next one).
    pub attempts: i32,
    /// Number of semantic resubmissions that produced this row. Bounded
    /// independently of the transport budget (`federation.md` §4.1 quarantine
    /// convergence bounds).
    pub semantic_attempts: i32,
    /// Unix seconds — earliest time the worker may claim this row.
    pub next_attempt_at: i64,
    /// Last observed HTTP status code. `None` when the attempt never reached a
    /// response (transport error) or before the first attempt.
    pub last_http_status: Option<i32>,
    /// Stable machine-readable classification of the last failure.
    pub last_error_code: Option<String>,
    /// First ~1 KiB of the most recent response body, for postmortem.
    pub last_response_excerpt: Option<String>,
    /// Worker identity currently holding the delivery lease.
    pub lease_owner: Option<String>,
    /// Random token proving lease ownership. Every terminal/retry write MUST
    /// present the matching token, so a stale holder's late response cannot
    /// overwrite the state a newer holder already wrote.
    pub lease_token: Option<String>,
    /// Unix seconds — when the current lease expires and the row becomes
    /// claimable again.
    pub lease_expires_at: Option<i64>,
    /// Egress policy version that suppressed this row, when
    /// `state == policy_suppressed`.
    pub policy_version: Option<String>,
    /// Diagnostic back-reference: the outbox row this one replaced through a
    /// semantic resubmission or an operator requeue.
    pub supersedes_outbox_id: Option<String>,
    /// Unix seconds — when the row was enqueued.
    pub created_at: i64,
    /// Unix seconds — when the row reached a terminal state. `None` while the
    /// row is still pending or leased.
    pub completed_at: Option<i64>,
}

/// Complete durable input for a Realm fanout outbox record.
#[derive(Clone, Debug)]
pub struct RealmFanoutOutboxInput {
    pub id: String,
    pub peer_id: DidCoreId,
    pub peer_url: Option<String>,
    pub endpoint: String,
    pub idempotency_key: String,
    pub payload_json: String,
    pub binding: RealmFanoutBinding,
    pub created_at: i64,
}

impl FederationOutboxRecord {
    pub fn validate_shape(&self) -> Result<(), String> {
        if self.coalescing_key.is_some() != self.coalescing_position.is_some() {
            return Err(
                "federation coalescing key and position must be present together".to_owned(),
            );
        }
        if self.coalescing_key.is_some() && self.realm_fanout.is_some() {
            return Err("Realm fanout rows cannot use a generic coalescing lane".to_owned());
        }
        if self
            .coalescing_position
            .is_some_and(|position| position < 0)
        {
            return Err("federation coalescing position cannot be negative".to_owned());
        }
        match self.realm_fanout.as_ref() {
            Some(binding) => {
                binding.validate()?;
                if matches!(
                    self.state,
                    FederationOutboxState::PolicySuppressed
                        | FederationOutboxState::DeadLettered
                        | FederationOutboxState::Superseded
                ) {
                    return Err(
                        "Realm fanout row entered a lifecycle outside the closed target state"
                            .to_owned(),
                    );
                }
            }
            None => {
                if matches!(
                    self.state,
                    FederationOutboxState::PendingRoute
                        | FederationOutboxState::CancelledAuthorityLost
                ) || self.leased_from_state == Some(FederationOutboxState::PendingRoute)
                {
                    return Err(
                        "generic federation row carries a Realm-only lifecycle state".to_owned(),
                    );
                }
            }
        }
        if self.state == FederationOutboxState::Leased {
            if self.leased_from_state.is_none()
                || self.lease_owner.is_none()
                || self.lease_token.is_none()
                || self.lease_expires_at.is_none()
            {
                return Err("leased federation row is missing lease state".to_owned());
            }
        } else if self.leased_from_state.is_some() {
            return Err("non-leased federation row carries leased_from_state".to_owned());
        }
        Ok(())
    }

    /// A freshly enqueued, never-attempted delivery intent.
    pub fn pending(
        id: String,
        peer_id: DidCoreId,
        peer_url: String,
        endpoint: String,
        idempotency_key: String,
        payload_json: String,
        created_at: i64,
    ) -> Self {
        Self {
            id,
            peer_id,
            peer_url: Some(peer_url),
            endpoint,
            idempotency_key,
            payload_json,
            coalescing_key: None,
            coalescing_position: None,
            state: FederationOutboxState::Pending,
            leased_from_state: None,
            realm_fanout: None,
            attempts: 0,
            semantic_attempts: 0,
            next_attempt_at: created_at,
            last_http_status: None,
            last_error_code: None,
            last_response_excerpt: None,
            lease_owner: None,
            lease_token: None,
            lease_expires_at: None,
            policy_version: None,
            supersedes_outbox_id: None,
            created_at,
            completed_at: None,
        }
    }

    /// Fresh generic delivery whose stable service identity is known but no
    /// deployment locator is configured. The worker keeps resolving that
    /// identity and applies the normal bounded retry policy.
    pub fn pending_without_locator(
        id: String,
        peer_id: DidCoreId,
        endpoint: String,
        idempotency_key: String,
        payload_json: String,
        created_at: i64,
    ) -> Self {
        let mut record = Self::pending(
            id,
            peer_id,
            String::new(),
            endpoint,
            idempotency_key,
            payload_json,
            created_at,
        );
        record.peer_url = None;
        record
    }

    pub fn realm_fanout(input: RealmFanoutOutboxInput) -> Self {
        let RealmFanoutOutboxInput {
            id,
            peer_id,
            peer_url,
            endpoint,
            idempotency_key,
            payload_json,
            binding,
            created_at,
        } = input;
        Self {
            id,
            peer_id,
            state: if peer_url.is_some() {
                FederationOutboxState::Pending
            } else {
                FederationOutboxState::PendingRoute
            },
            peer_url,
            endpoint,
            idempotency_key,
            payload_json,
            coalescing_key: None,
            coalescing_position: None,
            leased_from_state: None,
            realm_fanout: Some(binding),
            attempts: 0,
            semantic_attempts: 0,
            next_attempt_at: created_at,
            last_http_status: None,
            last_error_code: None,
            last_response_excerpt: None,
            lease_owner: None,
            lease_token: None,
            lease_expires_at: None,
            policy_version: None,
            supersedes_outbox_id: None,
            created_at,
            completed_at: None,
        }
    }

    /// Attach a monotonic coalescing lane to a generic pending delivery.
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_coalescing_lane(mut self, key: String, position: i64) -> Self {
        self.coalescing_key = Some(key);
        self.coalescing_position = Some(position);
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FederationOutboxDeadLetterRecord {
    pub id: String,
    pub outbox_id: String,
    pub peer_id: DidCoreId,
    pub endpoint: String,
    pub idempotency_key: String,
    pub last_http_status: Option<i32>,
    pub attempts: i32,
    pub response_excerpt: Option<String>,
    pub reason: String,
    pub failed_at: i64,
    /// Set when an operator replayed this dead letter into a fresh outbox row.
    pub requeued_outbox_id: Option<String>,
    pub requeued_by: Option<String>,
    pub requeue_reason: Option<String>,
    pub requeue_request_digest: Option<String>,
    pub requeued_at: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FederationFrontierExchangeRecord {
    pub realm_id: String,
    pub peer_id: DidCoreId,
    pub status: String,
    pub consecutive_failures: i32,
    pub last_success_at: Option<i64>,
    pub last_failure_at: Option<i64>,
    pub last_frontier_root: Option<String>,
    pub last_error: Option<String>,
    pub updated_at: i64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct FederationFrontierConfirmedEvidenceRecord {
    pub realm_id: String,
    pub peer_id: DidCoreId,
    pub evidence_scope_key: String,
    pub reason: String,
    pub evidence_scope: Value,
    pub observed_at: i64,
    /// Accepted resolution used only to normalize this node's local state.
    pub local_resolution_kind: Option<String>,
    pub local_resolution_digest: Option<String>,
    pub local_normalized_at: Option<i64>,
    /// Independent evidence that this exact peer aligned on this exact scope.
    pub peer_alignment_digest: Option<String>,
    pub peer_aligned_at: Option<i64>,
}

/// Local normalization of one disputed scope — the first of the two phases
/// that clear confirmed fork evidence.
///
/// It is projected only from an accepted `ak.fork.resolution` Control Move and
/// says nothing about any peer: a peer clears only after its own exact-scope
/// challenge shows a canonical sibling set equal to this verdict. The key is
/// the resolution cell subject alone, so single-bucket and cross-bucket
/// over-fork at one position can never produce two verdicts that disagree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FederationFrontierResolutionRecord {
    pub realm_id: String,
    pub cell_subject_key: String,
    pub subject: Value,
    pub verdict: Value,
    pub conflict_evidence_digest: String,
    pub resolution_event_digest: String,
    pub normalized_at: i64,
}

/// What one accepted verdict subtracts from the local accepted read surface.
///
/// This is the executable half of local normalization: the resolution record
/// says what was adjudicated, this says which Events stop being readable. Both
/// are written in one transaction, because a verdict that is durable while its
/// read-surface effect is not would let this Station disclose a sibling set
/// that contradicts a resolution it has already accepted.
///
/// The subtraction is by subject, not by a list of losing ids, so a sibling
/// that arrives after the verdict is excluded on arrival — `void_all` is final
/// for the position and `canonical_winner` cannot be reopened by a later
/// variant. Nothing is deleted: canonical bytes a Seal pinned, and the reducer
/// output it produced, are retained exactly as they were — a loser displaced by
/// a collision verdict moves to the collision bucket rather than disappearing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FederationForkNormalizationScope {
    /// `subject.kind=event_sibling_position`. Every Event at this exact
    /// `(realm_id, actor_id, actor_seq)` leaves the accepted read surface
    /// except `winner_event_id`; `None` is `void_all` and empties the position.
    SiblingPosition {
        actor_id: String,
        actor_seq: u64,
        winner_event_id: Option<String>,
    },
    /// `subject.kind=event_id_collision`. The local row for this identity stays
    /// readable only while its canonical preimage is byte-identical to the
    /// winning variant, which is the only way to tell two variants of one hash
    /// apart; `None` is `void_all`.
    EventIdCollision {
        event_id: String,
        winner_canonical_bytes: Option<Vec<u8>>,
        /// The covering Seal's `sealed_at`, in epoch milliseconds, or `None`
        /// for `void_all`.
        ///
        /// Spec section 6.3.3 point 3: an accepted `canonical_winner` is itself
        /// the admission authority for the winner's bytes, so a receiver that
        /// holds only the loser adopts the winner instead of staying unable to
        /// answer for that identity. That admission is required to be a pure
        /// function of `(winner bytes, resolution Seal)`, so the admitted
        /// Event's local receipt timestamp comes from the Seal rather than from
        /// a local clock — two receivers with different histories must end up
        /// byte-identical.
        winner_sealed_at_ms: Option<i64>,
    },
}

/// Durable progress through one immutable remote frontier observation.
///
/// The actor is the complete closed `ActorId`; a principal-only projection is
/// insufficient because Account actors at different Stations are distinct.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FederationFrontierReductionCheckpoint {
    pub realm_id: String,
    pub peer_id: DidCoreId,
    pub remote_snapshot_digest: String,
    pub actor_set_digest: String,
    pub actor_id: ActorId,
    pub cursor: Option<String>,
    pub updated_at: i64,
}

/// One admitted `SignalEnvelope` held for its TTL so subscribed devices in the
/// same scope can pick it up (`sync/signal.md` §4).
///
/// Every server-visible member here is copied from the envelope's own immutable
/// header, which is bound into the AEAD AAD. There is deliberately no
/// `signal_kind`, target, sequence or payload column: the exact payload type
/// and target live inside `encrypted_payload` and `signal.md` §1 forbids a
/// service from requiring or inferring a finer classification. Presence,
/// typing, call signalling and read receipts are all just Signals now, so they
/// share this one relay instead of four plaintext tables.
#[derive(Clone, Debug)]
pub struct SignalRelayRecord {
    pub realm_id: String,
    /// Signed security scope of the envelope. A Circle-scoped Signal is
    /// delivered only to that Circle's eligible devices.
    pub scope_ref: arkret_wire::ScopeRef,
    pub sender_actor_id: String,
    /// Present for an ordinary account-device sender and absent for an Agent.
    pub sender_device_id: Option<String>,
    /// The only server-visible product classification (`setup` / `moderation`
    /// / `session`).
    pub signal_class: arkret_wire::SignalClass,
    /// Digest of the complete admitted envelope. Used for short-lived replay
    /// suppression only; it is not a durable receipt.
    pub envelope_digest: String,
    pub sent_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// The verbatim admitted envelope handed to subscribers, so a receiver
    /// verifies `proof` over the exact canonical bytes the sender signed.
    pub envelope: arkret_wire::SignalEnvelope,
    /// Monotonic per-Realm position assigned by `SignalRelayStore::append`.
    /// Drives per-subscriber-device deliver-once: a subscriber's watermark
    /// records the highest `position` already delivered to that device, so an
    /// incremental re-subscribe inside the TTL window does not re-emit the same
    /// envelope. Producers leave this `0`; `append` overwrites it.
    pub position: u64,
}

#[derive(Clone, Debug)]
pub struct PolicyDocumentRecord {
    pub policy_id: String,
    pub owner: String,
    pub scope: String,
    pub subject_ref: String,
    pub policy_kind: String,
    pub payload: Value,
    pub active: bool,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct OrganizationRecord {
    pub organization_id: String,
    pub handle: Option<String>,
    pub display_name: String,
    pub source_refs: Vec<String>,
    pub policy_revision: String,
    pub verified: bool,
    pub members: BTreeSet<String>,
    pub member_count: usize,
    pub created_by: arkret_wire::DidCoreId,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// SOL-ORG-04 — durable row for one verified `ak.realm.organization`
/// relationship statement. Primary key `(realm_id, organization_id,
/// relationship)`. Field order mirrors the spec `realm_organization_payload`.
/// `control_scopes` is a JSON string array; the proof / delegation references
/// are stored as audit digests, never raw signature bytes.
#[derive(Clone, Debug)]
pub struct RealmOrganizationStatementRecord {
    pub realm_id: String,
    pub organization_id: DidCoreId,
    /// snake_case relationship: `owner` / `governance` / `sponsor` /
    /// `directory_certifier`.
    pub relationship: String,
    pub statement_id: String,
    /// `active` or `revoked`.
    pub status: String,
    pub control_scopes: Vec<String>,
    pub issued_at: chrono::DateTime<chrono::Utc>,
    pub not_before: Option<chrono::DateTime<chrono::Utc>>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub supersedes_statement_id: Option<String>,
    pub revokes_statement_id: Option<String>,
    pub realm_commit_ref: Option<String>,
    pub proof_digest: Option<String>,
    pub delegation_ref: Option<String>,
    pub issuer_role: String,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct RetentionPolicyRecord {
    pub realm_id: String,
    pub ttl_seconds: i64,
    pub updated_by: arkret_wire::ActorId,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct RetentionTombstoneRecord {
    pub event_id: String,
    pub realm_id: String,
    pub reason: String,
    pub policy_ttl_seconds: i64,
    pub expired_at: chrono::DateTime<chrono::Utc>,
    pub tombstoned_at: chrono::DateTime<chrono::Utc>,
    pub sealed: bool,
}

/// Durable closure of one founder-local Direct Conversation founding slot.
///
/// The unique key is the first three fields. Acceptance is the four consecutive
/// RealmCommits named by `event_ids`; the slot keeps no second receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectConversationFoundingSlotRecord {
    pub founder_id: String,
    pub trust_domain_id: String,
    pub pair_key: String,
    pub founding_unit_digest: String,
    pub realm_id: String,
    pub main_strand_id: String,
    pub authorization_basis: arkret_models_collaboration::objects::direct_conversation::DirectConversationAuthorizationBasis,
    pub event_ids: Vec<String>,
    pub idempotency_key: String,
    pub accepted_at: chrono::DateTime<chrono::Utc>,
}

/// One participant row in the durable Direct Conversation membership cut.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectConversationMemberCurrent {
    pub member_id: arkret_wire::ActorId,
    pub membership: String,
}

/// Resolver inputs read from accepted typed-current facts in one database
/// statement.  The HTTP resolver derives its closed state from this value;
/// it never consults the process-local binding/reducer projection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectConversationDurableState {
    pub founding_slot: DirectConversationFoundingSlotRecord,
    pub binding: Option<arkret_models_collaboration::events_payloads::direct_conversation::DirectConversationBindingCurrentValue>,
    pub group_state_ref: Option<arkret_wire::EventId>,
    pub group_current_exact_pair: Option<bool>,
    pub initial_exact_pair_group_state_ref: Option<arkret_wire::EventId>,
    pub peer_mls_admission: arkret_models_collaboration::direct_conversation::DirectConversationPeerMlsAdmission,
    pub members: Vec<DirectConversationMemberCurrent>,
}

/// A member Station's already verified, bounded public MLS replay input.
/// This is local provenance, never a wire carrier or governing admission state.
#[derive(Clone, Debug, PartialEq)]
pub struct ForeignDirectMlsInput {
    pub realm_id: arkret_wire::RealmId,
    pub caller: arkret_wire::ActorId,
    pub service_id: arkret_wire::DidCoreId,
    pub generation: u64,
    pub head: arkret_wire::CommitStreamHead,
    pub current: arkret_wire::TypedCurrentRow,
    /// Bounded signed Binding/MLS/member evidence, rechecked under the install lock.
    pub current_state_entries: Vec<arkret_wire::TypedCurrentRow>,
    pub participants: std::collections::BTreeSet<arkret_wire::ActorId>,
    pub history: Vec<(arkret_wire::RealmCommit, arkret_wire::Event)>,
    pub base: Option<ForeignDirectMlsBase>,
    pub replay_head: arkret_wire::CommitStreamHead,
    pub complete: bool,
    pub expected_initial_pair_ref: arkret_wire::EventId,
}
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ForeignDirectMlsBase {
    pub head: arkret_wire::CommitStreamHead,
    pub current_event_ref: arkret_wire::EventId,
    pub epoch: u64,
    pub covered_revision: u64,
    pub initial_pair_ref: Option<arkret_wire::EventId>,
    pub public_state: Vec<u8>,
}
