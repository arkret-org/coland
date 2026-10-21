use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::{
    AccountDataRecord, CanonicalEventRecord, ContactRecord, ContactVerifiedMirrorRecord,
    DeviceRevocationGateSelector, DeviceRevocationTransition, FederationOutboxRecord,
    IdempotencyRecord, PersistenceError, PersistenceResult, ProjectionEventRecord,
};

/// Project an already-admitted Agent cascade Event onto the frozen Agent ActorId
/// set. This is not admission authority: the full signed actor (including its
/// hosting Station) must remain identical in the canonical record and payload.
/// An adapter must never guess an Agent's Station from its controller.
pub fn admitted_cascade_agent_id(
    record: &CanonicalEventRecord,
) -> PersistenceResult<arkret_wire::ActorId> {
    let event: arkret_wire::Event =
        serde_json::from_value(record.envelope.clone()).map_err(|error| {
            PersistenceError::SchemaViolation(format!("invalid Agent cascade Event: {error}"))
        })?;
    let arkret_wire::ActorId::Account { .. } = &event.actor_id else {
        return Err(PersistenceError::Conflict(
            "Agent cascade requires an account actor".to_owned(),
        ));
    };
    if record.actor_id != event.actor_id.to_string()
        || event.kind != arkret_wire::EventKind::MemberState
        || event
            .payload
            .get("member_id")
            .and_then(|member| serde_json::from_value::<arkret_wire::ActorId>(member.clone()).ok())
            .as_ref()
            != Some(&event.actor_id)
    {
        return Err(PersistenceError::Conflict(
            "Agent cascade canonical actor does not bind the full Event member".to_owned(),
        ));
    }
    Ok(event.actor_id)
}

/// Contact projection mutation installed with its authority commit.
#[derive(Clone, Debug)]
pub struct ContactProjectionCommit {
    pub completion_intent: Option<crate::ContactCompletionIntent>,
    pub record: Box<ContactRecord>,
    pub expected_updated_at: Option<chrono::DateTime<chrono::Utc>>,
    pub conflict_code: String,
    pub verified_mirror: Option<ContactVerifiedMirrorRecord>,
    /// Optional holder-private policy mutation committed in the same unit as
    /// the Contact Event and lineage projection.
    pub invite_policy: Option<(
        arkret_wire::AccountId,
        arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy,
    )>,
}

/// All durable writes produced by accepting one canonical event.
///
/// Adapters must make the complete request visible atomically. Returning an
/// error must leave the event log, projection log, idempotency table, and
/// federation outbox unchanged.
/// One account-data register replaced by revision CAS inside an Event commit.
#[derive(Clone, Debug)]
pub struct AccountDataCasCommit {
    pub record: AccountDataRecord,
    pub expected_revision: u64,
    pub conflict_code: String,
}

/// Fresh Service document for one Applet Event, re-bound to the accepted epoch
/// and verified inside its accepting domain transaction. This is not a verdict.
#[derive(Clone, Debug)]
pub struct AppletEventProducerGuard {
    pub service_did_document: arkret_identity::DidDocument,
}

#[derive(Clone, Debug)]
pub struct EventCommitRequest {
    pub verified_media_participant: Option<arkret_signatures::media::VerifiedCallParticipant>,
    /// Current-authority transaction that orders the producer Event on its
    /// Realm, Circle, or Sidecar stream.
    pub authority_commit: crate::AuthorityCommitTransaction,
    /// Current producer authorization rechecked under this same Event/Commit,
    /// projection and CAS transaction for self submissions.
    pub self_producer_guard: Option<crate::SelfProducerCommitGuard>,
    pub applet_producer_guard: Option<AppletEventProducerGuard>,
    pub widget_token_gate: Option<crate::AppletWidgetTokenGateSelector>,
    /// Verifier-private subject evidence, rechecked inside the grant transaction.
    pub agent_grant_scope_evidence: Option<crate::VerifiedAgentScopeEvidence>,
    /// Cross-Station human-device producer evidence verified from an
    /// `authority_forward`; retained only with the Event's first Commit.
    pub forwarded_producer_evidence: Option<crate::ForwardedProducerDeviceEvidence>,
    pub forwarded_agent_producer:
        Option<arkret_identity::agent_authority_evidence::VerifiedAgentProducer>,
    pub agent_deployment_ceiling:
        arkret_models_collaboration::governance::agent_participation::ParticipationBits,
    pub event: CanonicalEventRecord,
    /// Internal result of projection-owned join-gate validation.  It is not
    /// authority: PostgreSQL must lock the exact policy named by the digest
    /// and re-evaluate all `parent_membership` dependencies before writing.
    pub parent_membership_admission: Option<ParentMembershipAdmissionCheck>,
    pub contact_projection: Option<ContactProjectionCommit>,
    /// Reducer-derived target for an accepted `ak.device.revoke`.
    pub device_revocation_transition: Option<DeviceRevocationTransition>,
    /// Exact author-device generation rechecked inside the Event transaction.
    pub device_revocation_gate: Option<DeviceRevocationGateSelector>,
    pub projections: Vec<ProjectionEventRecord>,
    pub idempotency: Option<IdempotencyRecord>,
    pub outbox: Vec<FederationOutboxRecord>,
    /// The exact admission submission a Realm-stream Event was committed
    /// from. The transaction plans its committed-replication fanout
    /// (`federation.md` §4.1.1) from the same accepted cut it writes; an
    /// Event whose Realm has a remote joined member cannot commit without it.
    pub realm_fanout_source: Option<arkret_wire::EventAdmissionSubmission>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParentMembershipAdmissionCheck {
    pub expected_join_policy_digest: arkret_wire::Hash,
    /// `true` when the join-policy combinator can pass only if at least one
    /// source member row is currently `join`; `false` means another `any`
    /// branch already passed, while the durable dependency cut still needs
    /// revalidation.
    pub require_joined_source: bool,
}

/// Applet projection mutation committed with a closed Event aggregate.
#[derive(Clone, Debug)]
pub struct AppletRecordCommit {
    pub applet_id: arkret_wire::AppletId,
    /// The accepted managed-actor identity winner used by this installation.
    /// `expected_record=None` is an insert-only first install; `Some` requires
    /// the already accepted winner to remain byte-for-byte unchanged.
    pub identity: AppletIdentityCommit,
    /// Exact durable record observed while validating the aggregate. `None`
    /// means the Applet must not exist and this mutation is an insert.
    pub expected_record: Option<serde_json::Value>,
    pub record: serde_json::Value,
}

#[derive(Clone, Debug)]
pub struct AppletIdentityCommit {
    pub target_station_id: arkret_wire::DidCoreId,
    pub expected_record: Option<serde_json::Value>,
    pub record: serde_json::Value,
}

/// Stable storage coordinate for one effective Applet installation. The
/// canonical scope JSON, rather than an ad-hoc realm/circle concatenation,
/// keeps Realm and Circle installs disjoint and gives every backend the same
/// composite-key derivation.
pub fn applet_effective_scope_key(scope: &arkret_wire::ScopeRef) -> PersistenceResult<String> {
    arkret_canonical::canonical_sha256(scope).map_err(|error| {
        PersistenceError::Conflict(format!(
            "schema_violation: Applet effective_scope is not canonical: {error}"
        ))
    })
}

pub fn applet_effective_scope_key_from_record(
    record: &serde_json::Value,
) -> PersistenceResult<String> {
    let scope = record.get("effective_scope").cloned().ok_or_else(|| {
        PersistenceError::Conflict(
            "schema_violation: durable Applet installation omits effective_scope".to_owned(),
        )
    })?;
    let scope: arkret_wire::ScopeRef = serde_json::from_value(scope).map_err(|error| {
        PersistenceError::Conflict(format!(
            "schema_violation: durable Applet effective_scope is invalid: {error}"
        ))
    })?;
    applet_effective_scope_key(&scope)
}

pub fn applet_id_from_record(record: &serde_json::Value) -> PersistenceResult<&str> {
    record
        .get("applet_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            PersistenceError::Conflict(
                "schema_violation: Applet installation record is missing applet_id".to_owned(),
            )
        })
}

/// Installation records are exact per-scope state only. Reject identity
/// anchors here as well as in the typed HTTP codec and PostgreSQL CHECK so the
/// memory and PostgreSQL adapters cannot drift into copying the accepted
/// identity winner back into every installation.
pub fn validate_applet_installation_record(record: &serde_json::Value) -> PersistenceResult<()> {
    const IDENTITY_FIELDS: &[&str] = &[
        "identity",
        "registry_id",
        "bot_actor_id",
        "bot_actor_station_id",
        "bot_actor_provision_ref",
        "bot_principal_control_realm_id",
        "initial_package",
        "initial_owner_actor_id",
        "initial_effective_scope",
        "initial_registration_event",
        "initial_capability_grant_refs",
        "bot_actor_provision_event",
        "bot_pcr_genesis_event",
        "bot_accountability_grant_event",
        "bot_profile_event",
        "globally_fenced_at",
    ];
    let object = record.as_object().ok_or_else(|| {
        PersistenceError::Conflict(
            "schema_violation: durable Applet installation is not an object".to_owned(),
        )
    })?;
    if let Some(field) = IDENTITY_FIELDS
        .iter()
        .find(|field| object.contains_key(**field))
    {
        return Err(PersistenceError::Conflict(format!(
            "schema_violation: Applet installation contains managed identity field {field}"
        )));
    }
    Ok(())
}

/// Decode the canonical namespace source from a strict durable Applet record.
///
/// The namespace claim table is a transaction-local conflict index, not a
/// second protocol carrier. Every adapter derives it from
/// `record.package.namespaces`; callers cannot supply an independently
/// drifting mirror.
pub fn applet_namespaces_from_record(
    record: &serde_json::Value,
) -> PersistenceResult<arkret_models_integration::AppletWireNamespaces> {
    let namespaces = record
        .pointer("/package/namespaces")
        .cloned()
        .ok_or_else(|| {
            PersistenceError::Conflict(
                "schema_violation: durable Applet record omits package.namespaces".to_owned(),
            )
        })?;
    serde_json::from_value(namespaces).map_err(|error| {
        PersistenceError::Conflict(format!(
            "schema_violation: durable Applet package.namespaces are invalid: {error}"
        ))
    })
}

/// All durable writes produced by accepting a closed multi-Event aggregate.
#[derive(Clone, Debug)]
pub struct RealmOrganizationProofCommit {
    pub event_id: arkret_wire::EventId,
    pub verification_method: arkret_wire::DidUrl,
    pub signed_at: DateTime<Utc>,
    pub public_key: [u8; 32],
}

/// Independently resolved historical keys for one exact Invite claim cut.
/// Prepared by the service, never deserialized from a caller's wire request.
#[derive(Clone, Debug)]
pub struct InviteClaimProofCommit {
    pub event_id: arkret_wire::EventId,
    pub event_digest: String,
    pub create_ref: arkret_wire::CommittedEventRef,
    pub committed_at: DateTime<Utc>,
    pub subject_public_key: [u8; 32],
    pub subject_native_control:
        Option<arkret_identity::principal_control::NativeIdentityControlKey>,
    pub subject_control_history: Option<serde_json::Value>,
    pub binding_public_key: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct EventBatchCommitRequest {
    pub audit_unit: Option<crate::RegisteredAuditCommit>,
    pub events: Vec<EventCommitRequest>,
    /// One moderation franking nonce consumed by a report Event in this
    /// batch. The ledger write is inseparable from the report Event: a failed
    /// commit consumes nothing, and a concurrent replay can commit at most
    /// once across processes.
    pub franking_replay_nonce: Option<FrankingReplayNonceCommit>,
    pub realm_organization_proof: Option<RealmOrganizationProofCommit>,
    pub invite_claim_proof: Option<InviteClaimProofCommit>,
    pub event_approvals: Option<crate::EventApprovalCommit>,
    pub applet_record: Option<AppletRecordCommit>,
    pub applet_authoring_preview: Option<AppletAuthoringPreviewCommit>,
    pub agent_membership_cascade: Option<crate::AgentMembershipCascadeCommit>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrankingReplayNonceCommit {
    pub realm_id: String,
    pub received_by: arkret_identifiers::DidCoreId,
    pub replay_nonce: String,
    pub report_event_id: String,
    pub consumed_at: DateTime<Utc>,
}

/// Coland's local retention default for a consumed franking nonce. The wire
/// protocol requires a finite window but does not assign its duration.
pub const LOCAL_FRANKING_REPLAY_NONCE_TTL_SECONDS: i64 = 24 * 60 * 60;

/// Coland's local active-row ceiling per `(realm_id, received_by)` scope.
/// Capacity exhaustion fails closed instead of evicting an active nonce.
pub const LOCAL_FRANKING_REPLAY_NONCE_MAX_ACTIVE_PER_SCOPE: usize = 4096;

pub fn franking_replay_nonce_expires_at(
    consumed_at: DateTime<Utc>,
) -> PersistenceResult<DateTime<Utc>> {
    consumed_at
        .checked_add_signed(chrono::TimeDelta::seconds(
            LOCAL_FRANKING_REPLAY_NONCE_TTL_SECONDS,
        ))
        .ok_or_else(|| {
            PersistenceError::Conflict(
                "schema_violation: franking nonce expiry overflows canonical time".to_owned(),
            )
        })
}

/// Refuse a nonce ledger row unless the same batch contains the exact report
/// Event and its signed franking payload. Persistence repeats this binding so
/// a future caller cannot accidentally turn the ledger into an unscoped
/// uniqueness service.
pub fn validate_franking_replay_nonce_commit(
    events: &[EventCommitRequest],
    commit: Option<&FrankingReplayNonceCommit>,
) -> PersistenceResult<()> {
    let Some(commit) = commit else {
        return Ok(());
    };
    let Some(report) = events
        .iter()
        .find(|request| request.event.event_id == commit.report_event_id)
    else {
        return Err(PersistenceError::Conflict(
            "schema_violation: franking nonce is not bound to a report Event in the batch"
                .to_owned(),
        ));
    };
    if report.event.kind != arkret_wire::EventKind::SelfModerationReport.as_str()
        || report.event.realm_id.as_deref() != Some(commit.realm_id.as_str())
        || report
            .event
            .envelope
            .pointer("/payload/franking_proof/received_by")
            .and_then(Value::as_str)
            != Some(commit.received_by.as_str())
        || report
            .event
            .envelope
            .pointer("/payload/franking_proof/replay_nonce")
            .and_then(Value::as_str)
            != Some(commit.replay_nonce.as_str())
    {
        return Err(PersistenceError::Conflict(
            "schema_violation: franking nonce does not match its report Event payload".to_owned(),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub struct AppletAuthoringPreviewCommit {
    pub subject_key: String,
    pub request_digest: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EventCommitOutcome {
    pub audit_outcome: Option<crate::RegisteredAuditOutcome>,
    pub event_inserted: bool,
    pub projections_inserted: usize,
    pub outbox_inserted: usize,
}

#[async_trait]
pub trait EventCommitUnitOfWork: Send + Sync {
    async fn commit_event(
        &self,
        request: EventCommitRequest,
    ) -> PersistenceResult<EventCommitOutcome>;

    async fn commit_event_batch(
        &self,
        request: EventBatchCommitRequest,
    ) -> PersistenceResult<EventCommitOutcome>;
}
