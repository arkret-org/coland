//! Backend-neutral persistence records, ports, and adapter contracts.
//!
//! PostgreSQL is Coland's current durable production adapter, but it is not
//! part of this crate's public boundary. A future SQLite or other durable
//! adapter implements these same ports and contract suites without exposing
//! backend client, query, transaction, or row types to services and HTTP.
//! Backend-specific code belongs in an adapter crate such as
//! `coland-storage-postgres`.

// Crate-private imports shared by the explicitly imported storage modules.
pub(crate) use std::collections::{BTreeMap, BTreeSet};

pub(crate) use arkret_event_draft::ProjectedEventOperation;
pub(crate) use async_trait::async_trait;
pub(crate) use chrono::Utc;
pub use coland_contracts::agent_session_authority::{
    AgentSessionAuthorityOutcome, AgentSessionAuthorityRequest,
};
pub use coland_domain::identity::{ContactRecord, ContactRequestSlotState};
pub(crate) use serde_json::Value;
pub(crate) use uuid::Uuid;

mod agent_draft_pending_intents;
mod agent_membership_cascades;
mod agent_principal;
pub use agent_draft_pending_intents::*;
mod records;
pub use agent_membership_cascades::*;
pub use agent_principal::{AgentPrincipalRecord, PendingAgentPairingCommitIntent};
pub use records::*;

mod account_device_signer_evidence;
mod account_status;
mod accounts;
mod actor_private_events;
mod actor_profiles;
mod agents;
mod applet_widget_tokens;
mod applets;
pub use applet_widget_tokens::*;
mod agent_management;
mod approval_admission;
mod audit;
mod authority_commit;
mod backup_series_erase;
mod blobs;
mod consent_current;
mod consent_request_quarantine;
mod contacts;
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod contract_tests;
mod device_revocations;
mod devices;
mod events;
mod federation;
mod franking;
mod governance;
mod grant_evaluation;
mod idempotency;
#[doc(hidden)]
pub mod ids;
mod invite_locators;
mod invite_new_source_ledger;
mod key_backup;
mod member_identity;
mod mls;
mod moderation;
mod notifications;
mod organization_registration;
#[cfg(test)]
mod owned_result_layout_tests;
mod policy;
mod principal_resolution;
mod projection;
pub use agent_management::agent_management_actions;
mod publication_evidence;
mod push;
mod push_handoff;
mod read_cursors;
mod realm_invites;
mod recovery;
mod service_identity;
mod service_route;
mod sessions;
mod sidecars;
mod signal;
mod sync_cursor;
pub use approval_admission::*;
mod unit_of_work;
mod websocket_auth;
mod webvh;
mod webvh_freshness;
pub use account_device_signer_evidence::*;
pub use account_status::*;
pub use accounts::*;
pub use actor_private_events::*;
pub use actor_profiles::*;
pub use agents::*;
pub use applets::*;
pub use audit::*;
pub use authority_commit::*;
pub use backup_series_erase::*;
pub use blobs::*;
pub use consent_current::*;
pub use consent_request_quarantine::*;
pub use contacts::*;
pub use device_revocations::*;
pub use devices::*;
pub use events::*;
pub use federation::*;
pub use franking::*;
pub use governance::*;
pub use grant_evaluation::*;
pub use idempotency::*;
pub use invite_locators::*;
pub use invite_new_source_ledger::*;
pub use key_backup::*;
pub use member_identity::*;
pub use mls::*;
pub use moderation::*;
pub use notifications::*;
pub use organization_registration::*;
pub use policy::*;
pub use principal_resolution::*;
pub use projection::*;
pub use publication_evidence::*;
pub use push::*;
pub use push_handoff::*;
pub use read_cursors::*;
pub use realm_invites::*;
pub use recovery::*;
pub use service_identity::*;
pub use service_route::*;
pub use sessions::*;
pub use sidecars::*;
pub use signal::*;
pub use sync_cursor::*;
mod current_sync;
pub use current_sync::*;
pub use unit_of_work::*;
pub use websocket_auth::*;
pub use webvh::*;
pub use webvh_freshness::{webvh_freshness_on_put, *};

/// Error type for persistence operations.
#[derive(Debug, thiserror::Error)]
pub enum PersistenceError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("database error: {0}")]
    Database(String),
    /// SOL-COR-02: a malformed typed wire ID reached a persistence boundary
    /// that handles untrusted input. Surfaces as the `schema_violation` wire
    /// reason instead of panicking the request task.
    #[error("schema violation: {0}")]
    SchemaViolation(String),
    #[error("internal error: {0}")]
    Internal(String),
}

/// Result type for persistence operations.
pub type PersistenceResult<T> = Result<T, PersistenceError>;

impl PersistenceError {
    pub fn database(error: impl std::fmt::Display) -> Self {
        Self::Database(error.to_string())
    }

    /// The registered conflict code this error carries, if any.
    ///
    /// See [`ConflictCode`] for why callers must use this instead of
    /// inspecting the detail text.
    #[must_use]
    pub fn conflict_code(&self) -> Option<ConflictCode> {
        match self {
            Self::Conflict(detail) => ConflictCode::from_detail(detail),
            _ => None,
        }
    }
}

/// A conflict reason that a routing layer is allowed to act on.
///
/// [`PersistenceError::Conflict`] carries a detail string shaped as either the
/// bare code (`"cas_conflict"`) or `"<code>: <diagnostics>"`. Everything that
/// turns a conflict into an HTTP status, a wire reason, or a signed decision
/// MUST read the code through [`ConflictCode::from_detail`] and `match` it
/// exhaustively. Substring matching on the detail is forbidden: it makes the
/// routing decision depend on diagnostic wording, it silently reorders into an
/// undeclared priority when several branches match, and it cannot distinguish
/// "this conflict has no registered code" from "no branch matched" -- which is
/// how an unclassified conflict used to leave the event-submit lane as a 500.
///
/// A detail with no registered prefix yields `None`. That is a real state:
/// several persistence conflicts are local invariant breaches with no protocol
/// code, and they must surface as an internal failure rather than be guessed
/// into a caller-facing reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ConflictCode {
    /// A Agent act-on-behalf approval nonce was already consumed.
    ApprovalNonceReused,
    /// A List WIP review is required but no verified approval reached this unit.
    ApprovalRequired,
    /// The applet was revoked between admission and commit.
    AppletRevoked,
    /// The exact installation has no independent current MLS join consent.
    AppletE2eeJoinUnauthorized,
    /// An Actor Profile `accountable_principal_ids` entry has no committed
    /// active accountability record at the accepting Commit
    /// (`zh/models/actor.md` section 3.3.1).
    AccountabilityGrantMissing,
    /// A KeyBackup request's pointer, series or device generation is no
    /// longer current (key-management.md §7.6).
    BackupRevisionStale,
    /// The Event producer holds no capability, at the accepting cut, for the
    /// transition it requests, or is not a joined member of its Realm.
    CapabilityDenied,
    /// The expected typed current revision differs from the accepting cut.
    CasConflict,
    /// An exact source needed for a current reducer result is unavailable.
    DependencyMissing,
    /// The exact device generation is no longer current.
    DeviceGenerationFenced,
    /// The exact device generation has an unresolved revoke proposal.
    DeviceRevocationPending,
    /// The exact device generation has a covering revoke Commit.
    DeviceRevoked,
    /// The device is not authorized at the admission instant, or its
    /// forwarded authorization evidence has expired.
    DeviceUnauthorized,
    /// A native DID successor fails its accepted method boundary.
    DidMethodSuccessorInvalid,
    /// The same identity already exists with different canonical bytes.
    DuplicateConflict,
    /// An encrypted application Event freezes an MLS epoch or group state
    /// other than the ready current group.
    EpochMismatch,
    /// The scope's key-access checkpoint awaits a covering winning MLS Commit.
    EpochUpdateRequired,
    /// A Call genesis selects a non-initial lifecycle state.
    CallStateTransitionInvalid,
    /// Two verified Event variants share one full EventId. Internal name for
    /// what the wire calls `witness_disagreement`.
    EventHashCollision,
    /// A stored Event id does not match its canonical digest.
    EventIdDigestMismatch,
    /// A projection was requested for an Event that was never accepted.
    EventNotAccepted,
    /// A declared precondition does not hold.
    FailedPrecondition,
    /// A Strand transition or Message targets an archived Strand.
    StrandNotActive,
    /// A Strand restore targets one that is not archived.
    StrandNotArchived,
    /// A Strand write targets terminal redacted state.
    StrandAlreadyTerminal,
    /// A Space archive targets one that is not active.
    SpaceNotActive,
    /// A Space restore targets one that is not archived.
    SpaceNotArchived,
    /// A Space lifecycle write targets a tombstoned Space.
    SpaceAlreadyTerminal,
    /// A Space tombstone still has a live child or Strand placement.
    SpaceHasLiveDependents,
    /// The signed parent pre-state differs from the current parent register.
    SpaceParentMismatch,
    /// The parent structural evidence is not readable at the operation cut.
    SpaceParentUnreadable,
    /// A readable canonical parent belongs to a different Realm.
    SpaceRealmMismatch,
    /// A structural Relation endpoint is not an object of the Relation's own
    /// Realm (`relation.md` section 4.4).
    CrossRealmStructuralRelation,
    /// A Realm entry was refused by its join rule or join policy; the
    /// applicant sees one non-enumerating result (`join-policy.md` §4).
    GateCheckFailed,
    /// A Realm or Circle membership edge is outside its registered FSM.
    InvalidMembershipTransition,
    /// The candidate durable Realm cut cannot be represented by the bounded
    /// inline v1 snapshot.
    SnapshotCapacityExceeded,
    /// A plaintext application body targets a scope with accepted MLS genesis.
    MlsActivationRequired,
    /// A second `ak.mls.genesis` targets a scope whose Genesis is accepted.
    MlsActivationIrreversible,
    /// An MLS transition's governance binding differs from the scope's
    /// current group, its Event payload or its GroupContext extension.
    GovernanceBindingMismatch,
    /// A `restricted` / `knock_restricted` join rule has no automatic gate in
    /// the Realm's join policy (`join-policy.md` §2).
    JoinRulePolicyMismatch,
    PolicyRevisionRollback,
    PolicyRevisionGap,
    PinTargetNotPinned,
    /// Membership compensation evidence changed, expired, or was consumed.
    MembershipCompensationConflict,
    /// MIMI migration lineage, selected topology, or current MLS binding fails.
    MimiRoomBindingMigrationProofInvalid,
    /// The exact recipient endpoint has no remaining queue capacity.
    RecipientQueueAtCapacity,
    /// Every grant that would allow the operation has exhausted its hard
    /// rate quota (`constraint-schema.md` section 8.1).
    RateLimited,
    /// The Realm is archived or frozen and the write is outside the closed
    /// exemption set (`realm-and-space.md` section 2.6.0).
    RealmFrozen,
    /// The actor chain exceeded its sibling or predecessor fork cap.
    ForkQuarantine,
    /// A Realm with this id already exists.
    RealmAlreadyExists,
    /// A recovery-policy write violates a non-specific policy invariant.
    RecoveryPolicyConflict,
    /// A recovery-policy version does not advance the active version.
    RecoveryPolicyVersionNotMonotonic,
    /// A recovery policy does not supersede the active policy exactly.
    RecoveryPolicySupersedesInvalid,
    /// The first accepted recovery policy of an account is not version 1.
    RecoveryPolicyGenesisNotV1,
    /// A recovery session with the requested id already exists.
    RecoverySessionAlreadyExists,
    /// A registered reducer could not produce the required typed result.
    ReducerProjectionFailed,
    /// The organization registration challenge does not match.
    OrganizationRegistrationChallengeInvalid,
    /// The organization registration was revoked.
    OrganizationRegistrationRevoked,
    /// The organization registration generation is stale.
    OrganizationRegistrationStale,
    /// The value violates its registered schema.
    SchemaViolation,
    /// A required signature or proof does not verify.
    SignatureInvalid,
    /// A key-backup series sequence went backwards.
    SeriesSeqNotMonotonic,
    /// A time-bounded workflow was acted on after its deadline.
    TtlExpired,
    /// A read dependency is momentarily unavailable; nothing was committed and
    /// the exact request may be retried.
    TemporarilyUnavailable,
    /// A structurally valid wire feature has no admissible v1 form.
    UnsupportedFeature,
    /// A directed `ak.invite.create` targets an account whose live-target
    /// slot is occupied; the detail after the code is the occupant's exact
    /// create Event id.
    InviteLiveTargetOccupied,
    /// The payload invitee and the stored directed invitee disagree.
    InviteDirectedInviteeMismatch,
    /// `ak.invite.cancel` targets an Invite without a stored directed invitee.
    InviteKindRequiresRevoke,
    /// The target Invite is already in a terminal lifecycle state.
    InviteAlreadyTerminal,
    /// A Capability Grant names authority its issuer does not hold at the
    /// accepting cut (`capabilities.md` §3.2).
    GrantExceedsIssuerAuthority,
    /// A Capability Grant's issuer chain loops back on itself.
    AuthorityCycle,
    /// A child Capability Grant outlives its issuer's authority.
    AuthorityExpiryWidening,
    /// `ak.capability.relinquish` by an actor other than the grant subject.
    GrantRelinquishNotSubject,
    /// A Direct Conversation founding unit is not the closed caller-authored
    /// four-Event unit (contact-and-direct-conversation.md section 6.1).
    DirectConversationFoundingUnitInvalid,
    /// The founder's local founding slot is already closed by another unit.
    DirectConversationSlotAlreadyCommitted,
    /// Binding integrity stage of the Direct Conversation admission table.
    DirectConversationBindingInvalid,
    /// Terminal guard stage of the Direct Conversation admission table.
    DirectConversationTerminalForbidden,
    /// Exact-two stage of the Direct Conversation admission table.
    DirectConversationMemberCountInvalid,
    /// Third-party member stage of the Direct Conversation admission table.
    DirectConversationThirdPartyMemberForbidden,
    /// Active-profile invite stage of the Direct Conversation admission table.
    DirectConversationInviteForbidden,
    /// Technical root phase-mask stage of the Direct Conversation admission table.
    DirectConversationRootMaskViolation,
    /// The closed participant evaluator denied an allowlisted action.
    DirectConversationParticipantAuthorityDenied,
    /// `ak.space.*` targets a Direct Conversation Realm.
    DirectConversationSpaceForbidden,
    /// A second `ak.agent.provision` declares an `agent_id` an accepted
    /// provision in the controller PCR already carries.
    AgentProvisioningAlreadyDeclared,
    /// A second `ak.agent.provision` declares an Agent PCR id an accepted
    /// provision already claims.
    AgentPcrGenesisDeclarationConflict,
    /// An Agent PCR genesis has no accepted provision declaring its id.
    AgentPcrGenesisDeclarationMissing,
    /// An Agent grant exceeds the immutable disclosed provision ceiling.
    AgentGrantExceedsRequestedScope,
    /// The Agent scope lacks qualified accepted-at private evidence.
    AgentRequestedScopeCommitmentInvalid,
}

impl ConflictCode {
    /// Every registered code, in the order the variants are declared.
    pub const ALL: [Self; 88] = [
        Self::ApprovalNonceReused,
        Self::ApprovalRequired,
        Self::AppletRevoked,
        Self::AppletE2eeJoinUnauthorized,
        Self::AccountabilityGrantMissing,
        Self::BackupRevisionStale,
        Self::CapabilityDenied,
        Self::CasConflict,
        Self::DependencyMissing,
        Self::DeviceGenerationFenced,
        Self::DeviceRevocationPending,
        Self::DeviceRevoked,
        Self::DeviceUnauthorized,
        Self::DidMethodSuccessorInvalid,
        Self::DuplicateConflict,
        Self::EpochMismatch,
        Self::EpochUpdateRequired,
        Self::CallStateTransitionInvalid,
        Self::EventHashCollision,
        Self::EventIdDigestMismatch,
        Self::EventNotAccepted,
        Self::FailedPrecondition,
        Self::StrandNotActive,
        Self::StrandNotArchived,
        Self::StrandAlreadyTerminal,
        Self::SpaceNotActive,
        Self::SpaceNotArchived,
        Self::SpaceAlreadyTerminal,
        Self::SpaceHasLiveDependents,
        Self::SpaceParentMismatch,
        Self::SpaceParentUnreadable,
        Self::SpaceRealmMismatch,
        Self::CrossRealmStructuralRelation,
        Self::GateCheckFailed,
        Self::InvalidMembershipTransition,
        Self::SnapshotCapacityExceeded,
        Self::MlsActivationRequired,
        Self::MlsActivationIrreversible,
        Self::GovernanceBindingMismatch,
        Self::JoinRulePolicyMismatch,
        Self::PolicyRevisionRollback,
        Self::PolicyRevisionGap,
        Self::PinTargetNotPinned,
        Self::MembershipCompensationConflict,
        Self::MimiRoomBindingMigrationProofInvalid,
        Self::RecipientQueueAtCapacity,
        Self::RateLimited,
        Self::RealmFrozen,
        Self::ForkQuarantine,
        Self::RealmAlreadyExists,
        Self::RecoveryPolicyConflict,
        Self::RecoveryPolicyVersionNotMonotonic,
        Self::RecoveryPolicySupersedesInvalid,
        Self::RecoveryPolicyGenesisNotV1,
        Self::RecoverySessionAlreadyExists,
        Self::ReducerProjectionFailed,
        Self::OrganizationRegistrationChallengeInvalid,
        Self::OrganizationRegistrationRevoked,
        Self::OrganizationRegistrationStale,
        Self::SchemaViolation,
        Self::SignatureInvalid,
        Self::SeriesSeqNotMonotonic,
        Self::TtlExpired,
        Self::TemporarilyUnavailable,
        Self::UnsupportedFeature,
        Self::InviteLiveTargetOccupied,
        Self::InviteDirectedInviteeMismatch,
        Self::InviteKindRequiresRevoke,
        Self::InviteAlreadyTerminal,
        Self::GrantExceedsIssuerAuthority,
        Self::AuthorityCycle,
        Self::AuthorityExpiryWidening,
        Self::GrantRelinquishNotSubject,
        Self::DirectConversationFoundingUnitInvalid,
        Self::DirectConversationSlotAlreadyCommitted,
        Self::DirectConversationBindingInvalid,
        Self::DirectConversationTerminalForbidden,
        Self::DirectConversationMemberCountInvalid,
        Self::DirectConversationThirdPartyMemberForbidden,
        Self::DirectConversationInviteForbidden,
        Self::DirectConversationRootMaskViolation,
        Self::DirectConversationParticipantAuthorityDenied,
        Self::DirectConversationSpaceForbidden,
        Self::AgentProvisioningAlreadyDeclared,
        Self::AgentPcrGenesisDeclarationConflict,
        Self::AgentPcrGenesisDeclarationMissing,
        Self::AgentGrantExceedsRequestedScope,
        Self::AgentRequestedScopeCommitmentInvalid,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AgentGrantExceedsRequestedScope => {
                arkret_wire::ReasonCode::AGENT_GRANT_EXCEEDS_REQUESTED_SCOPE
            }
            Self::AgentRequestedScopeCommitmentInvalid => {
                arkret_wire::ReasonCode::AGENT_REQUESTED_SCOPE_COMMITMENT_INVALID
            }
            Self::ApprovalNonceReused => arkret_wire::ReasonCode::APPROVAL_NONCE_REUSED,
            Self::ApprovalRequired => arkret_wire::ReasonCode::APPROVAL_REQUIRED,
            Self::AppletRevoked => "applet_revoked",
            Self::AppletE2eeJoinUnauthorized => {
                arkret_wire::ErrorCode::APPLET_E2EE_JOIN_UNAUTHORIZED
            }
            Self::AccountabilityGrantMissing => {
                arkret_wire::ReasonCode::ACCOUNTABILITY_GRANT_MISSING
            }
            Self::BackupRevisionStale => arkret_wire::ReasonCode::BACKUP_REVISION_STALE,
            Self::CapabilityDenied => arkret_wire::ErrorCode::CAPABILITY_DENIED,
            Self::CasConflict => "cas_conflict",
            Self::DependencyMissing => "dependency_missing",
            Self::DeviceGenerationFenced => arkret_wire::ErrorCode::DEVICE_GENERATION_FENCED,
            Self::DeviceRevocationPending => "device_revocation_pending",
            Self::DeviceRevoked => "device_revoked",
            Self::DeviceUnauthorized => arkret_wire::ErrorCode::DEVICE_UNAUTHORIZED,
            Self::DuplicateConflict => "duplicate_conflict",
            Self::EpochMismatch => arkret_wire::ErrorCode::EPOCH_MISMATCH,
            Self::EpochUpdateRequired => arkret_wire::ReasonCode::EPOCH_UPDATE_REQUIRED,
            Self::CallStateTransitionInvalid => {
                arkret_wire::ReasonCode::CALL_STATE_TRANSITION_INVALID
            }
            Self::EventHashCollision => "event_hash_collision",
            Self::EventIdDigestMismatch => "event_id_digest_mismatch",
            Self::EventNotAccepted => "event_not_accepted",
            Self::DidMethodSuccessorInvalid => "did_method_successor_invalid",
            Self::FailedPrecondition => "failed_precondition",
            Self::StrandNotActive => arkret_wire::ReasonCode::STRAND_NOT_ACTIVE,
            Self::StrandNotArchived => arkret_wire::ReasonCode::STRAND_NOT_ARCHIVED,
            Self::StrandAlreadyTerminal => arkret_wire::ReasonCode::STRAND_ALREADY_TERMINAL,
            Self::SpaceNotActive => arkret_wire::ReasonCode::SPACE_NOT_ACTIVE,
            Self::SpaceNotArchived => arkret_wire::ReasonCode::SPACE_NOT_ARCHIVED,
            Self::SpaceAlreadyTerminal => arkret_wire::ReasonCode::SPACE_ALREADY_TERMINAL,
            Self::SpaceHasLiveDependents => arkret_wire::ReasonCode::SPACE_HAS_LIVE_DEPENDENTS,
            Self::SpaceParentMismatch => arkret_wire::ReasonCode::SPACE_PARENT_MISMATCH,
            Self::SpaceParentUnreadable => arkret_wire::ReasonCode::SPACE_PARENT_UNREADABLE,
            Self::SpaceRealmMismatch => arkret_wire::ReasonCode::SPACE_REALM_MISMATCH,
            Self::CrossRealmStructuralRelation => {
                arkret_wire::ReasonCode::CROSS_REALM_STRUCTURAL_RELATION
            }
            Self::GateCheckFailed => arkret_wire::ReasonCode::GATE_CHECK_FAILED,
            Self::InvalidMembershipTransition => {
                arkret_wire::ReasonCode::INVALID_MEMBERSHIP_TRANSITION
            }
            Self::SnapshotCapacityExceeded => "snapshot_capacity_exceeded",
            Self::MlsActivationRequired => arkret_wire::ReasonCode::MLS_ACTIVATION_REQUIRED,
            Self::MlsActivationIrreversible => arkret_wire::ReasonCode::MLS_ACTIVATION_IRREVERSIBLE,
            Self::GovernanceBindingMismatch => arkret_wire::ReasonCode::GOVERNANCE_BINDING_MISMATCH,
            Self::JoinRulePolicyMismatch => arkret_wire::ReasonCode::JOIN_RULE_POLICY_MISMATCH,
            Self::PolicyRevisionRollback => arkret_wire::ErrorCode::POLICY_REVISION_ROLLBACK,
            Self::PolicyRevisionGap => arkret_wire::ReasonCode::POLICY_REVISION_GAP,
            Self::PinTargetNotPinned => arkret_wire::ReasonCode::PIN_TARGET_NOT_PINNED,
            Self::MembershipCompensationConflict => "membership_compensation_conflict",
            Self::MimiRoomBindingMigrationProofInvalid => {
                arkret_wire::ReasonCode::MIMI_ROOM_BINDING_MIGRATION_PROOF_INVALID
            }
            Self::RecipientQueueAtCapacity => "quota_exceeded",
            Self::RateLimited => arkret_wire::ErrorCode::RATE_LIMITED,
            Self::RealmFrozen => arkret_wire::ErrorCode::REALM_FROZEN,
            Self::ForkQuarantine => "fork_quarantine",
            Self::RealmAlreadyExists => "realm_already_exists",
            Self::RecoveryPolicyConflict => "recovery_policy_conflict",
            Self::RecoveryPolicyVersionNotMonotonic => "recovery_policy_version_not_monotonic",
            Self::RecoveryPolicySupersedesInvalid => "recovery_policy_supersedes_invalid",
            Self::RecoveryPolicyGenesisNotV1 => "recovery_policy_genesis_not_v1",
            Self::RecoverySessionAlreadyExists => "recovery_session_already_exists",
            Self::ReducerProjectionFailed => "reducer_projection_failed",
            Self::OrganizationRegistrationChallengeInvalid => {
                "organization_registration_challenge_invalid"
            }
            Self::OrganizationRegistrationRevoked => "organization_registration_revoked",
            Self::OrganizationRegistrationStale => "organization_registration_stale",
            Self::SchemaViolation => "schema_violation",
            Self::SignatureInvalid => "signature_invalid",
            Self::SeriesSeqNotMonotonic => "series_seq_not_monotonic",
            Self::TtlExpired => "ttl_expired",
            Self::TemporarilyUnavailable => arkret_wire::ErrorCode::TEMPORARILY_UNAVAILABLE,
            Self::UnsupportedFeature => "unsupported_feature",
            Self::InviteLiveTargetOccupied => arkret_wire::ReasonCode::INVITE_LIVE_TARGET_OCCUPIED,
            Self::InviteDirectedInviteeMismatch => {
                arkret_wire::ReasonCode::INVITE_DIRECTED_INVITEE_MISMATCH
            }
            Self::InviteKindRequiresRevoke => arkret_wire::ReasonCode::INVITE_KIND_REQUIRES_REVOKE,
            Self::InviteAlreadyTerminal => arkret_wire::ReasonCode::INVITE_ALREADY_TERMINAL,
            Self::GrantExceedsIssuerAuthority => {
                arkret_wire::ReasonCode::GRANT_EXCEEDS_ISSUER_AUTHORITY
            }
            Self::AuthorityCycle => arkret_wire::ReasonCode::AUTHORITY_CYCLE,
            Self::AuthorityExpiryWidening => arkret_wire::ReasonCode::AUTHORITY_EXPIRY_WIDENING,
            Self::GrantRelinquishNotSubject => {
                arkret_wire::ReasonCode::GRANT_RELINQUISH_NOT_SUBJECT
            }
            Self::DirectConversationFoundingUnitInvalid => {
                arkret_wire::ReasonCode::DIRECT_CONVERSATION_FOUNDING_UNIT_INVALID
            }
            Self::DirectConversationSlotAlreadyCommitted => {
                arkret_wire::ReasonCode::DIRECT_CONVERSATION_SLOT_ALREADY_COMMITTED
            }
            Self::DirectConversationBindingInvalid => {
                arkret_wire::ReasonCode::DIRECT_CONVERSATION_BINDING_INVALID
            }
            Self::DirectConversationTerminalForbidden => {
                arkret_wire::ReasonCode::DIRECT_CONVERSATION_TERMINAL_FORBIDDEN
            }
            Self::DirectConversationMemberCountInvalid => {
                arkret_wire::ReasonCode::DIRECT_CONVERSATION_MEMBER_COUNT_INVALID
            }
            Self::DirectConversationThirdPartyMemberForbidden => {
                arkret_wire::ReasonCode::DIRECT_CONVERSATION_THIRD_PARTY_MEMBER_FORBIDDEN
            }
            Self::DirectConversationInviteForbidden => {
                arkret_wire::ReasonCode::DIRECT_CONVERSATION_INVITE_FORBIDDEN
            }
            Self::DirectConversationRootMaskViolation => {
                arkret_wire::ReasonCode::DIRECT_CONVERSATION_ROOT_MASK_VIOLATION
            }
            Self::DirectConversationParticipantAuthorityDenied => {
                arkret_wire::ReasonCode::DIRECT_CONVERSATION_PARTICIPANT_AUTHORITY_DENIED
            }
            Self::DirectConversationSpaceForbidden => {
                arkret_wire::ReasonCode::DIRECT_CONVERSATION_SPACE_FORBIDDEN
            }
            Self::AgentProvisioningAlreadyDeclared => {
                arkret_wire::ReasonCode::AGENT_PROVISIONING_ALREADY_DECLARED
            }
            Self::AgentPcrGenesisDeclarationConflict => {
                arkret_wire::ReasonCode::AGENT_PCR_GENESIS_DECLARATION_CONFLICT
            }
            Self::AgentPcrGenesisDeclarationMissing => {
                arkret_wire::ReasonCode::AGENT_PCR_GENESIS_DECLARATION_MISSING
            }
        }
    }

    /// The Direct Conversation admission-table reason this code carries, if
    /// any. These refusals are the closed `{status="rejected",reason_code}`
    /// Event submit outcome, never a problem response
    /// (contact-and-direct-conversation.md section 8.4).
    #[must_use]
    pub const fn direct_conversation_admission_reason(self) -> Option<&'static str> {
        match self {
            Self::DirectConversationBindingInvalid
            | Self::DirectConversationTerminalForbidden
            | Self::DirectConversationMemberCountInvalid
            | Self::DirectConversationThirdPartyMemberForbidden
            | Self::DirectConversationInviteForbidden
            | Self::DirectConversationRootMaskViolation
            | Self::DirectConversationParticipantAuthorityDenied => Some(self.as_str()),
            _ => None,
        }
    }

    /// Read the code prefix out of a conflict detail.
    ///
    /// The prefix is the whole detail, or everything before the first `": "`.
    /// Matching is exact on that token, so a diagnostic that merely mentions a
    /// code elsewhere in its text never routes.
    #[must_use]
    pub fn from_detail(detail: &str) -> Option<Self> {
        let token = detail.split_once(": ").map_or(detail, |(head, _)| head);
        Self::ALL.into_iter().find(|code| code.as_str() == token)
    }
}

impl std::fmt::Display for ConflictCode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Account, identity, messaging, and device persistence registry.
pub trait IdentityStoreRegistry: Send + Sync {
    fn accounts(&self) -> &dyn AccountStore;
    fn account_localparts(&self) -> &dyn AccountLocalpartStore;
    fn account_lifecycle(&self) -> &dyn AccountLifecycleStore;
    fn sessions(&self) -> &dyn SessionStore;
    fn account_data(&self) -> &dyn AccountDataStore;
    fn contacts(&self) -> &dyn ContactStore;
    fn contact_verified_mirrors(&self) -> &dyn ContactVerifiedMirrorStore;
    fn invite_receive_policies(&self) -> &dyn InviteReceivePolicyStore;
    fn invite_locators(&self) -> &dyn InviteLocatorStore;
    fn invite_new_source_ledger(&self) -> &dyn InviteNewSourceLedgerStore;
    fn consent_request_quarantine(&self) -> &dyn ConsentRequestQuarantineStore;
    fn consent_current(&self) -> &dyn ConsentCurrentStore;
    fn mimi_consent_correlations(&self) -> &dyn MimiConsentCorrelationStore;
    fn realm_meta(&self) -> &dyn RealmMetaStore;
    fn messages(&self) -> &dyn MessageStore;
    fn member_identity(&self) -> &dyn MemberIdentityStore;
    fn blobs(&self) -> &dyn BlobStore;
    fn devices(&self) -> &dyn DeviceInventoryStore;
    fn device_revocations(&self) -> &dyn DeviceRevocationStore;
}

/// Federation, retention, organization, and audit persistence registry.
pub trait FederationGovernanceStoreRegistry: Send + Sync {
    fn federation_outbox(&self) -> &dyn FederationOutboxStore;
    fn handle_releases(&self) -> &dyn HandleReleaseStore;
    fn retention_policies(&self) -> &dyn RetentionPolicyStore;
    fn retention_tombstones(&self) -> &dyn RetentionTombstoneStore;
    fn organizations(&self) -> &dyn OrganizationStore;
    fn organization_registrations(&self) -> &dyn OrganizationRegistrationStore;
    fn realm_organizations(&self) -> &dyn RealmOrganizationStore;
    fn realm_organization_statements(&self) -> &dyn RealmOrganizationStatementStore;
    fn audit(&self) -> &dyn AuditStore;
}

/// Delivery, policy, recovery, and service identity persistence registry.
pub trait DeliveryPolicyStoreRegistry: Send + Sync {
    fn moderation(&self) -> &dyn ModerationStore;
    fn federation_operations(&self) -> &dyn FederationOperationsStore;
    fn push_devices(&self) -> &dyn PushDeviceStore;
    fn push_registration_handoffs(&self) -> &dyn PushRegistrationHandoffStore;
    fn signal_relay(&self) -> &dyn SignalRelayStore;
    fn policy_documents(&self) -> &dyn PolicyDocumentStore;
    fn recovery_policies(&self) -> &dyn RecoveryPolicyStore;
    fn recovery_sessions(&self) -> &dyn RecoverySessionStore;
    fn actor_profiles(&self) -> &dyn ActorProfileStore;
    fn security_transactions(&self) -> &dyn SecurityTransactionStore;
    fn webvh(&self) -> &dyn WebvhStore;
    fn service_identity(&self) -> &dyn ServiceIdentityStore;
}

/// Canonical event and derived projection persistence registry.
pub trait EventProjectionStoreRegistry: Send + Sync {
    fn events(&self) -> &dyn EventStore;
    fn projection_events(&self) -> &dyn ProjectionEventStore;
    fn applets(&self) -> &dyn AppletStore;
    fn device_messages(&self) -> &dyn DeviceMessageStore;
    fn device_keys(&self) -> &dyn DeviceKeyStore;
    fn one_time_keys(&self) -> &dyn OneTimeKeyStore;
    fn key_backups(&self) -> &dyn KeyBackupStore;
    fn space_container_projections(&self) -> &dyn SpaceContainerProjectionStore;
    fn circle_projections(&self) -> &dyn CircleProjectionStore;
    fn strand_projections(&self) -> &dyn StrandProjectionStore;
    fn object_current_snapshot(&self) -> &dyn ObjectCurrentSnapshotStore;
    fn morph_projections(&self) -> &dyn MorphProjectionStore;
    fn relation_current_states(&self) -> &dyn RelationCurrentStateStore;
    fn capability_grant_current_states(&self) -> &dyn CapabilityGrantCurrentStateStore;
    fn invite_current_states(&self) -> &dyn InviteCurrentStateStore;
    /// Publication evidence (lease + minted ingress receipt) per accepted
    /// Event digest (`authz/offline-publication.md` §2.1).
    fn publication_evidence(&self) -> &dyn PublicationEvidenceStore;
}

/// MLS, agent, and notification persistence registry.
pub trait MlsAgentStoreRegistry: Send + Sync {
    // G3.S1: MLS lifecycle stores.
    fn mls_key_packages(&self) -> &dyn MlsKeyPackageStore;
    fn mls_groups(&self) -> &dyn MlsGroupCurrentStore;
    // AKP-0010 — agent participation policy.
    fn agent_participation(&self) -> &dyn AgentParticipationStore;
    // AKP-0008 — Agent principals.
    fn agents(&self) -> &dyn AgentStore;
    fn agent_membership_cascades(&self) -> &dyn AgentMembershipCascadeStore;
    fn agent_draft_pending_intents(&self) -> &dyn AgentDraftPendingIntentStore;
    /// First-class Agent Sidecar aggregates and context bindings.
    fn sidecars(&self) -> &dyn SidecarStore;
    // AKP-0016 — per-recipient notification projection.
    fn notifications(&self) -> &dyn NotificationStore;
}

/// Synchronization and request idempotency persistence registry.
pub trait SyncStoreRegistry: Send + Sync {
    fn sync_cursors(&self) -> &dyn SyncCursorStore;
    fn idempotency_keys(&self) -> &dyn IdempotencyStore;
    /// `ak.profile.binding.websocket.v1` challenge + replay ledger.
    fn websocket_auth(&self) -> &dyn WebsocketAuthStore;
    fn account_status_replicas(&self) -> &dyn AccountStatusReplicaStore;
}

/// Owner-published identity resolution and remote-route safety persistence.
pub trait ResolutionStoreRegistry: Send + Sync {
    fn principal_resolutions(&self) -> &dyn PrincipalResolutionStore;
    fn service_routes(&self) -> &dyn ServiceRouteStore;
}

/// Complete persistence capability assembled by an infrastructure adapter.
pub trait PersistenceStore:
    EventCommitUnitOfWork
    + IdentityStoreRegistry
    + FederationGovernanceStoreRegistry
    + DeliveryPolicyStoreRegistry
    + EventProjectionStoreRegistry
    + MlsAgentStoreRegistry
    + SyncStoreRegistry
    + ResolutionStoreRegistry
    + Send
    + Sync
{
    fn authority_commits(&self) -> &dyn AuthorityCommitStore;
    fn account_device_signer_evidence(&self) -> &dyn AccountDeviceSignerEvidenceStore;
    /// `ak.private.read_cursor.v1` account-private winners.
    fn read_cursors(&self) -> &dyn ReadCursorStore;
    /// Private effects of `ak.self.actor_private_events.command.submit.v1`.
    fn actor_private_events(&self) -> &dyn ActorPrivateEventStore;
}

#[cfg(test)]
mod conflict_code_tests {
    use super::{ConflictCode, PersistenceError};

    #[test]
    fn bare_code_and_prefixed_detail_both_resolve() {
        assert_eq!(
            ConflictCode::from_detail("cas_conflict"),
            Some(ConflictCode::CasConflict)
        );
        assert_eq!(
            ConflictCode::from_detail("fork_quarantine: actor sequence sibling limit"),
            Some(ConflictCode::ForkQuarantine)
        );
    }

    #[test]
    fn a_code_mentioned_inside_diagnostics_does_not_route() {
        // The old substring matcher classified this as `cas_conflict`.
        assert_eq!(
            ConflictCode::from_detail("localpart `cas_conflict` is already assigned"),
            None
        );
        assert_eq!(
            ConflictCode::from_detail("schema_violation is not the prefix here"),
            None
        );
    }

    #[test]
    fn unregistered_conflicts_are_reported_as_such() {
        assert_eq!(
            ConflictCode::from_detail("organization registration current pointer CAS failed"),
            None
        );
        assert_eq!(
            PersistenceError::Internal("cas_conflict".to_owned()).conflict_code(),
            None
        );
    }

    #[test]
    fn every_code_round_trips_through_its_wire_token() {
        for code in ConflictCode::ALL {
            assert_eq!(ConflictCode::from_detail(code.as_str()), Some(code));
            assert_eq!(
                ConflictCode::from_detail(&format!("{code}: detail")),
                Some(code)
            );
        }
    }
}

mod registered_audit;
pub use registered_audit::*;
