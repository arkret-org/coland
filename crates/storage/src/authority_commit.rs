//! Durable authority-commit persistence boundary.
//!
//! Producer Events are queued without ordering metadata. Only the current
//! governance Station may atomically append a [`RealmCommit`], mark the Event
//! committed, and enqueue any MLS Welcome deliveries. Each Realm, Circle and
//! Sidecar stream advances independently.

use arkret_wire::{
    CommitStreamHead, CommitStreamRef, Event, EventId, MlsWelcomeDelivery, RealmAuthorityHandoff,
    RealmCommit, RealmCommitId, RealmStateSnapshot,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::{PersistenceError, PersistenceResult};

/// A delivered cross-Station KeyPackage claim whose exact pair Welcome may
/// have been consumed since the last source-side observation.
#[derive(Clone, Debug)]
pub struct DirectConversationPendingPeerClaimQuery {
    pub peer_id: String,
    pub original_request_body: String,
    pub claim_request_id: String,
    pub request_digest: String,
}

/// Result of a caller-scoped stream scan at one governing read cut. The
/// caller is an authenticated Account (`self`) or peer Station (`peer`).
#[derive(Clone, Debug, PartialEq)]
pub enum AccountStreamScan {
    /// A page inside the caller's proved readable interval.
    Page(arkret_wire::StreamScanOutcome),
    /// The Realm is not governed here, or the caller is not (and hosts no)
    /// currently joined member: it has no readable interval on this stream.
    NotAuthorized,
    /// The caller may be authorized, but this Station cannot prove its exact
    /// readable interval and disclosure at this cut.
    Unproved(&'static str),
}

/// Peer-only Full disclosure and its original immutable Human sources.
#[derive(Clone, Debug, PartialEq)]
pub enum PeerStreamScan {
    Page(arkret_models_collaboration::authority_commit::PeerStreamScanOutcome),
    NotAuthorized,
    Unproved(&'static str),
}

/// Result of `ak.self.realm.read.streams.v1` for one authenticated Account
/// at one governing read cut.
#[derive(Clone, Debug, PartialEq)]
pub enum AccountRealmStreamList {
    /// Every row the caller may know exists, in JCS(stream_ref) order.
    Listed(Vec<arkret_wire::RealmStreamRow>),
    /// Unknown Realm or a caller that is not a currently joined member: the
    /// universal non-enumerating `not_found`.
    NotVisible,
    /// The caller is a member, but the stream set it may know about or a
    /// row's readable floor cannot be proved at this cut.
    Unproved(&'static str),
}

/// Internal subscription admission cut; no parallel protocol result carrier.
#[derive(Clone, Debug, PartialEq)]
pub struct AccountRealmStreamAuthorizationCut {
    pub listing: AccountRealmStreamList,
    pub history_digest: Option<String>,
}

/// Result of `ak.self.committed_event.resource.get.v1` for one caller on an
/// ordinary Realm's Realm stream, decided from typed current at one read cut.
#[derive(Clone, Debug, PartialEq)]
pub enum MemberCommittedEventRead {
    /// The Commit lies in the caller's readable interval; the Event is
    /// disclosed in full or as the withheld branch.
    Read(Box<arkret_wire::CommittedEventView>),
    /// Unknown, or outside the caller's readable interval: indistinguishable.
    NotVisible,
    /// The held Realm stream is pending its bootstrap anchor
    /// (`federation.md` §4.1.1): no local read is served.
    PendingAnchor,
    /// The Commit is not on the Realm stream of an ordinary Realm, whose
    /// visibility this typed current decides (a principal-control Realm, or a
    /// Circle or Sidecar stream).
    OutsideOrdinaryRealmStream,
}

/// Result of an exact, non-enumerating self current read at one governing
/// read cut (`ak.self.current_results.read.exact.v1`,
/// `ak.self.strand.watch.read.current.v1`).
#[derive(Clone, Debug)]
pub enum SelfExactCurrentRead<T> {
    /// A selector-identical answer bound to the cut's generation and head.
    Answer(T),
    /// Unknown, foreign, invisible or unauthorized selector.
    NotFound,
    /// The current governing basis for the selector cannot be confirmed at
    /// this cut; absence is never inferred from it.
    Unresolved(&'static str),
}

/// Anchor state behind `ak.self.media_service_binding.read.resolve.v1` for one
/// authenticated Account at one governing read cut.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MediaServiceAnchorRead {
    /// Invisible Realm, non-member caller, or no accepted media service
    /// assignment in the Realm.
    NotFound,
    /// A media service assignment was accepted in the visible Realm.
    Anchored {
        value: arkret_models_collaboration::events_payloads::realm::RealmMediaServiceValue,
        revision: arkret_wire::CurrentRevision,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueuedEventStatus {
    Queued,
    Committed,
    Rejected,
}

/// Last local attempt to forward an already queued Event. This is not an
/// authority decision: a rejection at one cut may be superseded by exact
/// replay at a later cut, while the Event row remains queued until replica.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForwardAttemptStatus {
    Forwarding,
    Rejected,
    TemporarilyUnavailable,
}

impl ForwardAttemptStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Forwarding => "forwarding",
            Self::Rejected => "rejected",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ForwardAttemptRecord {
    /// Exact original submission; this is transport intent, never current state.
    pub original_submission:
        Option<arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest>,
    /// Frozen signed source siblings and complete peer unit, only for exact transport retry.
    pub peer_request:
        Option<Box<arkret_models_collaboration::authority_commit::PeerAuthoritySubmitRequest>>,
    /// Verified governing acceptance witness, not an installed replica.
    pub accepted_commit: Option<RealmCommit>,
    pub status: ForwardAttemptStatus,
    pub reason_code: Option<String>,
    pub attempted_at: DateTime<Utc>,
}

/// Per-request verified identity for the native MLS refusal transaction; never wire or current
/// state.
#[derive(Clone, Copy)]
pub enum ManagedMlsRefusalSource<'a> {
    Local(&'a crate::AppletManagedDeviceScopeGuard),
}

#[derive(Clone, Debug, PartialEq)]
pub struct QueuedEventRecord {
    pub event: Event,
    pub status: QueuedEventStatus,
    pub queued_at: DateTime<Utc>,
    pub committed: Option<RealmCommit>,
    pub rejection_reason: Option<String>,
    pub forward_attempt: Option<ForwardAttemptRecord>,
}

/// Exact durable pair used to materialize a caller-scoped committed-event
/// read view. This is an internal persistence carrier, not a third protocol
/// object and has no identity or signature of its own.
#[derive(Clone, Debug, PartialEq)]
pub struct CommittedEventRecord {
    pub commit: RealmCommit,
    pub event: Event,
}

/// Durable MIMI room binding winner at one accepted RealmCommit revision.
#[derive(Clone, Debug)]
pub struct MimiRoomBindingCurrentRecord {
    pub current: arkret_models_collaboration::events_payloads::mimi::MimiRoomBindingCurrentRow,
    pub source_event_id: arkret_wire::EventId,
    pub realm_id: arkret_wire::RealmId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CurrentRealmAuthority {
    pub realm_id: arkret_wire::RealmId,
    pub generation: u64,
    pub service_id: arkret_wire::DidCoreId,
    pub authority_ref: arkret_wire::RealmCommitAuthorityRef,
    pub last_handoff_ref: Option<arkret_wire::RealmAuthorityHandoffId>,
}

/// The accepted lifecycle roster of one Realm held by this Station
/// (`realm-read-operations.schema.json#/$defs/realm_lifecycle_view`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptedRealmRoster {
    pub controller_actor_id: arkret_wire::ActorId,
    pub joined_members: Vec<arkret_wire::ActorId>,
}

/// One durable-cut maximal Realm snapshot projection before identity and
/// Station signature are attached by the serving layer.
#[derive(Clone, Debug, PartialEq)]
pub struct RealmStateSnapshotMaterial {
    pub realm_id: arkret_wire::RealmId,
    pub governance_generation: u64,
    pub visible_stream_heads: Vec<arkret_wire::CommitStreamHead>,
    pub current_state_entries: Vec<arkret_wire::TypedCurrentRow>,
    pub retention_and_history_floor: arkret_wire::RetentionAndHistoryFloor,
}

/// Bounded native evidence for a member Station's Direct resolver. Values
/// remain SDK typed current; this carrier is never serialized or signed.
#[derive(Clone, Debug, PartialEq)]
pub struct DirectConversationReplicaCut {
    pub authority: CurrentRealmAuthority,
    pub head: CommitStreamHead,
    pub current_state_entries: Vec<arkret_wire::TypedCurrentRow>,
}

impl DirectConversationReplicaCut {
    /// Unrelated accepted Events may advance the head while the exact
    /// binding, MLS and membership revisions remain unchanged.
    pub fn retains_resolver_facts(&self, previous: &Self) -> bool {
        self.authority == previous.authority
            && self.current_state_entries == previous.current_state_entries
            && self.head.stream_ref == previous.head.stream_ref
            && (self.head.stream_position > previous.head.stream_position
                || self.head == previous.head)
    }
}

/// Signs the exact material proved at an issuance cut. It runs inside that
/// cut, so it must be synchronous and must not read other state.
pub type RealmStateSnapshotSigner<'a> = &'a (
        dyn Fn(&RealmStateSnapshotMaterial) -> PersistenceResult<RealmStateSnapshot> + Send + Sync
    );

/// Freeze of one Account's Realm-stream delivery window
/// (`client-sync.md` 5.2, decision 0101).
///
/// `window_cursor` is the frozen window identity the frame repeats as
/// `window_snapshot_cursor`; `expires_at_ms` is the window's consumable
/// deadline, which also bounds the Account cursor that carries it.
#[derive(Clone, Debug)]
pub struct AccountRealmWindowRequest {
    pub realm_id: arkret_wire::RealmId,
    pub account: arkret_wire::AccountId,
    pub issuer: arkret_wire::DidCoreId,
    pub window_limit: u32,
    pub window_cursor: String,
    pub expires_at_ms: i64,
    pub now_ms: i64,
    /// Canonical bytes available for all windows, committed rows, typed current
    /// and coverage heads. The caller reserves the remaining frame envelope.
    /// A payload that does not fit fails the entire freeze without truncation.
    pub byte_budget: usize,
    /// The Realm-stream head the Account cursor last delivered. When it is
    /// still an accepted ancestor of the head within `window_limit`, the
    /// window is the live delta after it instead of the last `window_limit`
    /// Commits.
    pub delivered_heads: Vec<arkret_wire::CommitStreamHead>,
    /// `None` uses the bounded default visible set. An explicit selection
    /// carries the caller's exact per-stream filter for this Realm.
    pub selected_stream_refs: Option<Vec<arkret_wire::CommitStreamRef>>,
}

/// One frozen, fully delivered stream window and its committed rows.
///
/// A non-preview `window_start_basis` names an exact snapshot already
/// issued to the Account, and the freeze reserved it for the window's
/// consumable period. Without such a reservation a limited window is
/// `preview_only` and carries no basis.
#[derive(Clone, Debug)]
pub struct AccountRealmWindow {
    pub governance_generation: u64,
    /// The first selected stream's window. Kept separate from siblings so
    /// existing single-stream consumers can inspect its exact basis.
    pub window: arkret_models_collaboration::sync_frames::account_sync::RealmStreamWindow,
    pub additional_windows:
        Vec<arkret_models_collaboration::sync_frames::account_sync::RealmStreamWindow>,
    pub streams_limited: bool,
    pub committed_events: Vec<arkret_wire::CommittedEventView>,
    /// Every stream visible to this Account at the same cut as the window.
    /// The window itself still carries only one stream's committed tail.
    pub current_stream_heads: Vec<arkret_wire::CommitStreamHead>,
    /// Typed current results of the same proved cut, i.e. at the window
    /// cut; the Account current carrier of the window's Realm detail.
    pub current_state_entries: Vec<arkret_wire::TypedCurrentRow>,
}

/// An issued snapshot without any live window reservation stays archived at
/// least this long after issuance, the same span as an Account sync
/// snapshot reservation (0441), before retention may reclaim it.
pub const UNRESERVED_ISSUED_SNAPSHOT_RETENTION_MS: i64 = 3_660_000;

/// Longest consumable period a window reservation may claim: the Account
/// stream cursor that carries the window never lives longer.
pub const MAX_ACCOUNT_WINDOW_RESERVATION_MS: i64 = 3_600_000;

/// Issued snapshots of one Account and Realm that no live window reservation
/// names are kept to the newest this many (0441). Issuing a further one
/// reclaims the oldest; a head whose issuance was reclaimed backs no later
/// window basis, so that window is `preview_only`.
pub const MAX_UNRESERVED_ISSUED_SNAPSHOTS_PER_ACCOUNT_REALM: i64 = 8;

/// Live window reservations one Account may hold on one stream (0441). At
/// the cap a newly frozen limited window names no basis and is
/// `preview_only`; a reservation is never evicted before its deadline.
/// Together with the unreserved cap this bounds the signed objects kept for
/// one Account and Realm to 40 within the reservation lifetime.
pub const MAX_LIVE_WINDOW_RESERVATIONS_PER_ACCOUNT_STREAM: i64 = 32;

/// Decision 0081 / 0068: the complete RFC 8785 canonical signed body is one
/// inline object of at most 8 MiB. There is no page, chunk, or truncation.
pub const MAX_INLINE_REALM_STATE_SNAPSHOT_BYTES: usize = 8 * 1024 * 1024;

/// Reject the whole signed object when its canonical body exceeds the limit.
pub fn enforce_inline_realm_state_snapshot_capacity(
    snapshot: &RealmStateSnapshot,
) -> PersistenceResult<()> {
    let bytes = arkret_canonical::canonical_json_bytes(snapshot)
        .map_err(crate::PersistenceError::database)?;
    if bytes.len() > MAX_INLINE_REALM_STATE_SNAPSHOT_BYTES {
        return Err(crate::PersistenceError::Conflict(
            "snapshot_capacity_exceeded: complete signed Realm snapshot exceeds 8 MiB".to_owned(),
        ));
    }
    Ok(())
}

/// The signer may attach only identity, time, and signature; every disclosed
/// member must be exactly the proved material.
pub fn signed_snapshot_matches_material(
    snapshot: &RealmStateSnapshot,
    material: &RealmStateSnapshotMaterial,
) -> bool {
    snapshot.realm_id == material.realm_id
        && snapshot.governance_generation == material.governance_generation
        && snapshot.visible_stream_heads == material.visible_stream_heads
        && snapshot.current_state_entries == material.current_state_entries
        && snapshot.retention_and_history_floor == material.retention_and_history_floor
}

/// One transaction installed after all Event, authority and MLS checks pass.
#[derive(Clone, Debug, PartialEq)]
pub struct AuthorityCommitTransaction {
    pub expected_authority: CurrentRealmAuthority,
    pub event: Event,
    pub commit: RealmCommit,
    pub producer_signer_fact:
        Option<arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact>,
    pub mls_state: Option<MlsStateInstallation>,
    pub welcomes: Vec<VerifiedMlsWelcome>,
    /// Service-configured maximum outstanding deliveries for each exact
    /// recipient endpoint. A transaction carrying Welcome must provide a
    /// positive bound; zero is permitted only when no Welcome is present.
    pub recipient_queue_capacity: usize,
}

/// Actual current subject-control method authenticated at the HTTP boundary.
/// Event signatures and command permissions remain independently verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppletControlCarrier {
    pub actor_id: arkret_wire::ActorId,
    pub control_ref: arkret_wire::CommittedEventRef,
    pub verification_method: arkret_wire::DidUrl,
    pub public_key: [u8; 32],
    pub governance_service_id: arkret_wire::DidCoreId,
    pub governance_generation: u64,
}

/// Authenticated transport material; the private reader repeats current checks.
#[derive(Clone)]
pub enum RealmActorMaterialCaller {
    /// An original creation task retained by the accepting transaction. The
    /// reader must prove that task and the current exact manager before supply.
    CreationCompletion {
        applet_id: arkret_wire::AppletId,
        request_digest: arkret_wire::Hash,
        creation_ref: arkret_wire::CommittedEventRef,
        service_id: arkret_wire::DidCoreId,
    },
    Account {
        account_id: arkret_wire::AccountId,
        expires_at: DateTime<Utc>,
    },
    Control {
        authority: AppletControlCarrier,
        expires_at: DateTime<Utc>,
    },
    Service {
        service_id: arkret_wire::DidCoreId,
        verification_method: arkret_wire::DidUrl,
        public_key: [u8; 32],
        expires_at: DateTime<Utc>,
    },
    Device {
        guard: Box<crate::AppletManagedDeviceScopeGuard>,
        expires_at: DateTime<Utc>,
    },
}

pub type RealmActorMaterialSigner<'a> = &'a (
        dyn Fn(
    &arkret_models_integration::RealmActorMaterialUnsigned,
) -> PersistenceResult<arkret_models_integration::RealmActorMaterialOutcome>
            + Send
            + Sync
    );

/// Current producer authorization pinned by the self submit preflight and
/// rechecked inside the same transaction that commits the Event. This is an
/// internal persistence guard, never a caller-supplied protocol claim.
#[derive(Clone, Debug, PartialEq)]
pub enum SelfProducerCommitGuard {
    /// The locally configured MIMI facade authored this Event. The exact
    /// binding and independently verified reporter/sender are rechecked at cut.
    MimiFacade {
        service_id: arkret_wire::DidCoreId,
        verification_method: arkret_wire::DidUrl,
        room_uri: arkret_wire::MimiRoomUri,
        binding_event_id: arkret_wire::EventId,
        attributed_actor: arkret_wire::ActorId,
        source_provider_id: arkret_wire::DidCoreId,
        reporter_authority: Option<serde_json::Value>,
        submit_request: Option<serde_json::Value>,
        mapping_receipt: Option<serde_json::Value>,
        reporter_device_guard: Option<Box<crate::DeviceRevocationGateSelector>>,
    },
    /// Native managed Device identity and exact signed business scope. Current
    /// permission and source provenance are rechecked in the accepting unit.
    AppletManagedDevice(Box<AppletManagedDeviceScopeGuard>),
    HumanDevice(crate::DeviceRevocationGateSelector),
    /// Original native regular root frozen with the accepting Event Commit.
    HumanDeviceEvidence {
        selector: crate::DeviceRevocationGateSelector,
        evidence: Box<arkret_models_identity::AccountDeviceSignerEvidence>,
    },
    Agent {
        pcr_realm_id: arkret_wire::RealmId,
        agent_id: arkret_wire::DidCoreId,
        authorization_ref: arkret_wire::CommittedEventRef,
        verification_method: arkret_wire::DidUrl,
    },
}

/// Process-local evidence prepared from authenticated transport and a fresh
/// Service resolver. This is never a wire credential or an allow verdict.
#[derive(Clone, Debug, PartialEq)]
pub struct AppletManagedDeviceScopeGuard {
    pub authority: crate::AppletManagedDeviceAuthority,
    pub effective_scope: arkret_wire::ScopeRef,
    pub service_did_document: arkret_identity::DidDocument,
}

impl SelfProducerCommitGuard {
    pub fn human_device_selector(&self) -> Option<&crate::DeviceRevocationGateSelector> {
        match self {
            Self::HumanDevice(selector) | Self::HumanDeviceEvidence { selector, .. } => {
                Some(selector)
            }
            _ => None,
        }
    }
}

/// A complete ordinary Realm bootstrap, including the exact HTTP request
/// bytes used for durable idempotency comparison. Every proposed Commit is
/// prepared and verified by the service before this storage boundary.
#[derive(Clone, Debug)]
pub struct OrdinaryRealmBootstrapCommitUnit {
    pub submission:
        arkret_models_collaboration::authority_commit::OrdinaryRealmBootstrapUnitSubmission,
    pub exact_request_body: Vec<u8>,
    pub transactions: Vec<AuthorityCommitTransaction>,
    /// Signing-time authority prepared by ingress, in the submitted slot order.
    /// Empty only when no slot carries detached approval evidence.
    pub event_approvals: Vec<Option<crate::EventApprovalCommit>>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum OrdinaryRealmBootstrapCommitOutcome {
    Committed(Vec<RealmCommit>),
    Duplicate(Vec<RealmCommit>),
}

/// The caller-authored four-Event Direct Conversation founding unit with the
/// four consecutive Commits the founder's current Station prepared for it
/// (contact-and-direct-conversation.md sections 5.5 and 6.1). Every
/// coordinate is recomputed from the Event bytes by [`Self::facts`]; nothing
/// the request asserts beside the Events is trusted.
#[derive(Clone, Debug, PartialEq)]
pub struct DirectConversationFoundingCommitUnit {
    pub submission:
        arkret_models_collaboration::authority_commit::DirectConversationFoundingUnitSubmission,
    pub transactions: [AuthorityCommitTransaction; 4],
}

/// Coordinates derived from the exact unit bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectConversationFoundingFacts {
    pub founder_id: arkret_wire::ActorId,
    pub peer_id: arkret_wire::ActorId,
    pub trust_domain_id: arkret_wire::TrustDomainId,
    /// The genesis `governance_station_id`, which must be the founder's
    /// current Station admitting the unit.
    pub governance_station_id: arkret_wire::DidCoreId,
    pub pair_key: arkret_wire::Hash,
    pub realm_id: arkret_wire::RealmId,
    pub main_strand_id: arkret_wire::StrandId,
    pub founding_unit_digest: arkret_wire::Hash,
    /// The branch-selecting critical ref of the genesis Event.
    pub authority_ref: DirectConversationFoundingAuthorityRef,
}

/// The exact-XOR critical ref role that selects the genesis admission variant
/// (contact-and-direct-conversation.md section 5.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DirectConversationFoundingAuthorityRef {
    /// `direct_conversation_contact_round`: the pair's current Contact round.
    ContactRound(arkret_wire::Hash),
    /// `direct_conversation_agent_provision`: the accepted provision Event.
    AgentProvision(arkret_wire::EventId),
}

/// The Direct Conversation admission table's verdict at one cut.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectConversationAdmissionCut {
    /// The Event's Realm is not a Direct Conversation.
    NotDirectConversation,
    /// No stage of the table refuses the Event.
    Passed,
    /// The first matching stage in registered precedence.
    Refused(crate::ConflictCode),
}

#[derive(Clone, Debug, PartialEq)]
pub enum DirectConversationFoundingCommitOutcome {
    Committed([RealmCommit; 4]),
    Duplicate([RealmCommit; 4]),
}

fn founding_unit_invalid(detail: impl std::fmt::Display) -> arkret_wire::WireError {
    arkret_wire::WireError::Protocol(detail.to_string())
}

impl DirectConversationFoundingCommitUnit {
    /// Recompute every founding coordinate from the four Events and refuse any
    /// unit that is not the closed caller-authored shape of section 6.1 and
    /// the fixed section 6.2 baseline. An error here is always
    /// `direct_conversation_founding_unit_invalid`.
    pub fn facts(&self) -> arkret_wire::Result<DirectConversationFoundingFacts> {
        use arkret_models_collaboration::governance::membership_invite::MembershipPayload;
        use arkret_models_collaboration::objects::direct_conversation::{
            DirectConversationPairKeyParticipant, direct_conversation_pair_key,
        };

        self.submission.validate().map_err(founding_unit_invalid)?;
        let events = self.submission.events.each_ref().map(|item| &item.event);
        let plan =
            arkret_models_collaboration::direct_conversation::DirectConversationFoundingPlan::from_events(
                events,
            )
            .map_err(founding_unit_invalid)?;
        let realm_scope = arkret_wire::ScopeRef::Realm {
            realm_id: plan.realm_id.clone(),
        };
        if events[0].scope_ref != arkret_wire::ScopeRef::RealmGenesis
            || events[1..]
                .iter()
                .any(|event| event.scope_ref != realm_scope)
        {
            return Err(founding_unit_invalid(
                "the genesis opens the Realm and the other three Events target its stream",
            ));
        }
        if self.submission.events.iter().any(|item| {
            item.approval_signatures.is_some()
                || item.event.executed_by.is_some()
                || item.event.authorization_ref.is_some()
                || item.event.applet_id.is_some()
        }) {
            return Err(founding_unit_invalid(
                "the founder authors every founding Event directly",
            ));
        }
        let unit_event_ids = events
            .iter()
            .map(|event| event.event_id.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        if events[1..].iter().any(|event| {
            event.semantic_refs.iter().any(|reference| {
                unit_event_ids.contains(reference.id.as_str())
                    || matches!(
                        reference.role.as_str(),
                        "direct_conversation_contact_round" | "direct_conversation_agent_provision"
                    )
            })
        }) {
            return Err(founding_unit_invalid(
                "only the genesis carries the founding authority ref and no Event names another",
            ));
        }
        let genesis = arkret_event_draft::EventPayloadExt::as_realm_create(events[0])
            .map_err(founding_unit_invalid)?
            .object;
        if genesis.initial_join_rule != arkret_wire::JoinRule::Closed
            || genesis.initial_history_access != arkret_wire::HistoryAccess::SinceJoin
            || genesis.initial_discoverability != arkret_wire::Discoverability::InviteOnly
        {
            return Err(founding_unit_invalid(
                "the genesis must pin the closed, invite_only, since_join baseline",
            ));
        }
        let membership = |event: &Event| {
            serde_json::to_value(&event.payload)
                .and_then(serde_json::from_value::<MembershipPayload>)
                .map_err(founding_unit_invalid)
        };
        let founder = membership(events[1])?;
        let peer = membership(events[2])?;
        if [&founder, &peer].into_iter().any(|join| {
            join.strand_id.is_some()
                || !join.gate_proofs.is_empty()
                || join.invite_ref.is_some()
                || join.membership_cause.is_some()
        }) || founder.agent_controller_binding.is_some()
        {
            return Err(founding_unit_invalid(
                "the founding joins are neither invites nor gated entries",
            ));
        }
        let strand = arkret_event_draft::EventPayloadExt::as_strand_create(events[3])
            .map_err(founding_unit_invalid)?
            .object;
        let discussion = strand
            .tracks
            .get(arkret_models_collaboration::objects::profiles::STRAND_TRACK_NAME_DISCUSSION);
        if strand.scope_circle_id.is_some()
            || discussion
                .is_none_or(|track| track.is_primary != Some(true) || track.enabled == Some(false))
        {
            return Err(founding_unit_invalid(
                "the main Strand is Realm-default with a primary discussion track",
            ));
        }
        let trust_domain_id = genesis.trust_domain.clone();
        let pair_key = direct_conversation_pair_key(
            trust_domain_id.clone(),
            DirectConversationPairKeyParticipant::unmapped(founder.member_id.clone()),
            DirectConversationPairKeyParticipant::unmapped(peer.member_id.clone()),
        )
        .map_err(founding_unit_invalid)?;
        let mut roles = events[0].semantic_refs.iter().filter(|reference| {
            matches!(
                reference.role.as_str(),
                "direct_conversation_contact_round" | "direct_conversation_agent_provision"
            )
        });
        let authority_ref = match (roles.next(), roles.next()) {
            (Some(reference), None) if reference.critical => match reference.role.as_str() {
                "direct_conversation_contact_round" => {
                    DirectConversationFoundingAuthorityRef::ContactRound(
                        arkret_wire::Hash::new(reference.id.clone())
                            .map_err(founding_unit_invalid)?,
                    )
                }
                _ => DirectConversationFoundingAuthorityRef::AgentProvision(
                    arkret_wire::EventId::new(reference.id.clone())
                        .map_err(founding_unit_invalid)?,
                ),
            },
            _ => {
                return Err(founding_unit_invalid(
                    "the genesis must carry exactly one critical founding authority ref",
                ));
            }
        };
        if matches!(
            authority_ref,
            DirectConversationFoundingAuthorityRef::ContactRound(_)
        ) && peer.agent_controller_binding.is_some()
        {
            return Err(founding_unit_invalid(
                "a Contact-round founding carries no Agent controller binding",
            ));
        }
        Ok(DirectConversationFoundingFacts {
            founder_id: founder.member_id,
            peer_id: peer.member_id,
            trust_domain_id,
            governance_station_id: genesis.governance_station_id,
            pair_key,
            realm_id: plan.realm_id,
            main_strand_id: plan.main_strand_id,
            founding_unit_digest: plan.founding_unit_digest,
            authority_ref,
        })
    }

    pub fn validate(&self) -> arkret_wire::Result<()> {
        let facts = self.facts()?;
        let first = &self.transactions[0];
        let authority = &first.expected_authority;
        if authority.realm_id != facts.realm_id
            || authority.generation != 0
            || authority.last_handoff_ref.is_some()
            || authority.authority_ref
                != arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                    first.event.event_id.clone(),
                )
        {
            return Err(founding_unit_invalid(
                "the founding unit must install its exact genesis authority",
            ));
        }
        for (submitted, transaction) in self.submission.events.iter().zip(&self.transactions) {
            transaction.validate()?;
            if submitted.event != transaction.event
                || transaction.expected_authority != *authority
                || transaction.mls_state.is_some()
                || !transaction.welcomes.is_empty()
            {
                return Err(founding_unit_invalid(
                    "a founding transaction diverges from its submitted Event or authority",
                ));
            }
        }
        arkret_models_collaboration::authority_commit::DirectConversationFoundingAcceptanceOutcome {
            unit_kind: self.submission.unit_kind,
            status:
                arkret_models_collaboration::authority_commit::AggregateAcceptanceStatus::Committed,
            commits: self.commits(),
        }
        .validate()?;
        if self.transactions[0].commit.stream_position != 0
            || self.transactions[0].commit.previous_commit_ref.is_some()
            || self
                .transactions
                .iter()
                .any(|transaction| transaction.commit.committed_at != first.commit.committed_at)
        {
            return Err(founding_unit_invalid(
                "the four founding Commits must open the Realm stream at one instant",
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn commits(&self) -> [RealmCommit; 4] {
        self.transactions
            .each_ref()
            .map(|transaction| transaction.commit.clone())
    }
}

/// Complete PCR genesis admission prepared by the governance Station after
/// authenticating the Account Authority relay and both producer proofs.
#[derive(Clone, Debug, PartialEq)]
pub struct PcrGenesisCommitUnit {
    pub submission: arkret_models_collaboration::principal_operations::PcrGenesisAdmissionInput,
    pub exact_request_body: Vec<u8>,
    pub transactions: [AuthorityCommitTransaction; 2],
}

#[derive(Clone, Debug, PartialEq)]
pub enum PcrGenesisCommitOutcome {
    Committed(arkret_models_collaboration::principal_operations::PcrGenesisAdmissionOutcome),
    Duplicate(arkret_models_collaboration::principal_operations::PcrGenesisAdmissionOutcome),
}

impl PcrGenesisCommitUnit {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        self.submission.validate()?;
        if self.exact_request_body.is_empty()
            || serde_json::from_slice::<
                arkret_models_collaboration::principal_operations::PcrGenesisAdmissionInput,
            >(&self.exact_request_body)
            .ok()
            .as_ref()
                != Some(&self.submission)
        {
            return Err(arkret_wire::WireError::Protocol(
                "PCR genesis exact request bytes differ from the admitted input".to_owned(),
            ));
        }
        let first = &self.transactions[0];
        let second = &self.transactions[1];
        let authority = &first.expected_authority;
        let expected_stream = CommitStreamRef::Realm {
            realm_id: self.submission.pcr_realm_id.clone(),
        };
        if authority.realm_id != self.submission.pcr_realm_id
            || authority.service_id != self.submission.account_authority_id
            || authority.generation != 0
            || authority.last_handoff_ref.is_some()
            || authority.authority_ref
                != arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                    self.submission.genesis_unit.create().event_id.clone(),
                )
            || second.expected_authority != *authority
            || first.event != *self.submission.genesis_unit.create()
            || second.event != *self.submission.genesis_unit.founding_authorize()
            || first.commit.stream_ref != expected_stream
            || second.commit.stream_ref != expected_stream
            || first.commit.stream_position != 0
            || first.commit.previous_commit_ref.is_some()
            || second.commit.stream_position != 1
            || second.commit.previous_commit_ref.as_ref() != Some(&first.commit.commit_id)
            || self.transactions.iter().any(|transaction| {
                transaction.mls_state.is_some() || !transaction.welcomes.is_empty()
            })
        {
            return Err(arkret_wire::WireError::Protocol(
                "PCR genesis transaction does not bind its ordered Event and Commit pair"
                    .to_owned(),
            ));
        }
        first.validate()?;
        second.validate()?;
        Ok(())
    }
}

impl OrdinaryRealmBootstrapCommitUnit {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        self.submission.validate()?;
        if self.exact_request_body.is_empty()
            || self.transactions.len() != self.submission.events.len()
        {
            return Err(arkret_wire::WireError::Protocol(
                "ordinary Realm bootstrap body/transaction cardinality is invalid".to_owned(),
            ));
        }
        match serde_json::from_slice::<
            arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest,
        >(&self.exact_request_body)
        {
            Ok(arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest::OrdinaryRealmBootstrap(parsed))
                if parsed == self.submission => {}
            _ => return Err(arkret_wire::WireError::Protocol(
                "ordinary Realm bootstrap exact body does not match the submitted unit".to_owned(),
            )),
        }
        let first = &self.transactions[0];
        if !self.event_approvals.is_empty() && self.event_approvals.len() != self.transactions.len()
        {
            return Err(arkret_wire::WireError::Protocol(
                "ordinary Realm bootstrap approval history is incomplete".to_owned(),
            ));
        }
        for (index, (submitted, transaction)) in self
            .submission
            .events
            .iter()
            .zip(&self.transactions)
            .enumerate()
        {
            if let Some(prepared) = self.event_approvals.get(index) {
                let signatures = prepared.as_ref().map(|evidence| {
                    evidence
                        .methods
                        .iter()
                        .map(|method| method.signature.clone())
                        .collect::<Vec<_>>()
                });
                if signatures != submitted.approval_signatures {
                    return Err(arkret_wire::WireError::Protocol(
                        "ordinary Realm bootstrap approval history differs from its submitted evidence".to_owned(),
                    ));
                }
            }
            transaction.validate()?;
            if submitted.event != transaction.event
                || transaction.expected_authority != first.expected_authority
                || transaction.mls_state.is_some()
                || !transaction.welcomes.is_empty()
            {
                return Err(arkret_wire::WireError::Protocol(
                    "ordinary Realm bootstrap transaction diverges from its submitted Event or authority"
                        .to_owned(),
                ));
            }
        }
        arkret_models_collaboration::authority_commit::OrdinaryRealmBootstrapAcceptanceOutcome {
            unit_kind: self.submission.unit_kind,
            status:
                arkret_models_collaboration::authority_commit::AggregateAcceptanceStatus::Committed,
            commits: self
                .transactions
                .iter()
                .map(|transaction| transaction.commit.clone())
                .collect(),
        }
        .validate()?;
        Ok(())
    }
}

/// The public MLS transition an accepted `ak.mls.genesis` or `ak.mls.commit`
/// installs (encryption-and-audit.md §2.2, §5.1).
///
/// The serving layer verified the RFC 9420 public transition from the exact
/// Event bytes against `base`; the accepting transaction installs it only
/// while `base` is still the scope's current group, so a concurrent winner
/// turns this attempt into a zero-write refusal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsStateInstallation {
    pub effective_scope: arkret_wire::ScopeRef,
    /// `None` for Genesis; otherwise the exact current group the Commit was
    /// verified against.
    pub base: Option<MlsInstalledBase>,
    /// The epoch the transition reaches.
    pub epoch: u64,
    /// Station-private public RFC 9420 tracker state at `epoch`. It holds no
    /// member secret and is never a wire value.
    pub public_state: Vec<u8>,
    /// The distinct principals of every leaf of the public state at `epoch`,
    /// read from the verified tracker. A Direct Conversation Realm decides its
    /// exact-pair group state from them (contact-and-direct-conversation.md
    /// §7.2, §8.3).
    pub member_principals: std::collections::BTreeSet<arkret_wire::ActorId>,
    /// Every inline Proposal actually consumed by a verified Commit, in its
    /// signed PublicMessage wire order. Empty for Genesis or self-update.
    /// The accepting PG transaction freezes these with the winning Commit.
    pub consumed_proposals: Vec<MlsConsumedProposalInstallation>,
    /// The public Blobs published atomically with this transition: two
    /// carried Genesis artifacts, or one post-Commit ratchet tree. A local
    /// Genesis may use its already published Blobs.
    pub public_blobs: Vec<MlsPublicBlob>,
}

/// Station-private historical leaf coordinates derived only from verified RFC
/// public state. Leaf indices never enter the roster read wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsProposalLeafProvenance {
    pub leaf_index: u32,
    pub actor_id: arkret_wire::ActorId,
    pub signature_key: arkret_wire::Base64UrlString,
}

/// Exact accepted Commit Proposal provenance carried from the SDK public
/// tracker into one PG acceptance transaction. It is not a protocol DTO.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsConsumedProposalInstallation {
    pub ordinal: u64,
    pub proposal_ref: Vec<u8>,
    pub proposal_type: u16,
    pub proposal_wire: Vec<u8>,
    pub sender_leaf: MlsProposalLeafProvenance,
    pub target_before: Option<MlsProposalLeafProvenance>,
    pub target_after: Option<MlsProposalLeafProvenance>,
}

/// One content-addressed public Genesis artifact or post-Commit tree. Its bytes
/// are already in the object store under `storage_key`; the accepting
/// transaction writes the Blob row that serves them to
/// `ak.peer.mls.read.group_state_material.v1`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsPublicBlob {
    /// The content-addressed reference of the verified public bytes.
    pub blob_ref: arkret_wire::BlobRef,
    /// Lower-case hex SHA-256 of the bytes, the object store's key input.
    pub sha256: String,
    pub size_bytes: i64,
    pub storage_backend: String,
    pub storage_key: String,
}

/// The current group coordinates a Commit transition was verified against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsInstalledBase {
    pub current_mls_commit_event_ref: arkret_wire::EventId,
    pub epoch: u64,
}

/// One producer-signed Welcome the serving layer verified.
///
/// A recipient this Station hosts carries the exact KeyPackage claim ledger
/// entry its Welcome was verified against (device-lifecycle.md, claim ledger
/// rules) and is queued here. A recipient another Station hosts carries no
/// local claim: its Welcome rides the Commit's committed-replication intent
/// to that Station, which re-verifies the claim (encryption-and-audit.md
/// §2.2).
#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedMlsWelcome {
    pub delivery: MlsWelcomeDelivery,
    pub claim: Option<MlsWelcomeClaimLedgerKey>,
    /// Required for a locally hosted native package; storage checks the original
    /// package and current PCR/scope facts inside the accepting transaction.
    pub applet_device_scope_guard: Option<crate::AppletManagedDeviceScopeGuard>,
    /// Absent until the immutable Genesis selector is verified from the
    /// accepted committed-replication carrier.
    pub roster_witness: Option<VerifiedMlsRecipientRosterWitness>,
}

/// Serving-layer verified, recipient-Station signed Add attestation and its
/// independent accepted Genesis selector. Canonical JSON is the exact typed
/// `MlsAttestAddRequestBody` after signature verification, not a new wire DTO.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedMlsRecipientRosterWitness {
    pub accepted_genesis_event_ref: EventId,
    pub signed_attest_add_request_canonical_json: Vec<u8>,
    /// Present for a same-Station recipient. Remote recipients resolve and
    /// freeze this closure when their signed proof reaches governance.
    pub local_attestor_resolution: Option<arkret_models_identity::AuthenticatedServiceResolution>,
    pub claim_issuer_resolution: Option<arkret_models_identity::AuthenticatedServiceResolution>,
}

/// Peer-authenticated Add authority proof after the serving layer has verified
/// both historical Station signatures (claim receipt and attestation).
/// Persistence still compares every selector with the accepted Commit,
/// producer-signed Welcome and consumed Add Proposal in one transaction.
#[derive(Clone, Debug)]
pub struct VerifiedMlsAddAuthorityAttestation {
    pub source_station_id: arkret_wire::DidCoreId,
    pub request: arkret_models_collaboration::mls_roster_authority::MlsAttestAddRequestBody,
    /// Exact method-native Station resolution used to verify both historical
    /// signatures at ingress. Governance freezes this with the Add proof.
    pub attestor_resolution: arkret_models_identity::AuthenticatedServiceResolution,
    pub claim_issuer_resolution: arkret_models_identity::AuthenticatedServiceResolution,
}

/// Historical facts selected and cross-checked at one governing read cut.
/// The Station service signs a manifest over these complete ordered records;
/// leaf indices and the claim batch never enter this result.
#[derive(Clone, Debug)]
pub struct MlsRosterAuthorityFacts {
    pub group_info_ref: arkret_wire::BlobRef,
    pub ratchet_tree_ref: arkret_wire::BlobRef,
    pub authority_head_commit_event_ref: EventId,
    pub records: Vec<arkret_models_collaboration::mls_roster_authority::MlsRosterRecord>,
    /// The original signed private claim proof for each Add record, in the
    /// same order. It is verified before governance signs a public manifest;
    /// the claim batch is never included in the public roster response.
    pub historical_add_proofs:
        Vec<arkret_models_collaboration::mls_roster_authority::MlsAttestAddRequestBody>,
}

#[derive(Clone, Debug)]
pub enum MlsMemberRosterSelectorRead {
    NotFound,
    RevisionUnavailable,
    Authorized {
        request: Box<
            arkret_models_collaboration::mls_roster_authority::MlsRosterAuthorityReadRequestBody,
        >,
        governance_station_id: arkret_wire::DidCoreId,
    },
}

#[derive(Clone, Debug)]
pub enum MlsRosterAuthorityRead {
    NotFound,
    RevisionUnavailable,
    /// `None` means the caller's Account Station proved its local cut but
    /// must forward to governance for the complete historical facts.
    Authorized {
        facts: Option<MlsRosterAuthorityFacts>,
    },
}

/// The durable claim ledger row `keypackage_claim_ref` resolved to, with the
/// exact request digest the verification read; the accepting transaction
/// requires the row to still hold that request and a live claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsWelcomeClaimLedgerKey {
    pub source_id: String,
    pub claim_request_id: String,
    pub request_digest: String,
}

/// Why the current MLS send gate refuses one application body
/// (encryption-and-audit.md §2.5.2, decision 0100).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MlsSendGateRefusal {
    /// Plaintext into a scope with an accepted `ak.mls.genesis`.
    ActivationRequired,
    /// Ciphertext into a scope with no accepted MLS Genesis/current group.
    NotActivated,
    /// The scope's key-access revision still awaits a covering winning
    /// Commit: the sender pauses instead of re-encrypting.
    EpochUpdateRequired,
    /// The frozen epoch or `group_state_ref` differs from the ready current
    /// group: the sender refreshes the group and re-encrypts a new request.
    EpochMismatch,
}

impl MlsSendGateRefusal {
    /// The registered identity the refusal carries.
    #[must_use]
    pub const fn conflict_code(self) -> crate::ConflictCode {
        match self {
            Self::ActivationRequired => crate::ConflictCode::MlsActivationRequired,
            Self::NotActivated => crate::ConflictCode::FailedPrecondition,
            Self::EpochUpdateRequired => crate::ConflictCode::EpochUpdateRequired,
            Self::EpochMismatch => crate::ConflictCode::EpochMismatch,
        }
    }

    #[must_use]
    pub const fn detail(self) -> &'static str {
        match self {
            Self::ActivationRequired => "plaintext is not allowed after MLS activation",
            Self::NotActivated => "scope has no accepted MLS group",
            Self::EpochUpdateRequired => {
                "the scope key-access revision is not yet covered by an accepted MLS Commit"
            }
            Self::EpochMismatch => "frozen message encryption context is no longer applicable",
        }
    }

    /// The refusal as the persistence conflict its registered code parses
    /// back from.
    #[must_use]
    pub fn into_conflict(self) -> crate::PersistenceError {
        crate::PersistenceError::Conflict(format!("{}: {}", self.conflict_code(), self.detail()))
    }
}

/// The encrypted envelopes one `ak.message.create` payload carries, content
/// first: `None` for a plaintext body.
pub fn message_create_envelopes(
    payload: &std::collections::BTreeMap<String, serde_json::Value>,
) -> Result<Option<Vec<arkret_models_crypto::EncryptedEnvelope>>, String> {
    let envelope = |field: &str| {
        payload
            .get(field)
            .map(|value| serde_json::from_value(value.clone()))
            .transpose()
            .map_err(|error| format!("message {field}: {error}"))
    };
    match (
        envelope("encrypted_content")?,
        envelope("encrypted_metadata")?,
    ) {
        (Some(content), metadata) => Ok(Some(std::iter::once(content).chain(metadata).collect())),
        (None, None) => Ok(None),
        (None, Some(_)) => Err("message encrypted_metadata requires encrypted_content".to_owned()),
    }
}

/// encryption-and-audit.md §2.5.2: decide the current MLS send gate of one
/// application body against the scope's `current` group. `envelopes` is
/// `None` for plaintext and otherwise every encrypted envelope of the body.
/// An uncovered key-access revision wins over a stale frozen epoch; the
/// sending endpoint's own authorization is decided by the caller first, at
/// the same cut.
pub fn decide_mls_send_gate(
    current: Option<&arkret_wire::MlsGroupCurrent>,
    scope: &arkret_wire::ScopeRef,
    envelopes: Option<&[&arkret_models_crypto::EncryptedEnvelope]>,
) -> Result<(), MlsSendGateRefusal> {
    let Some(envelopes) = envelopes else {
        return match current {
            Some(_) => Err(MlsSendGateRefusal::ActivationRequired),
            None => Ok(()),
        };
    };
    let current = current.ok_or(MlsSendGateRefusal::NotActivated)?;
    if current.covered_key_access_revision < current.current_key_access_revision {
        return Err(MlsSendGateRefusal::EpochUpdateRequired);
    }
    if current.effective_scope != *scope
        || envelopes.iter().any(|envelope| {
            envelope.encryption_context.epoch() != current.epoch
                || envelope.encryption_context.group_state_ref()
                    != &current.current_mls_commit_event_ref
        })
    {
        return Err(MlsSendGateRefusal::EpochMismatch);
    }
    Ok(())
}

impl AuthorityCommitTransaction {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        if !self.welcomes.is_empty() && self.recipient_queue_capacity == 0 {
            return Err(arkret_wire::WireError::Protocol(
                "MLS Welcome transaction omitted its recipient queue capacity".to_owned(),
            ));
        }
        self.event.validate_for_submit_structural()?;
        self.commit.validate_shape()?;
        let expected_stream =
            CommitStreamRef::from_scope(&self.event.scope_ref, Some(self.event.realm_id.clone()))?;
        if self.expected_authority.realm_id != self.event.realm_id
            || self.commit.realm_id != self.event.realm_id
            || self.commit.event_ref != self.event.event_id
            || self.commit.stream_ref != expected_stream
            || self.commit.governance_generation != self.expected_authority.generation
            || self.commit.authority_ref != self.expected_authority.authority_ref
        {
            return Err(arkret_wire::WireError::Protocol(
                "authority commit transaction bindings disagree".to_owned(),
            ));
        }
        let is_mls = matches!(
            self.event.kind,
            arkret_wire::EventKind::MlsGenesis | arkret_wire::EventKind::MlsCommit
        );
        match &self.mls_state {
            Some(state) if is_mls => validate_mls_installation(&self.event, state)?,
            None if !is_mls => {}
            _ => {
                return Err(arkret_wire::WireError::Protocol(
                    "MLS Genesis or Commit acceptance requires exactly one installed group state"
                        .to_owned(),
                ));
            }
        }
        if !self.welcomes.is_empty() && self.event.kind != arkret_wire::EventKind::MlsCommit {
            return Err(arkret_wire::WireError::Protocol(
                "MLS Welcome delivery requires an MLS Commit Event".to_owned(),
            ));
        }
        for welcome in &self.welcomes {
            let delivery = &welcome.delivery;
            delivery.validate_shape()?;
            if delivery.realm_id != self.event.realm_id
                || delivery.effective_scope != self.event.scope_ref
                || delivery.commit_event_ref != self.event.event_id
            {
                return Err(arkret_wire::WireError::Protocol(
                    "MLS Welcome does not bind the committed Event and stream".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

fn validate_mls_installation(
    event: &Event,
    state: &MlsStateInstallation,
) -> arkret_wire::Result<()> {
    let payload = serde_json::to_value(&event.payload).map_err(|error| {
        arkret_wire::WireError::Protocol(format!("MLS Event payload cannot be encoded: {error}"))
    })?;
    let mismatch = || {
        arkret_wire::WireError::Protocol(
            "installed MLS state differs from the signed governance binding".to_owned(),
        )
    };
    if state.public_state.is_empty() || state.effective_scope != event.scope_ref {
        return Err(mismatch());
    }
    match event.kind {
        arkret_wire::EventKind::MlsGenesis => {
            let payload: arkret_models_collaboration::events_payloads::MlsGenesisPayload =
                serde_json::from_value(payload).map_err(|error| {
                    arkret_wire::WireError::Protocol(format!(
                        "MLS Genesis Event has no valid payload: {error}"
                    ))
                })?;
            payload.validate()?;
            if payload.effective_scope() != &event.scope_ref
                || state.base.is_some()
                || state.epoch != 0
                || !state.consumed_proposals.is_empty()
            {
                return Err(mismatch());
            }
            let carried = state
                .public_blobs
                .iter()
                .map(|blob| &blob.blob_ref)
                .collect::<Vec<_>>();
            if !carried.is_empty()
                && carried != [&payload.group_info_ref, &payload.ratchet_tree_ref]
            {
                return Err(arkret_wire::WireError::Protocol(
                    "a forwarded Genesis stores exactly its GroupInfo and ratchet tree Blobs"
                        .to_owned(),
                ));
            }
        }
        _ => {
            let payload: arkret_models_crypto::MlsCommitPayload = serde_json::from_value(payload)
                .map_err(|error| {
                arkret_wire::WireError::Protocol(format!(
                    "MLS Commit Event has no valid governance binding: {error}"
                ))
            })?;
            let binding = payload.governance_binding();
            let Some(base) = &state.base else {
                return Err(mismatch());
            };
            if state.public_blobs.len() != 1 {
                return Err(mismatch());
            }
            for (ordinal, proposal) in state.consumed_proposals.iter().enumerate() {
                if proposal.ordinal != ordinal as u64
                    || proposal.proposal_ref.is_empty()
                    || proposal.proposal_wire.is_empty()
                    || proposal.sender_leaf.actor_id != event.actor_id
                    || !matches!(
                        (
                            proposal.proposal_type,
                            &proposal.target_before,
                            &proposal.target_after
                        ),
                        (1, None, Some(_))
                            | (2, Some(_), Some(_))
                            | (3, Some(_), None)
                            | (4, None, None)
                            | (7, None, None)
                    )
                {
                    return Err(mismatch());
                }
            }
            if binding.effective_scope() != &event.scope_ref
                || base.current_mls_commit_event_ref != *payload.base_group_state_ref()
                || base.epoch != payload.base_epoch()
                || state.epoch != payload.next_epoch()
                || payload.covers_key_access_revision() != binding.key_access_revision()
            {
                return Err(mismatch());
            }
        }
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthorityCommitWriteOutcome {
    Committed,
    Duplicate,
    StaleAuthority(CurrentRealmAuthority),
}

/// Outcome of the registered `accepted_device` authorization unit.
#[derive(Clone, Debug, PartialEq)]
pub enum AcceptedDeviceAuthorizationOutcome {
    /// This call committed the Event, its RealmCommit and the device current.
    Committed(arkret_wire::RealmCommit),
    /// The exact Event was already accepted; this is its stored Commit.
    Duplicate(arkret_wire::RealmCommit),
}

/// How a member Station holds one verified committed replica on a Realm
/// stream it does not govern (`federation.md` §4.1.1).
#[derive(Clone, Debug, PartialEq)]
pub enum CommittedReplicaRole {
    /// The exact governor-accepted result of this hosted Account's own
    /// Circle leave. The store must prove its frozen original submission,
    /// parent Realm revision and canonical opening join in the same cut.
    /// This does not authorize ordinary replication or any read surface.
    AcceptedOwnCircleLeave {
        member_account_id: arkret_wire::AccountId,
    },
    /// A hosted member's own verified join (its `ak.member.state{join}` or
    /// its directed `ak.invite.accept`). While no hosted member is joined it
    /// opens the held stream -- or re-opens the stream this Station still
    /// holds, restarting continuity at the join (decision 0122) -- which stays
    /// pending anchor until the governing Station's bootstrap snapshot is
    /// installed; otherwise it is an ordinary held-stream successor.
    OpeningJoin {
        member_account_id: arkret_wire::AccountId,
    },
    /// A direct successor of the held head of an anchored stream. At or
    /// below the installed bootstrap snapshot head it is held for continuity
    /// and as canonical bytes only, its effect already being in the installed
    /// typed current; after it, the hosted-member basis and the Event's
    /// visibility are re-verified against local typed current, which the
    /// Event then advances.
    HeldStream,
}

/// One committed Event a non-governance member Station stores as an exact
/// source replica (`federation.md` §3, §4.1.1).
///
/// The serving layer has already verified the producer proof, the source
/// RealmCommit under `authority` and the Event/Commit binding. The store
/// re-proves continuity, the anchor state and, for a successor, the
/// hosted-member basis and visibility under its own locks.
#[derive(Clone, Debug, PartialEq)]
pub struct CommittedReplica {
    /// This Station's own service id; a replica never names it as governance.
    pub local_service_id: arkret_wire::DidCoreId,
    /// The verified remote current authority the source Commit verified under.
    pub authority: CurrentRealmAuthority,
    /// Required for a verified older-tenure Full received under a newer cut.
    pub historical_commit: Option<arkret_identity::VerifiedHistoricalRealmCommit>,
    pub event: arkret_wire::Event,
    pub commit: arkret_wire::RealmCommit,
    pub producer_signer_fact:
        Option<arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact>,
    /// The immutable Genesis selector carried by an authenticated
    /// committed-replication item. A verified scan has no such carrier.
    pub genesis_event_ref: Option<EventId>,
    pub role: CommittedReplicaRole,
    pub received_at: chrono::DateTime<chrono::Utc>,
    /// The Welcomes the item carried for recipients this Station hosts whose
    /// claims the serving layer re-verified against this Station's ledger
    /// (encryption-and-audit.md §2.2 "跨站 recipient"); queued in the same
    /// transaction as the replica, each on its own.
    pub welcomes: Vec<VerifiedMlsWelcome>,
}

/// One verified RealmCommit whose Event the peer scan withheld, kept by a
/// member Station as a continuity-only chain node (`federation.md` §4.1.1).
/// It never enters the canonical Event store, a reducer, dedupe or digest.
#[derive(Clone, Debug, PartialEq)]
pub struct CommittedChainNode {
    pub local_service_id: arkret_wire::DidCoreId,
    pub authority: CurrentRealmAuthority,
    /// The same proof is required for continuity-only older-tenure nodes.
    pub historical_commit: Option<arkret_identity::VerifiedHistoricalRealmCommit>,
    pub commit: arkret_wire::RealmCommit,
}

/// Result of storing one committed replica.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommittedReplicaOutcome {
    Stored,
    Duplicate,
}

/// The Realm stream a member Station holds as a replica, opened by a hosted
/// member's own join (`federation.md` §4.1.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplicaStreamAnchor {
    pub realm_id: arkret_wire::RealmId,
    pub join_commit: arkret_wire::RealmCommit,
    pub member_account_id: arkret_wire::AccountId,
    /// The installed bootstrap snapshot head; `None` while pending anchor.
    pub anchored_head: Option<CommitStreamHead>,
}

/// A verified bootstrap snapshot a member Station installs as the typed
/// current of its pending replica stream (`federation.md` §4.1.1).
#[derive(Clone, Debug, PartialEq)]
pub struct ReplicaAnchorInstall {
    pub realm_id: arkret_wire::RealmId,
    /// Exact current bootstrap reader join. A pending anchor requires its
    /// original opening; refresh may use another proved hosted current join.
    pub join_commit_id: arkret_wire::RealmCommitId,
    /// Generation authenticated by the signed bootstrap snapshot.
    pub governance_generation: u64,
    /// The snapshot's head on the Realm stream, at or after the join.
    pub snapshot_head: CommitStreamHead,
    pub visible_stream_heads: Vec<CommitStreamHead>,
    pub current_state_entries: Vec<arkret_wire::TypedCurrentRow>,
    /// Exact signed bootstrap verified by the caller, archived with its rows.
    pub verified_snapshot: arkret_wire::RealmStateSnapshot,
}

/// Inputs for the same read-only Signal eligibility cut used by every layer.
#[derive(Clone, Copy, Debug)]
pub struct SignalScopeAuthorityQuery<'a> {
    pub scope: &'a arkret_wire::ScopeRef,
    pub authority_commit_id: &'a RealmCommitId,
    pub parent_realm_authority_commit_id: Option<&'a RealmCommitId>,
    pub sender: &'a arkret_wire::ActorId,
    pub signal_class: arkret_wire::SignalClass,
    pub sent_at: DateTime<Utc>,
    pub at: DateTime<Utc>,
    pub include_product_authority: bool,
    pub product_agent: Option<(
        &'a arkret_wire::AccountId,
        &'a arkret_models_collaboration::events_payloads::agent::AgentKeyScope,
    )>,
}

/// Internal read-only eligibility at the Signal's signed and current cuts.
#[derive(Clone, Debug)]
pub struct SignalScopeAuthority {
    pub recipient_actors: Vec<arkret_wire::ActorId>,
    pub historical_mls_event_ref: arkret_wire::EventId,
    pub current_mls: arkret_wire::MlsGroupCurrent,
    pub cipher_suite: String,
    pub current_realm_head: arkret_wire::CommitStreamHead,
    pub current_scope_head: arkret_wire::CommitStreamHead,
    pub product_authority: Option<Box<arkret_models_collaboration::SignalProductAuthority>>,
}

/// Accepted Call state and complete-ActorId roster at one held stream head.
#[derive(Clone, Debug)]
pub struct CallCurrentCut {
    pub scope_ref: arkret_wire::ScopeRef,
    pub head: arkret_wire::CommitStreamHead,
    pub generation: u64,
    pub lifecycle: arkret_models_collaboration::events_payloads::call::CallLifecycleState,
    pub focus: Option<arkret_models_collaboration::events_payloads::call::CallFocus>,
    pub participants: Vec<(
        arkret_models_collaboration::events_payloads::call::CallParticipant,
        arkret_wire::RealmCommit,
    )>,
    pub roster_revision: Option<arkret_wire::CurrentRevision>,
    pub moderation_revision: Option<arkret_wire::CurrentRevision>,
    pub moderation_current:
        Option<arkret_models_collaboration::events_payloads::call::CallModerationCurrentValue>,
    pub moderation: Vec<arkret_models_collaboration::events_payloads::call::CallParticipantRemoval>,
}

/// One atomic read cut for a member's MLS Genesis material request. A member
/// Station may authorize from its verified replica without holding Genesis
/// FullView; the governing Station must return the exact accepted Genesis.
#[derive(Clone, Debug)]
pub enum MlsMemberGroupStateMaterialRead {
    NotFound,
    RevisionUnavailable,
    Authorized {
        genesis: Option<Box<arkret_wire::CommittedEventFullView>>,
    },
}

/// One request-local observation of the configured Account Authority's complete
/// authenticated resolve answer. It is never serialized or persisted, and does
/// not turn record signing or receipt acceptance time into a freshness TTL.
#[derive(Clone, Debug)]
pub struct AccountStatusCurrentObservation {
    record: arkret_models_collaboration::account_status::AccountStatusRecord,
    completed_at: std::time::Instant,
}

impl AccountStatusCurrentObservation {
    /// Called only after the original signed resolve reaches its final page
    /// and every returned original record is verified and monotonically stored.
    pub fn after_authenticated_resolve(
        record: arkret_models_collaboration::account_status::AccountStatusRecord,
    ) -> Self {
        Self {
            record,
            completed_at: std::time::Instant::now(),
        }
    }

    pub fn record(&self) -> &arkret_models_collaboration::account_status::AccountStatusRecord {
        &self.record
    }

    pub fn is_completed(&self) -> bool {
        self.completed_at <= std::time::Instant::now()
    }
}

/// Process-local publication inputs using the original SDK content models.
/// This is not a wire object or a reusable authorization assertion.
#[derive(Clone, Debug, Default)]
pub struct AccountContentDeliveryInput {
    /// New Blob bytes at an exact Realm upload boundary; never a read grant.
    pub native_blob_upload: Option<arkret_wire::RealmId>,
    pub realms: Vec<arkret_wire::RealmId>,
    pub committed_events: Vec<arkret_wire::CommittedEventView>,
    /// Exact immutable claim response and the real native endpoints whose
    /// current material permission must remain held through this handoff.
    pub keypackage_claims: Vec<crate::MlsKeyPackageClaimDelivery>,
    /// Exact member selectors for public MLS material at the native handoff cut.
    pub mls_group_material_reads: Vec<
        arkret_models_collaboration::mls_group_state_material::MlsMemberGroupStateMaterialReadRequestBody,
    >,
    pub mls_roster_reads: Vec<
        arkret_models_collaboration::mls_roster_authority::MlsMemberRosterAuthorityReadRequestBody,
    >,
    /// Exact prepared scan and original SDK response, re-read on the held cut.
    pub stream_scans: Vec<(
        arkret_wire::StreamScanRequest,
        arkret_wire::StreamScanOutcome,
    )>,
    pub current_views:
        Vec<arkret_models_collaboration::sync_frames::current_results::AccountCurrentView>,
    pub projection_lists: Vec<(
        arkret_wire::RealmId,
        bool,
        arkret_models_collaboration::objects::query_projection::ProjectionSpaceList,
        arkret_models_collaboration::objects::query_projection::ProjectionStrandList,
    )>,
    pub morph_lists: Vec<(
        arkret_wire::RealmId,
        bool,
        arkret_models_collaboration::objects::query_projection::ProjectionMorphList,
    )>,
    pub morph_documents: Vec<(
        arkret_wire::RealmId,
        arkret_wire::MorphId,
        arkret_models_collaboration::objects::query_projection::DocumentMorphProjectionOutcome,
    )>,
    pub morph_absences: Vec<(arkret_wire::RealmId, arkret_wire::MorphId)>,
    pub account_status_observations: Vec<AccountStatusCurrentObservation>,
    pub realm_lifecycle_reads: Vec<arkret_models_collaboration::governance::realm_governance::RealmLifecycleView>,
    pub realm_link_reads: Vec<(arkret_models_collaboration::governance::realm_governance::RealmLinkList, Option<Vec<String>>)>,
    pub realm_exports: Vec<arkret_models_collaboration::governance::realm_governance::RealmExport>,
    pub snapshots: Vec<arkret_wire::RealmStateSnapshot>,
    pub future_materials: Vec<arkret_wire::MlsWelcomeDelivery>,
    pub notifications:
        Vec<arkret_models_collaboration::sync_frames::account_subscribe::NotificationDelta>,
    pub exact_reads: Vec<(
        arkret_models_collaboration::exact_current_results::ExactCurrentResultsReadRequestBody,
        arkret_models_collaboration::exact_current_results::ExactCurrentResultsReadOutcome,
    )>,
    pub watch_reads: Vec<(
        arkret_models_collaboration::strand_watch_operations::StrandWatchCurrentRequestBody,
        arkret_models_collaboration::strand_watch_operations::StrandWatchCurrentOutcome,
    )>,
    /// Trusted in-process witness from a fresh authenticated governing peer.
    /// It is only consumed by this one response's local delivery guard.
    pub remote_watch_read: Option<(
        arkret_models_collaboration::strand_watch_operations::StrandWatchCurrentRequestBody,
        arkret_models_collaboration::strand_watch_operations::StrandWatchCurrentOutcome,
        CurrentRealmAuthority,
    )>,
    /// A fresh governing audited-read response or its durable local freeze.
    pub audited_watch_read: Option<(
        arkret_models_collaboration::strand_watch_operations::WatchAuditReadRequest,
        arkret_models_collaboration::strand_watch_operations::WatchAuditReadOutcome,
        CurrentRealmAuthority,
    )>,
    pub watch_delivery_device: Option<crate::DeviceRevocationGateSelector>,
    /// Authenticated exact private material, verified before entering delivery.
    pub realm_actor_material: Option<Box<(
        arkret_models_integration::RealmActorMaterialRequest,
        arkret_models_integration::RealmActorMaterialOutcome,
        CurrentRealmAuthority,
    )>>,
    /// Local bearer sessions retain their exact stored Account through handoff.
    /// Request-scoped signed grants are freshly introspected at the HTTP cut.
    pub watch_local_session: Option<(String, crate::AccountPk)>,
    pub blobs: Vec<(
        arkret_wire::BlobRef,
        crate::BlobRecord,
        arkret_wire::CapabilityActionId,
    )>,
    pub credential_expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub agent_session_scope: Option<(Vec<String>, serde_json::Map<String, serde_json::Value>)>,
    pub agent_endpoint: Option<crate::AgentEndpointGuard>,
    pub applet_endpoint: Option<AppletManagedDeviceScopeGuard>,
    pub qualified_agent_scope_evidence: Option<crate::VerifiedAgentScopeEvidence>,
    pub unresolved_content_realms: Vec<arkret_wire::RealmId>,
}

impl AccountContentDeliveryInput {
    pub fn committed(rows: &[arkret_wire::CommittedEventView]) -> Self {
        Self {
            realms: rows
                .iter()
                .map(|row| row.commit().realm_id.clone())
                .collect(),
            committed_events: rows.to_vec(),
            ..Self::default()
        }
    }

    pub fn snapshot(snapshot: &arkret_wire::RealmStateSnapshot) -> Self {
        Self {
            realms: vec![snapshot.realm_id.clone()],
            snapshots: vec![snapshot.clone()],
            ..Self::default()
        }
    }

    pub fn account_frame(
        frame: &arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame,
    ) -> PersistenceResult<Self> {
        let mut input = Self::default();
        if let Some(realms) = &frame.realms {
            for (id, detail) in &realms.entries {
                if detail.unavailable.is_some() {
                    continue;
                }
                let realm = arkret_wire::RealmId::new(id)
                    .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
                input.realms.push(realm.clone());
                input
                    .committed_events
                    .extend(detail.committed_events.iter().flatten().cloned());
                input.current_views.extend(detail.current.iter().cloned());
                if detail.state_at_window_start.is_some() || detail.member_roster.is_some() {
                    input.unresolved_content_realms.push(realm);
                }
            }
        }
        if let Some(deliveries) = &frame.to_device {
            for delivery in &deliveries.deliveries {
                if let arkret_models_collaboration::device_messages::RecipientDelivery::MlsWelcome { mls_welcome } = delivery {
                    input.realms.push(mls_welcome.realm_id.clone());
                    input.future_materials.push(mls_welcome.clone());
                }
            }
        }
        if let Some(notifications) = &frame.notifications {
            for delta in &notifications.items {
                delta
                    .validate_shape()
                    .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
                if let Some(content) = delta.ordinary_projection() {
                    input.realms.push(content.realm_id.clone());
                    input.notifications.push(delta.clone());
                }
            }
        }
        Ok(input)
    }
}

/// Process-local lock lease through the actual response handoff. It is never
/// serialized, signed, cached or accepted as a reusable authorization token.
#[async_trait]
pub trait AccountContentDeliveryGuard: Send {
    /// Publish native Blob metadata in the same transaction as its held
    /// authorization cut. Ordinary read guards cannot perform this write.
    async fn commit_native_blob_upload(
        self: Box<Self>,
        _reference: &arkret_wire::BlobRef,
        _record: &crate::BlobRecord,
        _max_actor_bytes: u64,
        _max_realm_bytes: u64,
    ) -> PersistenceResult<crate::BlobRecord> {
        Err(crate::PersistenceError::Conflict(
            "native Blob upload admission is unavailable".into(),
        ))
    }
    /// Recheck clock-dependent facts from the held cut immediately before the
    /// transport accepts bytes. Locks cannot prevent an expiry or time window.
    fn permits_handoff(&self) -> bool {
        false
    }
    /// Finish any asynchronous validation at the physical frame boundary.
    /// The implementation retains its original cut and rechecks its clock.
    async fn prepare_handoff(&mut self) -> bool {
        self.permits_handoff()
    }
    async fn finish(self: Box<Self>) -> PersistenceResult<()>;
}

/// Exact principals, accepted source and current cut used to prepare a native reply.
pub struct NativeMessageReplyPreparation<'a> {
    pub agent: &'a arkret_wire::AccountId,
    pub controller: &'a arkret_wire::AccountId,
    pub caller: &'a arkret_wire::AccountId,
    pub station: &'a arkret_wire::DidCoreId,
    pub source: &'a arkret_wire::CommittedEventFullView,
    pub strand: &'a arkret_wire::StrandId,
    pub input: &'a AccountContentDeliveryInput,
    pub deployment: arkret_models_collaboration::governance::agent_participation::ParticipationBits,
}

#[async_trait]
pub trait AuthorityCommitStore: Send + Sync {
    async fn call_current_cut(
        &self,
        _realm: &arkret_wire::RealmId,
        _call: &arkret_wire::CallId,
        _actor: &arkret_wire::ActorId,
    ) -> PersistenceResult<Option<CallCurrentCut>> {
        Err(PersistenceError::Conflict(
            "temporarily_unavailable: Call current cut is not available".to_owned(),
        ))
    }
    async fn check_call_media_release(
        &self,
        _request: &arkret_models_collaboration::objects::media::CallMediaTokenExchangeRequestBody,
        _issuer: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<bool> {
        Err(PersistenceError::Conflict(
            "temporarily_unavailable: media release cut is unavailable".to_owned(),
        ))
    }
    async fn realm_media_service_current(
        &self,
        _realm: &arkret_wire::RealmId,
    ) -> PersistenceResult<
        Option<arkret_models_collaboration::events_payloads::RealmMediaServiceValue>,
    > {
        Err(PersistenceError::Conflict(
            "temporarily_unavailable: media service current is not available".to_owned(),
        ))
    }
    /// Governing capability/management preflight for self or the exact verified
    /// controller of an owned Agent. This does not issue a runtime/session grant.
    async fn owned_agent_authorization_check(
        &self,
        _caller: &arkret_wire::ActorId,
        _station: &arkret_wire::DidCoreId,
        _request: &arkret_models_collaboration::governance::authorization::AuthzCheckRequestBody,
    ) -> PersistenceResult<
        Option<arkret_models_collaboration::governance::authorization::AuthzCheckOutcome>,
    > {
        Ok(None)
    }

    /// Revalidate complete bytes at this Station's current governing cut and
    /// retain all revocable dependency locks through network handoff. A replica
    /// without a registered authenticated governing barrier must fail closed.
    async fn acquire_committed_content_delivery(
        &self,
        _account: &arkret_wire::AccountId,
        _station: &arkret_wire::DidCoreId,
        _input: &AccountContentDeliveryInput,
    ) -> PersistenceResult<Option<Box<dyn AccountContentDeliveryGuard>>> {
        Err(crate::PersistenceError::Conflict(
            "revision_unavailable: current content delivery barrier is unavailable".into(),
        ))
    }

    async fn acquire_realm_actor_content_delivery(
        &self,
        _actor: &arkret_wire::ActorId,
        _station: &arkret_wire::DidCoreId,
        _input: &AccountContentDeliveryInput,
    ) -> PersistenceResult<Option<Box<dyn AccountContentDeliveryGuard>>> {
        Err(crate::PersistenceError::Conflict(
            "revision_unavailable: current content delivery barrier is unavailable".into(),
        ))
    }

    /// Hold a governing cut for fixed native MessageCreate reply preparation.
    /// Only trusted in-process callers supply original session/custody evidence.
    /// This creates neither a signed Event nor a quota operation identity.
    async fn acquire_native_message_reply_preparation(
        &self,
        _request: NativeMessageReplyPreparation<'_>,
    ) -> PersistenceResult<Box<dyn AccountContentDeliveryGuard>> {
        Err(crate::PersistenceError::Conflict(
            "revision_unavailable: native reply preparation barrier is unavailable".into(),
        ))
    }

    /// Assemble the complete registered Agent sibling from immutable accepted
    /// producer records and one current Origin cut. This is an internal port,
    /// not a new disclosure surface. ASRE alone is never a successful result.
    /// Original accepted producer material is staged before the admission unit.
    /// Only the exact signed candidate can consume it in the Commit transaction.
    async fn stage_agent_control_source(
        &self,
        _full: &arkret_wire::CommittedEventFullView,
        _dependency: &arkret_models_identity::AgentSignerDependency,
        _history: &arkret_models_identity::AuthenticatedServiceResolution,
    ) -> PersistenceResult<()> {
        Err(crate::PersistenceError::Conflict(
            "dependency_missing: Origin source storage unavailable".into(),
        ))
    }

    async fn prepare_agent_origin_state(
        &self,
        event: &Event,
        at: DateTime<Utc>,
    ) -> PersistenceResult<arkret_models_identity::AgentAuthorityState> {
        let _ = (event, at);
        Err(crate::PersistenceError::Conflict(
            "dependency_missing: Agent Origin complete evidence assembly is unavailable".into(),
        ))
    }

    async fn agent_origin_controller_gate_request(
        &self,
        event: &Event,
        evidence: &arkret_models_identity::AgentAuthorityState,
    ) -> PersistenceResult<arkret_wire::RequestId> {
        let _ = (event, evidence);
        Err(crate::PersistenceError::Conflict(
            "dependency_missing: durable Agent Origin gate request is unavailable".into(),
        ))
    }

    /// Under the original PCR/controller locks, reassemble and compare the
    /// complete typed source, check current key/lifecycle/gate, and persist the
    /// full carrier/ref before queueing the forwarding Event. A stale cut must
    /// refuse; it must not refresh or rewrite the supplied historical records.
    async fn retain_agent_forward_evidence_at_same_cut(
        &self,
        event: &Event,
        evidence: &arkret_models_identity::AgentProducerEvidence,
        at: DateTime<Utc>,
    ) -> PersistenceResult<()> {
        let _ = (event, evidence, at);
        Err(crate::PersistenceError::Conflict(
            "dependency_missing: Agent Origin same-cut retention is unavailable".into(),
        ))
    }

    /// Exact retained source; never read current authority to fill a missing historical row.
    async fn account_device_signer_fact(
        &self,
        event: &Event,
        commit: &RealmCommit,
    ) -> PersistenceResult<
        Option<arkret_models_collaboration::authority_commit::AccountDeviceHistoricalSignerFact>,
    >;
    /// Read an immutable source-only candidate. Admission repeats this at the locked cut.
    async fn prepare_realm_device_signer_fact(
        &self,
        _event: &arkret_wire::Event,
        _at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<
        arkret_models_collaboration::authority_commit::RealmDeviceHistoricalSignerFact,
    > {
        Err(PersistenceError::Internal(
            "Realm Device signer source is unavailable".into(),
        ))
    }

    async fn prepare_account_device_signer_fact(
        &self,
        event: &Event,
        admitted_at: DateTime<Utc>,
    ) -> PersistenceResult<
        Option<arkret_models_collaboration::authority_commit::AccountDeviceHistoricalSignerFact>,
    >;

    async fn producer_signer_fact(
        &self,
        event: &Event,
        commit: &RealmCommit,
    ) -> PersistenceResult<
        Option<arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact>,
    > {
        Ok(self
            .account_device_signer_fact(event, commit)
            .await?
            .map(Into::into))
    }
    async fn realm_actor_control_replay(
        &self,
        event: &Event,
        carrier: &AppletControlCarrier,
        request_digest: &arkret_wire::Hash,
    ) -> PersistenceResult<Option<RealmCommit>> {
        let _ = (event, carrier, request_digest);
        Err(PersistenceError::Conflict(
            "dependency_missing: private control replay unavailable".into(),
        ))
    }

    async fn read_realm_actor_material(
        &self,
        request: &arkret_models_integration::RealmActorMaterialRequest,
        caller: &RealmActorMaterialCaller,
        governor: &arkret_wire::DidCoreId,
        sign: RealmActorMaterialSigner<'_>,
    ) -> PersistenceResult<arkret_models_integration::RealmActorMaterialOutcome> {
        let _ = (request, caller, governor, sign);
        Err(PersistenceError::Conflict(
            "dependency_missing: private Realm material reader unavailable".into(),
        ))
    }

    async fn prepare_applet_authoring_completion(
        &self,
        completion: &crate::AppletAuthoringCompletion,
        governor: &arkret_wire::DidCoreId,
        delivery_key_digest: &arkret_wire::Hash,
        sign: RealmActorMaterialSigner<'_>,
    ) -> PersistenceResult<crate::AppletAuthoringCompletion> {
        let _ = (completion, governor, delivery_key_digest, sign);
        Err(PersistenceError::Internal(
            "durable creation completion material unavailable".into(),
        ))
    }

    async fn applet_registration_for_realm(
        &self,
        realm: &arkret_wire::RealmId,
        applet: &arkret_wire::AppletId,
    ) -> PersistenceResult<arkret_models_integration::AppletRegistrationPayload> {
        let _ = (realm, applet);
        Err(PersistenceError::Conflict(
            "dependency_missing: accepted Applet registration unavailable".into(),
        ))
    }

    async fn realm_actor_control_carrier(
        &self,
        metadata: &arkret_models_integration::RealmActorControlHttpMetadata,
        governor: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<AppletControlCarrier> {
        let _ = (metadata, governor);
        Err(crate::PersistenceError::Conflict(
            "dependency_missing: Realm control authentication unavailable".into(),
        ))
    }

    async fn consume_realm_actor_control_nonce(
        &self,
        expected: &AppletControlCarrier,
        metadata: &arkret_models_integration::RealmActorControlHttpMetadata,
        retain_until: DateTime<Utc>,
    ) -> PersistenceResult<()> {
        let _ = (expected, metadata, retain_until);
        Err(crate::PersistenceError::Conflict(
            "dependency_missing: Realm control nonce store unavailable".into(),
        ))
    }

    async fn prepare_realm_actor_control_signer_fact(
        &self,
        event: &Event,
        at: DateTime<Utc>,
    ) -> PersistenceResult<
        arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact,
    > {
        let _ = (event, at);
        Err(crate::PersistenceError::Conflict(
            "dependency_missing: Realm control signer source unavailable".into(),
        ))
    }

    async fn prepare_service_signer_fact(
        &self,
        event: &Event,
        guard: &crate::AppletEventProducerGuard,
        at: DateTime<Utc>,
    ) -> PersistenceResult<
        arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact,
    > {
        let _ = (event, guard, at);
        Err(crate::PersistenceError::Conflict(
            "dependency_missing: Service historical source preparation is unavailable".into(),
        ))
    }

    /// Bind the member's accepted target to immutable Genesis provenance at
    /// one current/target authorized cut, without disclosing a prejoin Event.
    async fn mls_member_roster_selector(
        &self,
        request: &arkret_models_collaboration::mls_roster_authority::MlsMemberRosterAuthorityReadRequestBody,
        issuer: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<MlsMemberRosterSelectorRead> {
        let _ = (request, issuer);
        Err(crate::PersistenceError::Conflict(
            "unsupported_feature: atomic MLS member roster selector is unavailable".to_owned(),
        ))
    }

    /// Return only the producer key frozen at this exact accepted Event.
    /// Current key state must never substitute for a missing admission record.
    async fn historical_producer_signer_key(
        &self,
        realm_id: &arkret_wire::RealmId,
        selector: &arkret_models_identity::SignerKeyQuerySelector,
    ) -> PersistenceResult<Option<arkret_models_identity::SignerKeyQueryOutcome>> {
        let _ = (realm_id, selector);
        Ok(None)
    }

    /// Return a key-only immutable original self-admission fact to its actual Human producer.
    /// Missing provenance never authorizes a PCR history read or current-key fallback.
    async fn historical_self_pcr_producer_signer_key(
        &self,
        realm_id: &arkret_wire::RealmId,
        selector: &arkret_models_identity::SignerKeyQuerySelector,
        recipient: &arkret_wire::AccountId,
    ) -> PersistenceResult<Option<arkret_models_identity::SignerKeyQueryOutcome>> {
        let _ = (realm_id, selector, recipient);
        Ok(None)
    }

    /// Recheck current and target-cut disclosure, history, membership and
    /// peer replication right in one read transaction, then return only a
    /// complete, internally consistent historical roster.
    async fn mls_roster_authority_read(
        &self,
        request: &arkret_models_collaboration::mls_roster_authority::MlsRosterAuthorityReadRequestBody,
        issuer: &arkret_wire::DidCoreId,
        source_peer: Option<&arkret_wire::DidCoreId>,
    ) -> PersistenceResult<MlsRosterAuthorityRead> {
        let _ = (request, issuer, source_peer);
        Err(crate::PersistenceError::Conflict(
            "unsupported_feature: atomic MLS roster authorization is unavailable".to_owned(),
        ))
    }

    /// Install a historical recipient proof only after the caller verified
    /// its authenticated source and historical Station signatures. The store
    /// binds it to frozen accepted facts and returns `Duplicate` only for an
    /// exact replay; any mismatch is a zero-write refusal.
    async fn install_mls_add_authority_attestation(
        &self,
        verified: &VerifiedMlsAddAuthorityAttestation,
        issuer: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<arkret_models_collaboration::mls_roster_authority::MlsAttestAddOutcome>
    {
        let _ = (verified, issuer);
        Err(crate::PersistenceError::Conflict(
            "unsupported_feature: MLS Add authority ingress is unavailable".to_owned(),
        ))
    }

    /// Original signed recipient proof, including acknowledged rows. Replays
    /// reuse these bytes even after claim expiry or Station key rotation.
    async fn mls_recipient_attestation(
        &self,
        commit: &EventId,
        welcome: &arkret_wire::MlsWelcomeDeliveryId,
    ) -> PersistenceResult<
        Option<arkret_models_collaboration::mls_roster_authority::MlsAttestAddRequestBody>,
    > {
        let _ = (commit, welcome);
        Err(crate::PersistenceError::Internal(
            "recipient attestation store unavailable".into(),
        ))
    }

    async fn pending_mls_recipient_attestations(
        &self,
        limit: usize,
    ) -> PersistenceResult<
        Vec<arkret_models_collaboration::mls_roster_authority::MlsAttestAddRequestBody>,
    > {
        let _ = limit;
        Err(crate::PersistenceError::Internal(
            "recipient attestation outbox unavailable".into(),
        ))
    }

    /// Acknowledge only the exact canonical request digest that governance
    /// reports installed. A different digest never retires the durable proof.
    async fn acknowledge_mls_recipient_attestation(
        &self,
        request: &arkret_models_collaboration::mls_roster_authority::MlsAttestAddRequestBody,
        digest: &arkret_wire::Hash,
        at: DateTime<Utc>,
    ) -> PersistenceResult<()> {
        let _ = (request, digest, at);
        Err(crate::PersistenceError::Internal(
            "recipient attestation acknowledgement unavailable".into(),
        ))
    }

    /// Evaluate current and target-cut membership, history and policy in one
    /// repeatable-read transaction. `source_peer` additionally requires the
    /// peer's replication right at that cut. Caller-bearing requests must
    /// never be authorized from independent point reads.
    async fn mls_member_group_state_material_read(
        &self,
        request: &arkret_models_collaboration::mls_group_state_material::MlsGroupStateMaterialRequestBody,
        issuer: &arkret_wire::DidCoreId,
        source_peer: Option<&arkret_wire::DidCoreId>,
    ) -> PersistenceResult<MlsMemberGroupStateMaterialRead> {
        let _ = (request, issuer, source_peer);
        Err(crate::PersistenceError::Conflict(
            "unsupported_feature: atomic MLS material authorization is unavailable".to_owned(),
        ))
    }

    async fn signal_recipient_realms(
        &self,
        actor: &arkret_wire::ActorId,
    ) -> PersistenceResult<Vec<arkret_wire::RealmId>> {
        let _ = actor;
        Err(crate::PersistenceError::Internal(
            "Signal recipient inventory is unavailable".to_owned(),
        ))
    }

    async fn signal_scope_authority(
        &self,
        _query: SignalScopeAuthorityQuery<'_>,
    ) -> PersistenceResult<Option<SignalScopeAuthority>> {
        Err(crate::PersistenceError::Conflict(
            "unsupported_feature: verified Signal scope cuts are unavailable".to_owned(),
        ))
    }

    async fn pending_franking_proofs(
        &self,
        receiver: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<Vec<crate::PendingFrankingProof>> {
        let _ = receiver;
        Ok(Vec::new())
    }

    async fn fix_franking_proof(
        &self,
        prepared: &crate::PreparedFrankingProof,
    ) -> PersistenceResult<Event> {
        let _ = prepared;
        Err(crate::PersistenceError::Conflict(
            "unsupported_feature: durable franking publication is unavailable".to_owned(),
        ))
    }

    async fn complete_franking_proof(
        &self,
        realm: &arkret_wire::RealmId,
        target: &arkret_wire::EventId,
        proof_event: &arkret_wire::EventId,
    ) -> PersistenceResult<()> {
        let _ = (realm, target, proof_event);
        Err(crate::PersistenceError::Conflict(
            "unsupported_feature: durable franking publication is unavailable".to_owned(),
        ))
    }

    async fn install_genesis_authority(
        &self,
        authority: &CurrentRealmAuthority,
    ) -> PersistenceResult<()>;

    /// Record a verified remote current authority of a Realm this Station
    /// does not govern, so it can forward to and verify under it. A lower
    /// generation never replaces a higher one, a same-generation different
    /// authority is refused, and a Realm this Station governs is never
    /// rewritten.
    async fn record_remote_authority(
        &self,
        authority: &CurrentRealmAuthority,
        local_service_id: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<()>;

    /// Whether the frozen Realm fanout intent of `event` to `peer` is still
    /// owed at the current accepted cut: one frozen basis must still hold as
    /// a whole (`federation.md` §4.1.1).
    async fn realm_fanout_still_owed(
        &self,
        event: &arkret_wire::Event,
        local_service_id: &arkret_wire::DidCoreId,
        peer: &arkret_wire::DidCoreId,
        witnesses: &[crate::RealmFanoutAuthorityWitness],
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<bool>;

    /// Store one verified committed replica with its held-stream continuity,
    /// anchor state, hosted-member basis and projected typed current in one
    /// transaction.
    async fn install_committed_audit_pair(
        &self,
        _request: &arkret_models_collaboration::authority_commit::AuditPairedEventFederationSubmission,
        _replicas: &[CommittedReplica; 2],
    ) -> PersistenceResult<arkret_models_collaboration::authority_commit::AggregateAcceptanceStatus>
    {
        Err(PersistenceError::Conflict(
            "revision_unavailable: atomic audit replication unavailable".to_owned(),
        ))
    }

    async fn install_committed_replica(
        &self,
        replica: &CommittedReplica,
    ) -> PersistenceResult<CommittedReplicaOutcome>;

    /// Retain the first peer item outcome in the replica's accepting transaction.
    /// Current recipient authorization is checked again before any receipt read.
    async fn install_committed_peer_replica(
        &self,
        replica: &CommittedReplica,
        receipt: &crate::IdempotencyRecord,
    ) -> PersistenceResult<(CommittedReplicaOutcome, bool)>;

    /// Queue, in one transaction, the re-verified Welcomes of a Commit this
    /// Station already holds as the exact replica (a replay after scan
    /// stored it). The held Commit and Event must equal the item.
    async fn queue_replicated_welcomes(
        &self,
        event: &arkret_wire::Event,
        commit: &arkret_wire::RealmCommit,
        genesis_event_ref: Option<&EventId>,
        welcomes: &[VerifiedMlsWelcome],
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<CommittedReplicaOutcome>;

    /// Store one verified withheld RealmCommit as a continuity-only chain node
    /// that directly follows the anchored held head.
    async fn install_committed_chain_node(
        &self,
        node: &CommittedChainNode,
    ) -> PersistenceResult<CommittedReplicaOutcome>;

    /// The replica anchor of `realm_id`'s Realm stream on this member Station.
    async fn replica_stream_anchor(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> PersistenceResult<Option<ReplicaStreamAnchor>>;

    async fn replica_anchor_for_stream(
        &self,
        stream: &CommitStreamRef,
    ) -> PersistenceResult<Option<ReplicaStreamAnchor>> {
        match stream {
            CommitStreamRef::Realm { realm_id } => self.replica_stream_anchor(realm_id).await,
            _ => Ok(None),
        }
    }

    /// Private write-recovery eligibility for an original accepted Human own
    /// leave. This grants no ordinary scan/get/historical-key read permission.
    /// Caller already verifies the original Gov/producer/Fact and held prefix;
    /// this read checks the same stored bound intent, effective terminal cut
    /// and the hosted member's original opening anchor in one read cut.
    async fn accepted_own_leave_bound_result(
        &self,
        event: &arkret_wire::Event,
        commit: &arkret_wire::RealmCommit,
        account: &arkret_wire::AccountId,
        local_service: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<bool> {
        let _ = (event, commit, account, local_service);
        Ok(false)
    }

    async fn circle_views_for_actor(
        &self,
        realm_id: &arkret_wire::RealmId,
        actor: &arkret_wire::ActorId,
    ) -> PersistenceResult<Vec<arkret_models_collaboration::governance::circle::CircleView>> {
        let _ = (realm_id, actor);
        Ok(Vec::new())
    }

    async fn circle_reads_for_actor(
        &self,
        realm_id: &arkret_wire::RealmId,
        actor: &arkret_wire::ActorId,
    ) -> PersistenceResult<Vec<arkret_models_collaboration::governance::circle::CircleReadView>>
    {
        let _ = (realm_id, actor);
        Ok(Vec::new())
    }

    async fn circle_view_for_actor(
        &self,
        circle_id: &arkret_wire::CircleId,
        actor: &arkret_wire::ActorId,
    ) -> PersistenceResult<Option<arkret_models_collaboration::governance::circle::CircleView>>
    {
        let _ = (circle_id, actor);
        Ok(None)
    }

    async fn circle_read_for_actor(
        &self,
        circle_id: &arkret_wire::CircleId,
        actor: &arkret_wire::ActorId,
    ) -> PersistenceResult<Option<arkret_models_collaboration::governance::circle::CircleReadView>>
    {
        let _ = (circle_id, actor);
        Ok(None)
    }

    async fn replica_authorization_head(
        &self,
        stream: &CommitStreamRef,
    ) -> PersistenceResult<Option<CommitStreamHead>> {
        let _ = stream;
        Ok(None)
    }

    /// Current hosted opening joins eligible to request an independently
    /// verified bootstrap refresh. The original durable prefix stays intact.
    async fn replica_bootstrap_readers(
        &self,
        stream: &CommitStreamRef,
        local_service: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<Vec<(arkret_wire::AccountId, arkret_wire::RealmCommit)>> {
        let _ = (stream, local_service);
        Ok(Vec::new())
    }

    async fn pending_replica_streams(&self) -> PersistenceResult<Vec<CommitStreamRef>> {
        Ok(self
            .pending_replica_stream_anchors()
            .await?
            .into_iter()
            .map(|realm_id| CommitStreamRef::Realm { realm_id })
            .collect())
    }

    /// Every Realm whose replica stream is still pending anchor.
    async fn pending_replica_stream_anchors(&self) -> PersistenceResult<Vec<arkret_wire::RealmId>>;

    /// Atomically install a verified bootstrap snapshot as replica current.
    /// Refreshing via another current hosted join retains the original prefix.
    async fn install_replica_anchor(&self, install: &ReplicaAnchorInstall)
    -> PersistenceResult<()>;

    /// The Commit this Station holds at the head of `stream_ref`, whether a
    /// full replica or a chain node.
    async fn held_stream_head_commit(
        &self,
        stream_ref: &CommitStreamRef,
    ) -> PersistenceResult<Option<arkret_wire::RealmCommit>>;

    async fn current_authority(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> PersistenceResult<Option<CurrentRealmAuthority>>;

    /// Read one accepted current membership only when this service is the
    /// Realm's current governing Station. Missing, remote, or inconsistent
    /// authority/member rows fail closed for optional authoring preparation.
    async fn local_current_member_joined(
        &self,
        realm_id: &arkret_wire::RealmId,
        member: &arkret_wire::ActorId,
        service_id: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<bool>;

    /// Whether `member` is a current joined member of `realm_id` in this
    /// service's accepted state: the typed `member_state` current row, backed
    /// by the Realm-stream RealmCommit that installed it, whether this service
    /// governs the Realm or holds its verified committed replica -- or, on a
    /// member Station, by the verified bootstrap snapshot its replica is
    /// anchored on.
    async fn accepted_current_member_joined(
        &self,
        realm_id: &arkret_wire::RealmId,
        member: &arkret_wire::ActorId,
    ) -> PersistenceResult<bool>;

    /// The held stream's current hosted-member basis, read in one durable cut.
    /// None means this Station has no replica anchor for this stream; a
    /// retained anchor alone never restores live authority after departure.
    async fn replica_stream_has_hosted_member(
        &self,
        stream: &arkret_wire::CommitStreamRef,
        local_service_id: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<Option<bool>>;

    /// Refuse fresh forwarding through a held Realm's verified lifecycle cut.
    /// Exact accepted replay is resolved before this gate. Missing replicas
    /// still use the ordinary governing admission and join/bootstrap contract.
    async fn require_held_replica_write_lifecycle(
        &self,
        event: &arkret_wire::Event,
    ) -> PersistenceResult<()>;

    /// A collaboration or Direct Realm genesis backed by a held Commit or a
    /// verified replica bootstrap anchor, including below the since_join floor.
    async fn accepted_ordinary_realm(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> PersistenceResult<bool> {
        let _ = realm_id;
        Ok(false)
    }

    /// The accepted lifecycle roster of `realm_id` held here: the current
    /// `realm_authority_root` controller and every member that
    /// [`Self::accepted_current_member_joined`] would report joined. `None`
    /// when this Station holds no accepted root for the Realm.
    async fn accepted_realm_roster(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> PersistenceResult<Option<AcceptedRealmRoster>>;

    /// The Agent's joined member row and its controller's exact active join
    /// generation, both from accepted durable current state. A stale binding
    /// never becomes effective after the controller rejoins.
    async fn accepted_effective_agent_member_joined(
        &self,
        realm_id: &arkret_wire::RealmId,
        agent: &arkret_wire::ActorId,
        controller: &arkret_wire::AccountId,
    ) -> PersistenceResult<bool> {
        let _ = (realm_id, agent, controller);
        Ok(false)
    }

    /// Whether `actor` reads `realm_id` on this Station: a current joined
    /// member by [`Self::accepted_current_member_joined`], or the Account
    /// that owns it as its principal-control Realm.
    async fn accepted_realm_reader(
        &self,
        realm_id: &arkret_wire::RealmId,
        actor: &arkret_wire::ActorId,
    ) -> PersistenceResult<bool>;

    /// The Realm's current `realm_plaintext_visible_services` declaration in
    /// this Station's accepted state, backed like
    /// [`Self::accepted_current_member_joined`]: by its held Realm-stream
    /// Commit, or on a member Station by the anchored bootstrap snapshot.
    async fn accepted_plaintext_visible_services(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> PersistenceResult<
        Option<
            arkret_models_collaboration::governance::plaintext_visibility::PlaintextVisibleServicesPayload,
        >,
    >;

    async fn queue_event(&self, event: &Event, queued_at: DateTime<Utc>) -> PersistenceResult<()>;

    /// Freeze the complete original Event or MLS submission without admitting it.
    async fn retain_forwarded_submission(
        &self,
        event: &Event,
        submission: &arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest,
        at: DateTime<Utc>,
    ) -> PersistenceResult<()> {
        let _ = (event, submission, at);
        Err(crate::PersistenceError::Conflict(
            "dependency_missing: forwarded original retention is not implemented by this store"
                .to_owned(),
        ))
    }

    /// Freeze one complete peer body; concurrent or uncertain retries keep the original.
    async fn freeze_forwarded_peer_request(
        &self,
        event: &Event,
        request: &arkret_models_collaboration::authority_commit::PeerAuthoritySubmitRequest,
        at: DateTime<Utc>,
    ) -> PersistenceResult<
        Box<arkret_models_collaboration::authority_commit::PeerAuthoritySubmitRequest>,
    > {
        let _ = (event, request, at);
        Err(crate::PersistenceError::Conflict(
            "dependency_missing: frozen peer request retention is not implemented".into(),
        ))
    }

    /// CAS-retain a verified governing acknowledgement against the queued original.
    /// It is not chain continuity, disclosure, or an installed RealmCommit.
    async fn retain_forwarded_acceptance(
        &self,
        event: &Event,
        commit: &RealmCommit,
        at: DateTime<Utc>,
    ) -> PersistenceResult<()> {
        let _ = (event, commit, at);
        Err(crate::PersistenceError::Conflict(
            "dependency_missing: forwarded original retention is not implemented by this store"
                .to_owned(),
        ))
    }

    async fn record_forward_attempt(
        &self,
        event_id: &arkret_wire::EventId,
        status: ForwardAttemptStatus,
        reason_code: Option<&str>,
        attempted_at: DateTime<Utc>,
    ) -> PersistenceResult<()>;

    async fn queued_event(
        &self,
        event_id: &arkret_wire::EventId,
    ) -> PersistenceResult<Option<QueuedEventRecord>>;

    /// Freeze an ordinary MLS Event-level refusal under the same authority
    /// lock as acceptance. Existing acceptance always wins; request failures
    /// must never call this method.
    async fn finalize_mls_rejection(
        &self,
        event: &Event,
        authority: &CurrentRealmAuthority,
        reason_code: &str,
        native: Option<(ManagedMlsRefusalSource<'_>, &crate::IdempotencyRecord)>,
    ) -> PersistenceResult<arkret_wire::AuthoritySubmitOutcome> {
        let _ = (event, authority, reason_code, native);
        Err(crate::PersistenceError::Conflict(
            "temporarily_unavailable: durable MLS refusal is unavailable".into(),
        ))
    }

    /// Test fixture: atomically queue a producer Event and install its
    /// authority Commit with no domain admission. Production admits every
    /// Event through its registered unit, never through this kind-agnostic
    /// path; the Account Authority private route accepts only the
    /// `accepted_device` unit.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    async fn admit_event_transaction(
        &self,
        transaction: &AuthorityCommitTransaction,
        queued_at: DateTime<Utc>,
    ) -> PersistenceResult<AuthorityCommitWriteOutcome>;

    /// Test fixture: [`Self::admit_event_transaction`] that also rechecks the
    /// producer's current authorization in the same database transaction.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    async fn admit_self_event_transaction(
        &self,
        transaction: &AuthorityCommitTransaction,
        guard: &SelfProducerCommitGuard,
        queued_at: DateTime<Utc>,
    ) -> PersistenceResult<AuthorityCommitWriteOutcome>;

    /// Read an exact durable outcome before resolving live producer or approval
    /// history again. Reuse of either unit identity with other bytes conflicts.
    async fn ordinary_realm_bootstrap_replay(
        &self,
        submission: &arkret_models_collaboration::authority_commit::OrdinaryRealmBootstrapUnitSubmission,
        exact_request_body: &[u8],
    ) -> PersistenceResult<Option<Vec<arkret_wire::RealmCommit>>>;

    async fn watch_audit_read_delivery_guard(
        &self,
        _request: &arkret_models_collaboration::strand_watch_operations::WatchAuditReadRequest,
        _outcome: &arkret_models_collaboration::strand_watch_operations::WatchAuditReadOutcome,
        _issuer: &arkret_wire::DidCoreId,
        _expires_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<Box<dyn AccountContentDeliveryGuard>> {
        Err(PersistenceError::Conflict(
            "revision_unavailable: governing audit delivery unavailable".to_owned(),
        ))
    }

    async fn watch_audit_read_disclosure(
        &self,
        _request: &arkret_models_collaboration::strand_watch_operations::WatchAuditReadRequest,
        _outcome: &arkret_models_collaboration::strand_watch_operations::WatchAuditReadOutcome,
        _issuer: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<()> {
        Err(PersistenceError::Conflict(
            "revision_unavailable: audit disclosure unavailable".to_owned(),
        ))
    }

    /// Freeze the complete origin unit before I/O; retain only a verified
    /// original acknowledgement, never an independently accepted slot.
    async fn retain_registered_pair_forward(
        &self,
        _request: &arkret_models_collaboration::authority_commit::AuditPairedEventUnitSubmission,
        _outcome: Option<
            &arkret_models_collaboration::authority_commit::AuditPairedEventAcceptanceOutcome,
        >,
    ) -> PersistenceResult<()> {
        Err(PersistenceError::Conflict(
            "revision_unavailable: registered forward archive unavailable".into(),
        ))
    }

    async fn registered_audit_result(
        &self,
        _event_id: &arkret_wire::EventId,
    ) -> PersistenceResult<Option<crate::RegisteredAuditResult>> {
        Err(PersistenceError::Conflict(
            "unsupported_feature: registered audit archive unavailable".to_owned(),
        ))
    }

    /// Install the entire registered ordinary Realm bootstrap in one DB
    /// transaction, including genesis authority, every Event/Commit and all
    /// current projections. Failed units leave no queued or committed Event.
    async fn admit_ordinary_realm_bootstrap_unit(
        &self,
        unit: &OrdinaryRealmBootstrapCommitUnit,
        queued_at: DateTime<Utc>,
    ) -> PersistenceResult<OrdinaryRealmBootstrapCommitOutcome>;

    /// Self bootstrap admission rechecks every exact producer binding in the
    /// same transaction as the Realm authority, Events and Commits.
    async fn admit_self_ordinary_realm_bootstrap_unit(
        &self,
        unit: &OrdinaryRealmBootstrapCommitUnit,
        producer_guards: &[SelfProducerCommitGuard],
        queued_at: DateTime<Utc>,
    ) -> PersistenceResult<OrdinaryRealmBootstrapCommitOutcome>;

    /// Admit the caller-authored Direct Conversation founding unit in one
    /// transaction (contact-and-direct-conversation.md sections 5.5 and 6.1):
    /// an exact retry of the same idempotency key and unit returns the stored
    /// Commits first; otherwise the founder's unique slot is claimed, the
    /// founding authority is read from this Station's current state, and the
    /// four Events, their consecutive Commits and current results are written.
    /// Every refusal writes nothing.
    async fn admit_self_direct_conversation_founding_unit(
        &self,
        unit: &DirectConversationFoundingCommitUnit,
        producer_guards: &[SelfProducerCommitGuard; 4],
        queued_at: DateTime<Utc>,
    ) -> PersistenceResult<DirectConversationFoundingCommitOutcome>;

    /// Materialize a verified, source-committed founding unit atomically on
    /// the peer Station, without another admission or Commit signature.
    async fn materialize_peer_direct_conversation_founding_unit(
        &self,
        unit: &DirectConversationFoundingCommitUnit,
        evidence: &arkret_models_collaboration::objects::direct_conversation::DirectConversationFoundingAuthorityEvidence,
        local_station: &arkret_wire::DidCoreId,
        received_at: DateTime<Utc>,
    ) -> PersistenceResult<arkret_models_collaboration::authority_commit::AggregateAcceptanceStatus>;

    /// Evaluate the Direct Conversation admission table
    /// (contact-and-direct-conversation.md section 8.4) for `event` at one
    /// read-only cut of its Realm. The accepting transaction evaluates the
    /// same table again at its own cut; this read lets a caller refuse an
    /// Event it has no admission unit for, and skip reducer preflight for a
    /// Direct Conversation Realm, whose table precedes every other authority.
    async fn direct_conversation_admission(
        &self,
        event: &Event,
    ) -> PersistenceResult<DirectConversationAdmissionCut>;

    /// Find the first exact-pair Add's pending remote claim, if its durable
    /// consume receipt has not yet been observed on the governing Station.
    async fn direct_conversation_pending_peer_claim_query(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> PersistenceResult<Option<DirectConversationPendingPeerClaimQuery>>;

    /// Install the complete PCR genesis, founding device current, and exact
    /// idempotency receipt in one durable transaction.
    async fn admit_pcr_genesis_unit(
        &self,
        unit: &PcrGenesisCommitUnit,
        queued_at: DateTime<Utc>,
    ) -> PersistenceResult<PcrGenesisCommitOutcome>;

    /// Admit one `accepted_device` `ak.device.authorize` relayed by the
    /// Account Authority (device-lifecycle.md §5.4, §5.5.2). At the locked PCR
    /// cut the approving device must be active in the current generation, the
    /// payload must name that generation, the target device must have no
    /// authorization history, and the target possession signature and the
    /// approver's producer proof must verify. The Event, Commit, typed device
    /// authorization and device mirror are written in one transaction; any
    /// refusal writes nothing.
    async fn admit_accepted_device_authorization(
        &self,
        transaction: &AuthorityCommitTransaction,
        queued_at: DateTime<Utc>,
    ) -> PersistenceResult<AcceptedDeviceAuthorizationOutcome>;

    /// One ordinary managed PCR successor, relayed by its exact Service.
    /// Rechecks accepted provenance, resolution, generation, scope installs,
    /// possession and producer proof under the PCR and installation locks.
    async fn applet_realm_actor_creations(
        &self,
        realm: &arkret_wire::RealmId,
        applet: &arkret_wire::AppletId,
    ) -> PersistenceResult<Vec<arkret_wire::CommittedEventFullView>> {
        let _ = (realm, applet);
        Err(PersistenceError::Conflict(
            "dependency_missing: Realm actor creation inventory unavailable".into(),
        ))
    }
    async fn realm_actor_creation_replay(
        &self,
        event: &arkret_wire::Event,
        digest: &arkret_wire::Hash,
        governor: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<Option<arkret_wire::RealmCommit>> {
        let _ = (event, digest, governor);
        Err(PersistenceError::Conflict(
            "dependency_missing: creation replay unavailable".into(),
        ))
    }
    async fn admit_realm_actor_creation(
        &self,
        transaction: &AuthorityCommitTransaction,
        producer: &crate::AppletEventProducerGuard,
        prepared: Option<&crate::EventApprovalCommit>,
        digest: &arkret_wire::Hash,
    ) -> PersistenceResult<arkret_wire::AuthoritySubmitOutcome> {
        let _ = (transaction, producer, prepared, digest);
        Err(PersistenceError::Conflict(
            "dependency_missing: creation unit unavailable".into(),
        ))
    }

    async fn realm_actor_recovery_replay(
        &self,
        event: &arkret_wire::Event,
        digest: &arkret_wire::Hash,
        governor: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<Option<arkret_wire::RealmCommit>> {
        let _ = (event, digest, governor);
        Err(PersistenceError::Conflict(
            "dependency_missing: recovery replay unavailable".into(),
        ))
    }
    async fn admit_realm_actor_recovery(
        &self,
        transaction: &AuthorityCommitTransaction,
        producer: &crate::AppletEventProducerGuard,
        publication: Option<&arkret_models_identity::ResolutionCommitment>,
        digest: &arkret_wire::Hash,
    ) -> PersistenceResult<arkret_wire::AuthoritySubmitOutcome> {
        let _ = (transaction, producer, publication, digest);
        Err(PersistenceError::Conflict(
            "dependency_missing: recovery unit unavailable".into(),
        ))
    }

    async fn admit_realm_actor_owner_control(
        &self,
        transaction: &AuthorityCommitTransaction,
        carrier: &AppletControlCarrier,
        publication: Option<&arkret_models_identity::ResolutionCommitment>,
        manager: Option<&crate::AppletEventProducerGuard>,
        prepared: Option<&crate::EventApprovalCommit>,
        digest: &arkret_wire::Hash,
    ) -> PersistenceResult<arkret_wire::AuthoritySubmitOutcome> {
        let _ = (transaction, carrier, publication, manager, prepared, digest);
        Err(PersistenceError::Conflict(
            "dependency_missing: owner control admission unavailable".into(),
        ))
    }

    async fn sweep_realm_actor_device_revocations(
        &self,
        governor: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<usize> {
        let _ = governor;
        Err(PersistenceError::Conflict(
            "dependency_missing: Realm revoke worker unavailable".into(),
        ))
    }

    async fn finish_realm_actor_device_revocation(
        &self,
        actor: &arkret_wire::ActorId,
        authority: &CurrentRealmAuthority,
        terminal: &arkret_models_integration::RealmActorOperationOutcome,
    ) -> PersistenceResult<()> {
        let _ = (actor, authority, terminal);
        Err(PersistenceError::Conflict(
            "dependency_missing: Realm revoke terminal unavailable".into(),
        ))
    }

    async fn admit_realm_actor_profile(
        &self,
        transaction: &AuthorityCommitTransaction,
        carrier: &AppletControlCarrier,
        prepared: Option<&crate::EventApprovalCommit>,
        request_digest: &arkret_wire::Hash,
    ) -> PersistenceResult<arkret_wire::AuthoritySubmitOutcome> {
        let _ = (transaction, carrier, prepared, request_digest);
        Err(PersistenceError::Conflict(
            "dependency_missing: Realm Profile control admission unavailable".into(),
        ))
    }

    async fn admit_applet_managed_device_authorization(
        &self,
        transaction: &AuthorityCommitTransaction,
        carrier: &AppletControlCarrier,
        request_digest: &arkret_wire::Hash,
    ) -> PersistenceResult<AcceptedDeviceAuthorizationOutcome> {
        let _ = (transaction, carrier, request_digest);
        Err(PersistenceError::Conflict(
            "temporarily_unavailable: managed device admission unavailable".into(),
        ))
    }

    /// Read the first durable PCR genesis receipt before freshness checks on an
    /// exact retry. Reusing either the Realm or idempotency key with different
    /// request bytes is a conflict, never a duplicate acceptance.
    async fn pcr_genesis_replay(
        &self,
        submission: &arkret_models_collaboration::principal_operations::PcrGenesisAdmissionInput,
        exact_request_body: &[u8],
    ) -> PersistenceResult<
        Option<arkret_models_collaboration::principal_operations::PcrGenesisAdmissionOutcome>,
    >;

    /// Atomically checks current authority, appends the per-stream commit,
    /// changes the Event from queued to committed, and enqueues every Welcome.
    async fn commit_transaction(
        &self,
        transaction: &AuthorityCommitTransaction,
    ) -> PersistenceResult<AuthorityCommitWriteOutcome>;

    async fn stream_head(
        &self,
        stream_ref: &CommitStreamRef,
    ) -> PersistenceResult<Option<CommitStreamHead>>;

    /// Resolve the unique successful RealmCommit for one Event id.
    ///
    /// A missing row returns `None`; storage uniqueness guarantees that this
    /// method never chooses between two successful commits for the same Event.
    async fn committed_event(
        &self,
        event_id: &arkret_wire::EventId,
    ) -> PersistenceResult<Option<CommittedEventRecord>>;

    async fn committed_event_by_commit_id(
        &self,
        commit_id: &arkret_wire::RealmCommitId,
    ) -> PersistenceResult<Option<CommittedEventRecord>>;

    async fn current_mimi_room_binding(
        &self,
        room_uri: &arkret_wire::MimiRoomUri,
    ) -> PersistenceResult<Option<MimiRoomBindingCurrentRecord>>;

    /// Resolve an agreed owner Direct binding independently of group mode.
    async fn agent_owner_direct_scope(
        &self,
        _realm: &arkret_wire::RealmId,
        _agent: &arkret_wire::AccountId,
        _controller: &arkret_wire::AccountId,
    ) -> PersistenceResult<bool> {
        Ok(false)
    }

    /// Read one accepted Agent typed current row at its durable revision.
    /// Only the closed AgentKey, AgentStatus and AgentInteraction selectors are admitted.
    async fn current_agent_result(
        &self,
        realm_id: &arkret_wire::RealmId,
        selector: &arkret_wire::CurrentSelector,
    ) -> PersistenceResult<Option<arkret_wire::TypedCurrentRow>>;

    /// Restore the default pointer from its accepted Commit or verified
    /// replica cut, without reading unrelated current families.
    async fn realm_default_strand_current(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> PersistenceResult<Option<arkret_wire::TypedCurrentRow>>;

    /// Governance generation and current heads for every independent Realm,
    /// Circle, and Sidecar stream at one durable cut, sorted by `stream_ref`.
    async fn realm_stream_heads(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> PersistenceResult<Option<crate::RealmStreamCut>>;

    /// Freeze one controller-owned context's exact current for a signed attach draft.
    async fn sidecar_context_prepare_current(
        &self,
        _realm: &arkret_wire::RealmId,
        _controller: &arkret_wire::AccountId,
        _context: &arkret_models_collaboration::sidecar_operations::SidecarContextRef,
    ) -> PersistenceResult<
        Option<(
            arkret_wire::EventId,
            Option<crate::AgentSidecarContextRecord>,
        )>,
    > {
        Err(crate::PersistenceError::Internal(
            "authoritative Sidecar context cut is unavailable".into(),
        ))
    }

    /// Derive native Sidecar participants from one accepted durable cut.
    async fn sidecar_participant_authority_cut(
        &self,
        _realm_id: &arkret_wire::RealmId,
        _sidecar_id: &arkret_wire::SidecarId,
        _controller: &arkret_wire::AccountId,
    ) -> PersistenceResult<
        Option<arkret_models_collaboration::agent_sidecar::SidecarParticipantAuthorityCut>,
    > {
        Err(crate::PersistenceError::Internal(
            "durable Sidecar participant authority cut is unavailable".to_owned(),
        ))
    }

    /// Read the maximal-disclosure snapshot material from one consistent
    async fn sidecar_access_cut(
        &self,
        _realm: &arkret_wire::RealmId,
        _sidecar: &arkret_wire::SidecarId,
        _controller: &arkret_wire::AccountId,
        _device: &arkret_wire::DeviceId,
    ) -> PersistenceResult<
        Option<(
            arkret_models_collaboration::agent_sidecar::SidecarParticipantAuthorityCut,
            Vec<arkret_wire::DidCoreId>,
            Option<arkret_wire::MlsGroupCurrent>,
            bool,
        )>,
    > {
        Err(crate::PersistenceError::Internal(
            "Sidecar effective authority cut is unavailable".into(),
        ))
    }

    async fn realm_lifecycle_for_actor(
        &self,
        realm: &arkret_wire::RealmId,
        actor: &arkret_wire::ActorId,
    ) -> PersistenceResult<
        Option<arkret_models_collaboration::governance::realm_governance::RealmLifecycleView>,
    > {
        let _ = (realm, actor);
        Err(crate::PersistenceError::Internal(
            "Realm lifecycle read is unavailable".into(),
        ))
    }

    async fn accepted_realm_links(
        &self,
        realm: &arkret_wire::RealmId,
        actor: &arkret_wire::ActorId,
        station: &arkret_wire::DidCoreId,
        direction: arkret_models_collaboration::governance::realm_governance::RealmLinkDirection,
        allow: Option<&[String]>,
    ) -> PersistenceResult<
        Option<arkret_models_collaboration::governance::realm_governance::RealmLinkList>,
    > {
        let _ = (realm, actor, station, direction, allow);
        Err(crate::PersistenceError::Internal(
            "accepted Realm link read is unavailable".into(),
        ))
    }

    async fn accepted_realm_organization_read(
        &self, realm: &arkret_wire::RealmId, caller: &arkret_wire::ActorId,
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<Option<arkret_models_collaboration::governance::realm_governance::RealmOrganizationRelationshipList>>{
        let _ = (realm, caller, at);
        Err(crate::PersistenceError::Internal(
            "accepted Realm organization read is unavailable".into(),
        ))
    }

    async fn realm_state_snapshot_material(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> PersistenceResult<Option<RealmStateSnapshotMaterial>>;

    /// Return snapshot material only when this exact Account's complete
    /// disclosure can be proved at one durable cut. Unsupported Realm shapes
    /// remain unavailable to the public snapshot endpoint.
    async fn realm_state_snapshot_material_for_account(
        &self,
        realm_id: &arkret_wire::RealmId,
        account: &arkret_wire::AccountId,
    ) -> PersistenceResult<Option<RealmStateSnapshotMaterial>>;

    /// Check an already validated Account cursor's selected minimum heads
    /// against current disclosure and held identities in one read-only cut.
    /// False is unavailable evidence, not proof of recoverable lag. Changed
    /// disclosure and retained-floor recovery remain the ordinary read's job.
    async fn account_continuation_heads_covered(
        &self,
        _realm_id: &arkret_wire::RealmId,
        _account: &arkret_wire::AccountId,
        _minimum_heads: &[CommitStreamHead],
    ) -> PersistenceResult<bool> {
        Err(crate::PersistenceError::Internal(
            "Account continuation head evidence is unavailable".into(),
        ))
    }

    /// Read only the exact binding, Realm MLS group, two participant rows
    /// and at most one additional joined member from a verified held cut.
    /// The Account's existing readable interval must be proved at that cut.
    async fn direct_conversation_replica_cut(
        &self,
        _realm_id: &arkret_wire::RealmId,
        _account: &arkret_wire::AccountId,
        _pair_key: &arkret_wire::Hash,
        _participants: &[arkret_wire::ActorId; 2],
    ) -> PersistenceResult<Option<DirectConversationReplicaCut>> {
        Err(crate::PersistenceError::Internal(
            "bounded Direct replica evidence is unavailable".into(),
        ))
    }

    /// Canonical object list DTOs derived from durable current at one caller
    /// membership/scope cut. This is an internal read API, not new wire state.
    async fn object_projection_lists_for_actor(
        &self,
        _realm_id: &arkret_wire::RealmId,
        _actor: &arkret_wire::ActorId,
        _include_terminal: bool,
    ) -> PersistenceResult<
        Option<(
            arkret_models_collaboration::objects::query_projection::ProjectionSpaceList,
            arkret_models_collaboration::objects::query_projection::ProjectionStrandList,
        )>,
    > {
        Err(crate::PersistenceError::Internal(
            "durable object projection read is unavailable".to_owned(),
        ))
    }

    /// Original SDK projection lists and their exact accepted-current
    /// structural dependencies, read together at one held database cut.
    /// Missing provenance fails closed; this is not an independent wire DTO.
    async fn object_projection_delivery_for_actor(
        &self,
        realm_id: &arkret_wire::RealmId,
        actor: &arkret_wire::ActorId,
        include_terminal: bool,
    ) -> PersistenceResult<
        Option<(
            arkret_models_collaboration::objects::query_projection::ProjectionSpaceList,
            arkret_models_collaboration::objects::query_projection::ProjectionStrandList,
            arkret_models_collaboration::sync_frames::current_results::AccountCurrentView,
        )>,
    > {
        let _ = (realm_id, actor, include_terminal);
        Err(crate::PersistenceError::Internal(
            "accepted object projection delivery read is unavailable".into(),
        ))
    }

    /// Native current Morph values rebuilt from complete accepted source chains.
    async fn morph_list_for_actor(
        &self,
        _realm: &arkret_wire::RealmId,
        _actor: &arkret_wire::ActorId,
        _station: &arkret_wire::DidCoreId,
        _include_terminal: bool,
    ) -> PersistenceResult<
        Option<arkret_models_collaboration::objects::query_projection::ProjectionMorphList>,
    > {
        Err(crate::PersistenceError::Internal(
            "native Morph list is unavailable".into(),
        ))
    }

    async fn document_morph_for_actor(
        &self,
        _realm: &arkret_wire::RealmId,
        _morph: &arkret_wire::MorphId,
        _actor: &arkret_wire::ActorId,
        _station: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<
        Option<
            arkret_models_collaboration::objects::query_projection::DocumentMorphProjectionOutcome,
        >,
    > {
        Err(crate::PersistenceError::Internal(
            "native document Morph is unavailable".into(),
        ))
    }

    /// A complete caller-visible export and its original accepted sources at
    /// one durable cut. Stored operation handles are metadata, not authority.
    async fn realm_export_for_actor(
        &self,
        _realm_id: &arkret_wire::RealmId,
        _actor: &arkret_wire::ActorId,
        _station: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<
        Option<(
            arkret_models_collaboration::governance::realm_governance::RealmExport,
            Vec<arkret_wire::CommittedEventView>,
        )>,
    > {
        Err(crate::PersistenceError::Internal(
            "accepted Realm export is unavailable".into(),
        ))
    }

    /// The effective scope of a non-terminal Strand `actor` currently reads
    /// from durable current rows (governed here or held as a verified
    /// replica); `None` for every hidden, missing or terminal target.
    async fn visible_strand_scope_for_actor(
        &self,
        realm_id: &arkret_wire::RealmId,
        strand_id: &arkret_wire::StrandId,
        actor: &arkret_wire::ActorId,
    ) -> PersistenceResult<Option<arkret_wire::ScopeRef>>;

    /// The bootstrap snapshot material a member Station anchors on
    /// (`federation.md` §4.1.1): `account`'s complete disclosure with the
    /// Realm stream floor at its join `membership_commit_id`, except an exact
    /// registered founding unit retains position zero, or `None`
    /// unless that Commit is still its current joined membership.
    async fn member_station_bootstrap_material(
        &self,
        realm_id: &arkret_wire::RealmId,
        account: &arkret_wire::AccountId,
        membership_commit_id: &arkret_wire::RealmCommitId,
    ) -> PersistenceResult<Option<RealmStateSnapshotMaterial>>;

    /// Prove the bootstrap floor of this exact current opening join from held
    /// registered atomic-unit originals. Missing store support is unavailable,
    /// never permission to accept a smaller floor.
    async fn member_station_bootstrap_floor(
        &self,
        realm_id: &arkret_wire::RealmId,
        account: &arkret_wire::AccountId,
        membership_commit_id: &arkret_wire::RealmCommitId,
    ) -> PersistenceResult<Option<u64>> {
        let _ = (realm_id, account, membership_commit_id);
        Ok(None)
    }

    /// Issue one complete signed Snapshot to `account` from a single durable
    /// cut: the governing tenure of `issuer` is locked and checked, the
    /// complete Account disclosure is proved, `sign` signs exactly that
    /// material, the canonical signed body is held to the 8 MiB inline limit,
    /// and the original object plus its Account issuance are persisted before
    /// the cut commits. Any failure leaves no issued object.
    async fn issue_realm_state_snapshot_for_account(
        &self,
        realm_id: &arkret_wire::RealmId,
        account: &arkret_wire::AccountId,
        issuer: &arkret_wire::DidCoreId,
        sign: RealmStateSnapshotSigner<'_>,
    ) -> PersistenceResult<Option<RealmStateSnapshot>>;

    /// Issue the complete material visible in one accepted native Device
    /// scope, proving its current read ceiling before signing or storing it.
    async fn issue_realm_state_snapshot_for_applet_device(
        &self,
        endpoint: &crate::AppletManagedDeviceScopeGuard,
        issuer: &arkret_wire::DidCoreId,
        credential_expires_at: chrono::DateTime<chrono::Utc>,
        sign: RealmStateSnapshotSigner<'_>,
    ) -> PersistenceResult<Option<RealmStateSnapshot>> {
        let _ = (endpoint, issuer, credential_expires_at, sign);
        Err(crate::PersistenceError::Internal(
            "native scoped Snapshot issuance is unavailable".to_owned(),
        ))
    }

    /// Archive an original governing Snapshot whose authority and signature
    /// the receiving layer verified. The store independently proves its exact
    /// Account disclosure against the member Station's durable replica cut.
    /// Return the actual archived original, including same-cut reuse, so the
    /// receiving layer can verify and emit only a retained exact reference.
    async fn install_verified_account_snapshot(
        &self,
        account: &arkret_wire::AccountId,
        issuer: &arkret_wire::DidCoreId,
        snapshot: &RealmStateSnapshot,
        minimum: &RealmStateSnapshotMaterial,
    ) -> PersistenceResult<RealmStateSnapshot> {
        let _ = (account, issuer, snapshot, minimum);
        Err(crate::PersistenceError::Internal(
            "verified Account Snapshot installation is unavailable".to_owned(),
        ))
    }

    /// Read the original signed Snapshot previously issued to this exact
    /// Account and recheck, at one read cut, that every disclosed row, head,
    /// and floor is still disclosable to it. `None` means the exact object
    /// was never issued to this Account for this Realm.
    async fn issued_realm_state_snapshot_for_actor(
        &self,
        _realm_id: &arkret_wire::RealmId,
        _actor: &arkret_wire::ActorId,
        _snapshot_id: &arkret_wire::RealmSnapshotId,
        _issuer: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<Option<RealmStateSnapshot>> {
        Err(PersistenceError::Internal(
            "Actor read port is not configured".into(),
        ))
    }

    async fn issued_realm_state_snapshot(
        &self,
        realm_id: &arkret_wire::RealmId,
        account: &arkret_wire::AccountId,
        snapshot_id: &arkret_wire::RealmSnapshotId,
        issuer: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<Option<RealmStateSnapshot>>;

    /// Freeze one Account window over the Realm stream at a single durable
    /// cut that share-locks the governing tenure of `issuer` and re-proves the
    /// Account's complete disclosure. A limited window carries a
    /// `window_start_basis` only when an exact snapshot issued to the Account
    /// matches its anchor and can be reserved for the window's consumable
    /// period; otherwise the stream is `preview_only`. The frozen head is
    /// issued to the Account in the same cut, signed by `sign`, so the next
    /// live delta after it names that exact snapshot as its basis. `None`
    /// means the Realm has no governed material.
    async fn freeze_account_realm_window(
        &self,
        request: &AccountRealmWindowRequest,
        sign: RealmStateSnapshotSigner<'_>,
    ) -> PersistenceResult<Option<AccountRealmWindow>>;

    /// Re-read a frozen window's reserved basis. `None` means the guarantee
    /// is lost (never reserved, expired, reclaimed, or no longer disclosable)
    /// and any re-emission of that stream window must be `preview_only`.
    async fn account_window_basis(
        &self,
        realm_id: &arkret_wire::RealmId,
        account: &arkret_wire::AccountId,
        window_cursor: &str,
        stream_ref: &CommitStreamRef,
        issuer: &arkret_wire::DidCoreId,
        now_ms: i64,
    ) -> PersistenceResult<
        Option<arkret_models_collaboration::sync_frames::account_sync::StreamWindowStartBasis>,
    >;

    /// Keyset page over one independent commit stream.
    ///
    /// The only paging key is `realm_commits.stream_position` inside the
    /// single `CommitStreamRef` named by the request: rows start at genesis
    /// position 0 when `after_position` is `None` and otherwise at
    /// `after_position + 1`, run consecutively, and stop after `limit` rows.
    /// No opaque page token, no reverse direction, and no separate
    /// `has_more`: `StreamScanOutcome::truncated` carries that alone.
    async fn scan_stream(
        &self,
        request: &arkret_wire::StreamScanRequest,
    ) -> PersistenceResult<arkret_wire::StreamScanOutcome>;

    /// `ak.self.committed_event.read.scan.v1` for one authenticated Account.
    ///
    /// Authorization, the readable interval, and the returned page come from
    /// one read cut at which `issuer` holds the Realm's governing tenure.
    /// Only intervals this Station can prove are served; every other shape
    /// fails closed as [`AccountStreamScan::Unproved`], never as a physical
    /// page that could disclose rows outside the caller's permission.
    async fn scan_stream_for_actor(
        &self,
        _request: &arkret_wire::StreamScanRequest,
        _actor: &arkret_wire::ActorId,
        _issuer: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<AccountStreamScan> {
        Err(PersistenceError::Internal(
            "Actor scan port is not configured".into(),
        ))
    }

    async fn scan_stream_for_account(
        &self,
        request: &arkret_wire::StreamScanRequest,
        account: &arkret_wire::AccountId,
        issuer: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<AccountStreamScan>;

    /// `ak.peer.committed_event.read.scan.v1` for one authenticated peer
    /// Station (`service-http-binding.md` §3.1.3: the calling Station must
    /// hold the replication right for the exact stream).
    ///
    /// A peer with no currently joined member routed to it has no right on
    /// any stream of the Realm. Every other shape is decided at the same
    /// governing read cut and fails closed as [`AccountStreamScan::Unproved`]
    /// until this Station can prove the peer's exact interval and disclosure.
    async fn scan_stream_for_peer(
        &self,
        request: &arkret_wire::StreamScanRequest,
        peer: &arkret_wire::DidCoreId,
        issuer: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<PeerStreamScan>;

    /// The committed Event `event_id` with its RealmCommit when `peer` may
    /// read it at one governing read cut of `issuer`: its Realm-stream
    /// position lies in one of the peer's replication intervals and the peer
    /// may hold its complete canonical bytes -- the rule a peer stream scan
    /// applies (`federation.md` §4.1.1). `None` for every other case.
    async fn committed_event_for_peer(
        &self,
        event_id: &arkret_wire::EventId,
        peer: &arkret_wire::DidCoreId,
        issuer: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<Option<arkret_wire::CommittedEventFullView>>;

    /// `ak.self.committed_event.resource.get.v1` for `caller` on an ordinary
    /// Realm's Realm stream, at one read cut of this Station -- governing, or
    /// holding the stream as an anchored replica. The caller's own Event is
    /// read in full; another actor's Event only by a current joined member
    /// whose readable floor (`history-visibility.md` §3.1) covers its
    /// position, and the genesis by every current member. Each is disclosed
    /// by the member committed-event decision; a held chain node is the
    /// withheld branch.
    async fn committed_event_for_member(
        &self,
        event_id: &arkret_wire::EventId,
        caller: &arkret_wire::ActorId,
        issuer: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<MemberCommittedEventRead>;

    /// `ak.self.realm.read.streams.v1` for one authenticated Account. The
    /// stream set, each head and each readable floor come from one read cut at
    /// which `issuer` holds the Realm's governing tenure; a set or floor this
    /// Station cannot prove fails closed instead of omitting a stream.
    async fn list_realm_streams_for_account(
        &self,
        realm_id: &arkret_wire::RealmId,
        account: &arkret_wire::AccountId,
        issuer: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<AccountRealmStreamList>;

    async fn realm_stream_subscription_cut(
        &self,
        _realm_id: &arkret_wire::RealmId,
        _account: &arkret_wire::AccountId,
        _issuer: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<AccountRealmStreamAuthorizationCut> {
        Ok(AccountRealmStreamAuthorizationCut {
            listing: AccountRealmStreamList::Unproved(
                "subscription history policy cut is unavailable",
            ),
            history_digest: None,
        })
    }

    /// `ak.self.current_results.read.exact.v1` for one authenticated Account:
    /// membership, governance generation, effective stream head and the
    /// selector's durable current row from one read cut.
    async fn exact_current_result_for_actor(
        &self,
        _request: &arkret_models_collaboration::exact_current_results::ExactCurrentResultsReadRequestBody,
        _actor: &arkret_wire::ActorId,
        _issuer: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<
        SelfExactCurrentRead<
            arkret_models_collaboration::exact_current_results::ExactCurrentResultsReadOutcome,
        >,
    > {
        Err(PersistenceError::Internal(
            "Actor read port is not configured".into(),
        ))
    }

    async fn exact_current_result_for_account(
        &self,
        request: &arkret_models_collaboration::exact_current_results::ExactCurrentResultsReadRequestBody,
        account: &arkret_wire::AccountId,
        issuer: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<
        SelfExactCurrentRead<
            arkret_models_collaboration::exact_current_results::ExactCurrentResultsReadOutcome,
        >,
    >;

    /// `ak.self.strand.watch.read.current.v1` for the authenticated Account,
    /// which is also the request's watcher.
    async fn strand_watch_current_for_account(
        &self,
        request: &arkret_models_collaboration::strand_watch_operations::StrandWatchCurrentRequestBody,
        account: &arkret_wire::AccountId,
        issuer: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<
        SelfExactCurrentRead<
            arkret_models_collaboration::strand_watch_operations::StrandWatchCurrentOutcome,
        >,
    >;

    /// Membership visibility and the accepted media service anchor of one
    /// Realm for `ak.self.media_service_binding.read.resolve.v1`.
    async fn media_service_anchor_for_account(
        &self,
        realm_id: &arkret_wire::RealmId,
        account: &arkret_wire::AccountId,
        issuer: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<MediaServiceAnchorRead>;

    /// Native PCR planned change: original device/root verification and freeze
    /// preparation belong to one authority transaction, without ordinary facts.
    async fn admit_pcr_governance_change(
        &self,
        _transaction: &AuthorityCommitTransaction,
    ) -> PersistenceResult<AuthorityCommitWriteOutcome> {
        Err(PersistenceError::Conflict(
            "temporarily_unavailable: native PCR planned change is unavailable".into(),
        ))
    }

    async fn install_handoff_with_private_state(
        &self,
        handoff: &RealmAuthorityHandoff,
        final_stream_heads: &[CommitStreamHead],
        snapshot: &RealmStateSnapshot,
        manifest: Option<&arkret_models_collaboration::authority_commit::PcrPrivateHandoffManifest>,
        management: &arkret_models_collaboration::authority_commit::ManagementPrivateHandoffManifest,
    ) -> PersistenceResult<()> {
        let _ = (handoff, final_stream_heads, snapshot, manifest, management);
        Err(PersistenceError::Conflict(
            "temporarily_unavailable: durable private import verification is unavailable".into(),
        ))
    }

    async fn install_handoff(
        &self,
        handoff: &RealmAuthorityHandoff,
        final_stream_heads: &[CommitStreamHead],
        snapshot: &RealmStateSnapshot,
    ) -> PersistenceResult<()>;

    /// Full originals at the outgoing frozen cut, including private streams.
    /// This is an internal migration verification read, never a member scan.
    async fn handoff_originals(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> PersistenceResult<Vec<arkret_wire::CommittedEventFullView>>;

    /// Returns the consecutive, durable handoff chain used to verify the
    /// current Station from the Realm's genesis authority.
    async fn authority_handoffs(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> PersistenceResult<Vec<RealmAuthorityHandoff>>;

    /// Latest handoff-installed snapshot. Account-issued `/head` objects are
    /// caller-scoped disclosures and never serve as this Realm-wide anchor.
    async fn latest_snapshot(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> PersistenceResult<Option<RealmStateSnapshot>>;
}

#[cfg(test)]
mod mls_installation_tests {
    use arkret_models_crypto::{MlsCommitEnvelope, MlsCommitPayload, MlsGovernanceBindingPayload};
    use arkret_wire::{EventId, Hash, RealmId, ScopeRef};

    use super::{MlsInstalledBase, MlsPublicBlob, MlsStateInstallation, validate_mls_installation};

    fn commit_event(scope: &ScopeRef, payload: &MlsCommitPayload) -> arkret_wire::Event {
        arkret_wire::test_support::raw_event_for_actor_at(
            "ak.mls.commit",
            scope.clone(),
            arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                arkret_wire::DidCoreId::new("ak:did_core:web:mls-committer.example").unwrap(),
                arkret_wire::DidCoreId::new("ak:did_core:web:mls-station.example").unwrap(),
            )),
            serde_json::to_value(payload).unwrap(),
            chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn installed_state_must_match_signed_mls_binding() {
        let realm_id =
            RealmId::new("ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-").unwrap();
        let base =
            EventId::from_event_digest(&Hash::new(arkret_canonical::sha256_digest([1])).unwrap())
                .unwrap();
        let binding =
            MlsGovernanceBindingPayload::realm(realm_id.clone(), Some(base.clone()), 0, 1, 7)
                .unwrap();
        let commit_bytes = b"canonical-commit";
        let envelope = MlsCommitEnvelope {
            group_id: binding.mls_group_id().unwrap(),
            epoch: 1,
            commit: arkret_wire::base64url::base64url_encode(commit_bytes),
            commit_digest: Hash::new(arkret_canonical::sha256_digest(commit_bytes)).unwrap(),
            ratchet_tree: None,
        };
        let payload = MlsCommitPayload::new(base.clone(), 7, &envelope, binding).unwrap();
        let scope = ScopeRef::Realm { realm_id };
        let event = commit_event(&scope, &payload);
        let installed = MlsStateInstallation {
            effective_scope: scope.clone(),
            base: Some(MlsInstalledBase {
                current_mls_commit_event_ref: base,
                epoch: 0,
            }),
            epoch: 1,
            public_state: vec![1],
            member_principals: Default::default(),
            consumed_proposals: Vec::new(),
            public_blobs: vec![MlsPublicBlob {
                blob_ref: arkret_wire::BlobRef::new(format!("ak:blob:sha256:{}", "5".repeat(64)))
                    .unwrap(),
                sha256: "5".repeat(64),
                size_bytes: 11,
                storage_backend: "local".to_owned(),
                storage_key: format!("sha256/{}", "5".repeat(64)),
            }],
        };
        assert!(validate_mls_installation(&event, &installed).is_ok());

        let mut no_tree = installed.clone();
        no_tree.public_blobs.clear();
        assert!(validate_mls_installation(&event, &no_tree).is_err());
        let mut extra_tree = installed.clone();
        extra_tree
            .public_blobs
            .push(installed.public_blobs[0].clone());
        assert!(validate_mls_installation(&event, &extra_tree).is_err());

        let mut wrong_base = installed.clone();
        wrong_base
            .base
            .as_mut()
            .unwrap()
            .current_mls_commit_event_ref =
            EventId::from_event_digest(&Hash::new(arkret_canonical::sha256_digest([2])).unwrap())
                .unwrap();
        assert!(validate_mls_installation(&event, &wrong_base).is_err());

        let mut wrong_epoch = installed.clone();
        wrong_epoch.epoch = 2;
        assert!(validate_mls_installation(&event, &wrong_epoch).is_err());

        let mut genesis_shaped = installed.clone();
        genesis_shaped.base = None;
        assert!(validate_mls_installation(&event, &genesis_shaped).is_err());

        let mut missing_state = installed;
        missing_state.public_state.clear();
        assert!(validate_mls_installation(&event, &missing_state).is_err());
    }
}
