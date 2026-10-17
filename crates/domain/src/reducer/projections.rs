//! Projection record types produced by the reducer.
//!
//! These are the structured side-band caches and value types that
//! [`super::ProjectionState`] holds. They are split out of the `reducer`
//! mod file for navigability; the mod file re-exports them so the
//! `crate::reducer::Xxx` paths stay unchanged.

use std::collections::{BTreeMap, BTreeSet};

use arkret_event_draft::ProjectedEventOperation as Operation;
use arkret_models_collaboration::events_payloads::ContentBlock;
use arkret_models_collaboration::governance::third_party_invite::ThirdPartyInvite;
use arkret_models_collaboration::objects::profiles::StrandTrack;
use arkret_models_collaboration::objects::space::ChildScopePolicy;
use arkret_wire::{AppletId, DidCoreId, EventId, Hash, ObjectStage};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug)]
pub struct PendingReplayEntry {
    pub target_ref: String,
    pub reason: String,
    pub operation_id: String,
    pub operation: Operation,
    pub queued_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InviteProjection {
    pub invite_id: String,
    pub realm_id: String,
    pub inviter_id: String,
    pub invitee_id: Option<String>,
    pub third_party_invite: Option<ThirdPartyInvite>,
    pub state: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub claim_nonces: BTreeMap<String, String>,
}

/// R3.1 — structured cache row for a single directed Realm link.
/// Mirrors the `ak.component.realm.link.v1` cell value plus envelope-
/// derived timestamps so the query API can render `created_at` /
/// `updated_at` without re-reading the durable Event store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealmLinkState {
    pub realm_id: String,
    pub target_realm_id: String,
    /// Canonical link kind string (snake_case, one of the eight values
    /// in `arkret_models_collaboration::governance::realm_governance::RealmLinkKind`).
    pub link_kind: String,
    /// `active` / `rejected` / `tombstoned`.
    pub status: String,
    pub label: Option<String>,
    pub commitment: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// SOL-ORG-02 — structured cache row for one `ak.realm.organization`
/// relationship statement projection. Mirrors the canonical
/// `ak.component.realm.organization.v1` registered state model cell keyed by the
/// composite subject `(organization_id, relationship)`. The reducer keeps
/// the latest statement per `(realm_id, organization_id, relationship)`; an
/// `active` statement marks the relationship live, a `revoked` statement
/// marks it inactive while retaining `statement_id` for audit.
///
/// Field order mirrors the spec `realm_organization_payload` so the
/// persistence row and query DTO stay aligned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealmOrganizationStatementState {
    pub realm_id: String,
    pub organization_id: DidCoreId,
    /// snake_case relationship: `owner` / `governance` / `sponsor` /
    /// `directory_certifier`.
    pub relationship: String,
    pub statement_id: String,
    /// `active` (relationship live) or `revoked` (inactive, retained for
    /// audit).
    pub status: String,
    /// Endorsement scopes covered by the organization's consent
    /// (snake_case `control_scopes[]` items).
    pub control_scopes: Vec<String>,
    pub issued_at: chrono::DateTime<chrono::Utc>,
    pub not_before: Option<chrono::DateTime<chrono::Utc>>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub supersedes_statement_id: Option<String>,
    pub revokes_statement_id: Option<String>,
    /// Digest of the Realm control frontier the organization evaluated.
    pub realm_commit_ref: Option<String>,
    /// Audit summary of the proof material (never the raw signature bytes).
    pub proof_digest: Option<String>,
    /// `authorization.delegation_ref` when present (delegated issuer roles).
    pub delegation_ref: Option<String>,
    /// `authorization.issuer_role` (snake_case).
    pub issuer_role: String,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl RealmOrganizationStatementState {
    /// `true` when this is an `active` statement currently inside its
    /// validity window (`not_before <= now < expires_at`).
    pub fn is_effective_active(&self, now: chrono::DateTime<chrono::Utc>) -> bool {
        if self.status != "active" {
            return false;
        }
        if let Some(nbf) = self.not_before
            && now < nbf
        {
            return false;
        }
        if let Some(exp) = self.expires_at
            && now >= exp
        {
            return false;
        }
        true
    }

    /// `true` when this active statement's `control_scopes` cover `scope`.
    pub fn covers_scope(&self, scope: &str) -> bool {
        self.control_scopes.iter().any(|s| s == scope)
    }
}

/// G3.S1 — KeyPackage lifetime window. MLS KeyPackages carry a
/// `lifetime = (not_before, not_after)` per RFC 9420 §10. The reducer's
/// CAS claim path enforces `not_before <= now < not_after` (out-of-window
/// publishes are rejected on intake; expired KeyPackages cannot be
/// claimed and a follow-up `claim` returns `keypackage_expired`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyPackageLifetimeProjection {
    pub not_before: i64,
    pub not_after: i64,
}

/// G3.S1 — published MLS KeyPackage row.
///
/// One per `(actor_id, device_id, keypackage_id)`. Ordinary packages use
/// an atomic CAS claim that flips `claimed_by` from `None` to `Some(group_id)`
/// and sets its claim window; last-resort packages keep the row published and
/// bind reuse to a single Realm.
#[derive(Clone, Debug, PartialEq, Eq)]
/// Server-side reducer projection for KeyPackage claim and consumption.
///
/// This is deliberately distinct from the SDK's `MlsKeyPackageRecord`, which
/// is a client/MLS behavior record. The server projection additionally owns
/// authorization anchors, claim deadlines, consumption timestamps, and the
/// last-resort Realm binding, so embedding the SDK record would create two
/// competing lifecycle sources.
pub struct MlsKeyPackageProjection {
    /// Canonical `keypackage-<uuid>` identifier.
    pub id: String,
    pub keypackage_ref: String,
    pub keypackage_digest: String,
    /// Complete Account owner; the endpoint principal may instead be an Agent.
    pub owner_account_id: arkret_wire::AccountId,
    pub effective_scope: Option<arkret_wire::ScopeRef>,
    pub actor_id: String,
    pub device_id: Option<String>,
    /// Exact Agent runtime verification method used by the non-device endpoint.
    pub endpoint_verification_method: Option<String>,
    pub lifetime: KeyPackageLifetimeProjection,
    /// Opaque bytes of the MLS KeyPackage (`mls_key_package` per RFC 9420
    /// §11). Server treats this as a black box; only the recipient device
    /// can decrypt the Welcome it backs.
    pub key_package_bytes: Vec<u8>,
    pub capabilities: Vec<String>,
    pub capabilities_digest: String,
    pub last_resort: bool,
    pub last_resort_realm_id: Option<String>,
    /// `None` while the KeyPackage is still claimable; `Some(group_id)`
    /// after a successful CAS claim. The CAS guarantees at-most-one
    /// claim across concurrent Welcomes.
    pub claimed_by: Option<String>,
    /// Claimed trust binding captured when the KeyPackage was published.
    /// Exactly one of `device_authorize_event_id` or
    /// `agent_key_authorize_event_id` is present.
    pub device_authorize_event_id: Option<String>,
    pub agent_key_authorize_event_id: Option<String>,
    /// Unix seconds at which the CAS claim happened (mirrors `claimed_by`).
    pub claimed_at: Option<i64>,
    /// Unix milliseconds for the single-use claim authorization deadline.
    pub claim_expires_at_unix_ms: Option<i64>,
    /// Unix seconds at which the target device consumed the claim.
    pub consumed_at: Option<i64>,
    pub created_at: i64,
}

/// Server-side Space-container state cache. Mirrors the
/// `projection_space_containers` table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpaceContainerProjection {
    pub container_space_id: String,
    pub realm_id: String,
    pub kind: String,
    pub title: String,
    pub fields: BTreeMap<String, Value>,
    pub scope_circle_id: Option<String>,
    pub child_scope_policy: Option<ChildScopePolicy>,
    pub parent_ref: Option<String>,
    pub rank: Option<String>,
    pub state: SpaceContainerLifecycleState,
    pub state_changed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_by: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_by: Option<String>,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Stream-F (Wave 1B) — `realm_destroyed_orphan` flag set by the
    /// `ak.realm.destroy` cascade when this container's home Realm is
    /// destroyed. Spec `realm-and-space.md` §2.5.1 ¶6: orphaned
    /// containers become read-only locked projections; no
    /// `ak.strand.move` / `ak.space.parent` / `ak.space.update` may
    /// revive them. Defaults to `false`.
    pub orphaned: bool,
}

pub(crate) fn space_container_id_from_payload(payload: &Value) -> Option<String> {
    payload
        .get("space_id")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SpaceContainerLifecycleState {
    #[default]
    Active,
    Archived,
    Tombstoned,
}

impl SpaceContainerLifecycleState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Archived => "archived",
            Self::Tombstoned => "tombstoned",
        }
    }
}

/// Wire spelling of an [`ObjectStage`], taken from the SDK enum's own serde
/// mapping. coland never re-declares the protocol-level 8-value stage
/// enumeration; both directions round-trip through the SDK type so the
/// projection, the durable mirror and the read surface agree by construction.
#[must_use]
pub fn object_stage_wire_value(stage: &ObjectStage) -> String {
    serde_json::to_value(stage)
        .ok()
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .unwrap_or_default()
}

/// Inverse of [`object_stage_wire_value`]. Returns `None` for any spelling
/// outside the registered enumeration.
#[must_use]
pub fn object_stage_from_wire_value(value: &str) -> Option<ObjectStage> {
    serde_json::from_value(Value::String(value.to_owned())).ok()
}

/// Server-side Strand state cache. Mirrors `projection_strands` table.
#[derive(Clone, Debug, PartialEq)]
pub struct StrandProjection {
    pub strand_id: String,
    pub realm_id: String,
    /// Strand track entries. The `synthesis` entry may carry its own narrative
    /// content; `discussion` remains configuration for the Message timeline.
    pub tracks: BTreeMap<String, StrandTrack>,
    pub title: String,
    pub summary: Option<String>,
    /// Strand Description (`Strand.content`), distinct from Synthesis content.
    /// Exactly one of `content` / `encrypted_content` is present on an `active`
    /// object and **both MUST be absent once `state=redacted`**
    /// (`models/common-fields.md` §5.2) — that absence is what makes "the
    /// content really was cleared" verifiable from a single materialized object
    /// instead of by replaying the event stream.
    pub content: Option<Value>,
    /// E2EE counterpart of `content`; mutually exclusive with it.
    pub encrypted_content: Option<Value>,
    pub fields: BTreeMap<String, Value>,
    pub state: ObjectLifecycleState,
    pub state_changed_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Business-progression axis (`common-fields.md` §5.3). Orthogonal to
    /// `state`: archive never moves `stage`, and `stage=done` never archives.
    /// Written at create from the wire object and afterwards only by
    /// `ak.strand.stage.set`; `ak.strand.update` patches on it are rejected.
    pub stage: Option<ObjectStage>,
    /// Reducer-derived timestamp of the most recent real stage transition.
    /// Never read from the wire, absent while `stage` is absent, and left
    /// untouched by a same-value self-transition (`common-fields.md` §5.3.3).
    pub stage_changed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_by: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_by: Option<String>,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
    /// AKP-0007 — the Circle this Strand is scoped to, if any (`ak:circle:…`).
    /// A message's effective circle-scope is derived from its Strand's
    /// `scope_circle_id` (spec: `scope_circle_id` is a Strand field, not a
    /// message field); messages never carry their own scope.
    pub scope_circle_id: Option<String>,
    /// `schema_refs` — the profile activation axis. Its calendar entry and the
    /// `metadata.fields.calendar` subtree co-occur in both directions.
    pub schema_refs: Vec<String>,
    /// Digest of the last accepted Event that explicitly wrote the Calendar
    /// subtree. Non-Calendar patches leave this winner unchanged.
    pub schedule_revision_source: Option<String>,
}

pub(crate) fn default_strand_tracks() -> BTreeMap<String, StrandTrack> {
    BTreeMap::from([(
        arkret_models_collaboration::objects::profiles::STRAND_TRACK_NAME_SYNTHESIS.to_owned(),
        StrandTrack::synthesis(),
    )])
}

/// AKP-0007 — server-side Circle state cache. Mirrors `projection_circles` +
/// `projection_circle_members` (see migration
/// `20260526010000_add_circles`).
///
/// `members` is the authoritative active-member set; the wire validator and
/// the `ak.circle.member.state` handler use it to enforce the
/// `Circle.members ⊆ Realm.members` invariant
/// (`circle_member_must_be_realm_member`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CircleProjection {
    pub circle_id: String,
    /// Parent Realm id. Create-locked — a Circle never re-binds to another
    /// Realm. Spec `circle.schema.json` §`realm_id`.
    pub realm_id: String,
    /// Optional create-locked Circle semantic profile discriminator.
    pub profile_ref: Option<String>,
    pub title: String,
    pub summary: Option<String>,
    pub display: Value,
    pub directory_visibility: String,
    pub join_rule: String,
    pub history_access: String,
    /// Reducer-derived MLS group binding, installed by this Circle's own accepted
    /// `ak.mls.genesis`. `None` means the Circle scope is still plaintext; once set, the Circle is
    /// irreversibly activated as standard RFC 9420 and the wire actor MUST NOT submit this.
    pub mls_group_ref: Option<String>,
    pub state: CircleLifecycleState,
    pub state_changed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_by: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_by: Option<String>,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Active Circle members. Maintained by `ak.circle.member.state`
    /// transitions (`active` -> insert, `removed`/`banned`/`left` ->
    /// remove). Always a strict subset of the parent Realm's active
    /// member set.
    pub members: BTreeSet<String>,
}

/// First-class Agent Sidecar aggregate. Sidecars are not Circles and
/// never acquire Circle membership or a hidden Circle/Strand backing object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SidecarProjection {
    pub sidecar_id: String,
    pub realm_id: String,
    pub controller_account_id: arkret_wire::AccountId,
    pub state: arkret_models_collaboration::agent_sidecar::AgentSidecarState,
    pub state_changed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// One versioned mapping from an existing source Relation or Strand into a
/// Sidecar. It does not create, own, or copy that source object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SidecarContextProjection {
    pub sidecar_id: String,
    pub normalized_context_ref: Value,
    pub version: u64,
    pub predecessor_event_ref: Option<String>,
    pub attach_event_ref: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CircleMembershipState {
    pub circle_id: String,
    pub member: String,
    pub state: String,
    pub invited_at: Option<chrono::DateTime<chrono::Utc>>,
    pub joined_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// AKP-0007 — Circle lifecycle state. Matches spec `circle.schema.json`
/// `state` enum (active / archived / tombstoned). Distinct from
/// [`ObjectLifecycleState`] (which carries the redacted/deleted forms used
/// by Strand / Morph); Circle has no redaction path because the canonical
/// terminal action is `ak.circle.tombstone`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CircleLifecycleState {
    #[default]
    Active,
    Archived,
    Tombstoned,
}

impl CircleLifecycleState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Archived => "archived",
            Self::Tombstoned => "tombstoned",
        }
    }
}

/// Server-side Morph state cache. Mirrors `projection_morphs` table.
#[derive(Clone, Debug, PartialEq)]
pub struct MorphProjection {
    pub morph_id: String,
    pub realm_id: String,
    /// AKP-0007 - the Circle this Morph is scoped to, if any (`ak:circle:...`).
    /// Morph updates and lifecycle writes must satisfy the same Circle
    /// membership conjunct as creates.
    pub scope_circle_id: Option<String>,
    pub morph_kind: String,
    pub title: Option<String>,
    pub fields: BTreeMap<String, Value>,
    pub schema_refs: Vec<String>,
    pub facets: BTreeMap<String, BTreeMap<String, Value>>,
    pub versions: Vec<DocumentVersionProjection>,
    /// Canonical content slot (`models/common-fields.md` §5.2). Exactly one of
    /// `content` / `encrypted_content` is present on an `active` object, and
    /// **both MUST be absent once `state=redacted`** — that absence is what
    /// makes "the content really was cleared" verifiable from a single
    /// materialized object instead of by replaying the event stream.
    ///
    /// Typed as the SDK [`ContentBlock`]: the morph payload validator has
    /// already decoded the create Event through
    /// `arkret_models_collaboration::objects::profiles::Morph`, so the
    /// projection stores the same decoded shape instead of raw JSON.
    pub content: Option<ContentBlock>,
    /// E2EE counterpart of `content`; mutually exclusive with it.
    pub encrypted_content: Option<Value>,
    pub state: ObjectLifecycleState,
    pub state_changed_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Business-progression axis (`common-fields.md` §5.3), written at create
    /// from the wire object and afterwards only by `ak.morph.stage.set`.
    pub stage: Option<ObjectStage>,
    /// Reducer-derived timestamp of the most recent real stage transition.
    pub stage_changed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_by: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_by: Option<String>,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Materialized version row for document-shaped Morphs.
///
/// This is intentionally projection-side state: the canonical source remains
/// the ordered `ak.morph.create` / `ak.morph.update` event stream, while the
/// read API exposes a compact version list for clients that need to hydrate a
/// document view without replaying the whole history.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocumentVersionProjection {
    pub version_id: String,
    pub event_id: String,
    pub author: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub body_digest: String,
    pub body: Value,
}

/// Server-side Applet registry entry. Populated by
/// `ak.applet.registration` (creates) and `ak.applet.discovery` (refreshes
/// discovery freshness). Spec `extensions/applet-integration.md` doesn't pin
/// down a state-machine for applet entries themselves (the bridge state
/// machine is per-session and lives client-side), so this is a simple
/// last-write-wins projection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppletProjection {
    pub applet_id: AppletId,
    /// Service authority that hosts this Applet. It is not the Applet identity.
    pub service_id: arkret_identifiers::DidCoreId,
    /// Optional capability list from the latest `ak.applet.registration`.
    pub capabilities: Option<Value>,
    /// Durable profile claims from the accepted registration Event.
    pub claimed_profiles: Vec<String>,
    /// Registration epoch bound by applet delegation constraints.
    pub registration_epoch: String,
    /// Exact accepted Event scope used by profile-bound grant rules.
    pub registration_scope_ref: Option<Value>,
    pub registered_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// State enum shared by Strand and Morph projections (mirrors SDK
/// `arkret_wire::ObjectState`). Unlike `SpaceContainerLifecycleState` which has
/// a single `Tombstoned` terminal, Strand / Morph use `Redacted` as their terminal
/// state per spec §5.1.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ObjectLifecycleState {
    #[default]
    Active,
    Archived,
    Redacted,
}

impl ObjectLifecycleState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Archived => "archived",
            Self::Redacted => "redacted",
        }
    }

    /// Terminal state per spec §5.1: Strand / Morph use `redacted` as their
    /// unrecoverable terminal.
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Redacted)
    }
}

/// Cached attribution for the parallel redaction OR-Set member on the
/// registered Message typed-ID subject. It carries the triggering
/// `ak.message.redact` event id so the read path can surface
/// `redaction_ref` on the message tombstone (strand-and-message.md §9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedactionCellValue {
    pub redacted_at: chrono::DateTime<chrono::Utc>,
    pub by: String,
    pub reason: Option<String>,
    pub redaction_event_id: Option<String>,
}

/// Projection-layer view of a single message cell. The reducer
/// keeps the original [`MessageState`] intact; this view is what callers
/// see at read time after the parallel `redaction` cell is consulted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectedMessageView {
    pub event_id: String,
    pub realm_id: String,
    pub sender: String,
    pub thread_id: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// `Some(content)` for live messages; `None` when a redaction tombstone
    /// is in effect (the projection layer replaced the payload).
    pub content: Option<Value>,
    /// `Some(value)` while the parallel `redaction` cell is set; `None` for
    /// live messages and for messages whose redaction was reverted (cell
    /// set back to null).
    pub redaction: Option<RedactionCellValue>,
}

#[derive(Clone, Debug)]
pub struct MessageState {
    pub event_id: String,
    pub message_id: String,
    pub realm_id: String,
    pub sender: String,
    pub thread_id: String,
    pub content: Value,
    pub encrypted: bool,
    pub operation_id: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// If this is a revision, points to the original event_id.
    pub revision_of: Option<String>,
    /// If redacted, the tombstone timestamp.
    pub redacted_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Clone, Debug)]
pub struct ReactionState {
    pub actor: String,
    pub key: String,
    pub active: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Settled RSVP of one `(event_ref, occurrence, actor_id)` subject.
///
/// The state model value is the whole `payload.entry`. Every response rides the
/// Realm's own commit stream, so the newest accepted one replaces the previous
/// outright; there is no covered-write set to retain and no winner to select.
#[derive(Clone, Debug, PartialEq)]
pub struct RsvpProjection {
    pub event_ref: String,
    pub occurrence: Option<String>,
    pub actor_id: String,
    pub entry: Value,
    pub source_event_id: EventId,
    pub source_event_digest: Hash,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PinProjection {
    pub pin_scope: Value,
    pub target_ref: String,
    pub rank: Option<String>,
    pub note: Option<Value>,
    pub actor_id: String,
    pub active: bool,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct PollState {
    pub message_event_id: arkret_wire::EventId,
    pub realm_id: arkret_wire::RealmId,
    pub scope_circle_id: Option<arkret_wire::CircleId>,
    pub definition: arkret_models_collaboration::events_payloads::PollBlock,
    /// Current selection set of each responder. A poll response is an ordinary
    /// Event on the same commit stream as the poll, so the latest accepted
    /// response of an actor replaces the previous one outright.
    pub votes: BTreeMap<arkret_wire::ActorId, Vec<String>>,
    pub responses:
        BTreeMap<arkret_wire::EventId, arkret_models_collaboration::poll::VerifiedPollResponse>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct ColandRelationState {
    pub relation_id: String,
    pub realm_id: String,
    pub relation_kind: String,
    pub scope_circle_id: Option<String>,
    pub from_ref: Option<arkret_models_collaboration::objects::relation::RelationEndpoint>,
    pub to_ref: Option<arkret_models_collaboration::objects::relation::RelationEndpoint>,
    pub rank: Option<String>,
    pub fields: BTreeMap<String, Value>,
    pub state: String,
    pub source_event_id: Option<String>,
    pub source_event_digest: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Restart-safe metadata for the one authoritative current Relation value in
/// a typed primary conflict domain. It is a read cache of the durable
/// authority row, never a second CAS authority.
#[derive(Clone, Debug, PartialEq)]
pub struct RelationCurrentResultProjection {
    pub relation_id: String,
    pub primary_conflict_domain:
        arkret_models_collaboration::objects::relation::RelationPrimaryConflictDomain,
    pub revision: arkret_wire::CurrentRevision,
}

impl ColandRelationState {
    /// Object-only traversal; an Actor endpoint is not an object id.
    pub fn from_object_ref(&self) -> Option<&str> {
        self.from_ref
            .as_ref()
            .and_then(|endpoint| endpoint.as_object_ref())
    }

    pub fn to_object_ref(&self) -> Option<&str> {
        self.to_ref
            .as_ref()
            .and_then(|endpoint| endpoint.as_object_ref())
    }

    pub fn is_active(&self) -> bool {
        self.state == "active"
    }
}

#[derive(Clone, Debug)]
pub struct ColandMembershipState {
    pub member: String,
    pub realm_id: String,
    /// Canonical transition state value (one of `invite` / `join` / `leave` /
    /// `ban` / `knock`). Authoritative source is the
    /// `ak.component.member.state.v1` cell in
    /// [`super::ProjectionState::cells`]; this field is the structured-cache
    /// mirror updated on every membership transition.
    pub state: String,
    pub role: String,
    /// Event frontier that established the current member state.
    pub membership_event_ref: Option<String>,
    /// First effective invite frontier retained after a later join so
    /// `history_access=since_join` can start at the invite boundary while
    /// `history_access=since_join` starts at the join boundary.
    pub invited_at: Option<chrono::DateTime<chrono::Utc>>,
    pub joined_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    /// Machine-readable reason for the current state when the transition was
    /// not member-initiated (for example `controller_membership_ended` on the
    /// forced Agent cascade, actor.md §3.3). `None` for ordinary
    /// member-driven transitions.
    pub reason: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ColandRealmState {
    pub realm_id: String,
    pub owner: Option<String>,
    pub title: Option<String>,
    pub deleted: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    /// Round 4 (B1.2) — Realm trust domain. Captured and locked
    /// immutable on the first `ak.realm.create`; subsequent events that
    /// attempt to set a different trust domain MUST be rejected with
    /// `cross_domain_replay_rejected`. Stored as the canonical
    /// `ak:trust_domain:<scope>` string form.
    pub trust_domain: Option<String>,
    /// Stream-F (Wave 1B) — Realm terminal-state marker. Set by
    /// `apply_realm_lifecycle` when a `ak.realm.tombstone` or
    /// `ak.realm.destroy` event is projected. Possible values:
    ///   - `None` — Realm is live.
    ///   - `Some("tombstoned")` — `ak.realm.tombstone` accepted; the `successor_realm_id` field
    ///     carries the migration target.
    ///   - `Some("destroyed")` — `ak.realm.destroy` accepted; no successor.
    ///
    /// Both terminal states block non-audit writes via
    /// `routing::events::event_log::terminal_realm_check`. Spec
    /// `realm-and-space.md` §2.5 / §2.5.1.
    pub terminal_state: Option<String>,
    /// Stream-F (Wave 1B) — for `ak.realm.tombstone` only: the
    /// `ak:realm:<44-char-token>` of the successor Realm that takes over child
    /// Space/Strand placement. `None` for live or destroyed Realms.
    pub successor_realm_id: Option<String>,
    /// COT-06-004 — the Realm's default Strand pointer (`ak:strand:<44-char-token>`).
    /// Set by `ak.realm.set_default_strand` (`apply_realm_set_default_strand`);
    /// the Strand it names MUST already be projected in this Realm. A Strand's
    /// derived `is_default` flag is computed at query time as
    /// `strand_id == realm.default_strand_id` — there is no separate stored
    /// per-Strand column.
    pub default_strand_id: Option<String>,
}
