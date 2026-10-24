//! Effect enums returned by the reducer's `apply_*` helpers.
//!
//! Split out of the `reducer` mod file; re-exported there so the
//! `crate::reducer::ProjectionEffect` / `MlsEffect` paths stay unchanged.

use arkret_models_collaboration::agent_operations::AgentLifecycleState;
use arkret_wire::{AppletId, DidCoreId, EventKind};

use super::{
    CircleLifecycleState, ColandRelationState, MessageState, ObjectLifecycleState,
    SpaceContainerLifecycleState,
};

/// The effect of applying an operation to the projection state.
#[derive(Clone, Debug)]
pub enum ProjectionEffect {
    MessageCreated(MessageState),
    MessageRevised {
        original_id: String,
        revision: MessageState,
    },
    MessageRedacted {
        event_id: String,
    },
    ReactionChanged {
        event_id: String,
        actor: String,
        key: String,
        active: bool,
    },
    RsvpProjected {
        event_ref: String,
        actor_id: String,
        occurrence: Option<String>,
        /// Accepted Event whose entry is now the settled RSVP.
        source_event_id: String,
    },
    PinProjected {
        pin_scope_key: String,
        target_ref: String,
        active: bool,
    },
    RelationCreated(ColandRelationState),
    RelationUpdated(ColandRelationState),
    RelationDeleted {
        relation_id: String,
    },
    MembershipChanged {
        realm_id: String,
        member: String,
        action: String,
    },
    InviteStateChanged {
        invite_id: String,
        realm_id: String,
        state: String,
        invitee_id: Option<String>,
    },
    RealmLifecycle {
        realm_id: String,
        action: String,
    },
    /// COT-06-004 — `ak.realm.set_default_strand` projected. The Realm's
    /// `default_strand_id` now points at `strand_id`.
    RealmDefaultStrandSet {
        realm_id: String,
        strand_id: String,
    },
    /// Space-container lifecycle transition accepted; new state is reflected in
    /// `ProjectionState::space_containers` and (when persisted) `projection_space_containers`.
    SpaceContainerLifecycle {
        container_space_id: String,
        new_state: SpaceContainerLifecycleState,
    },
    /// Strand lifecycle transition accepted. Mirror of `SpaceContainerLifecycle`
    /// for `ProjectionState::strands`.
    StrandLifecycle {
        strand_id: String,
        new_state: ObjectLifecycleState,
    },
    /// Morph lifecycle transition accepted. Same shape as Strand.
    MorphLifecycle {
        morph_id: String,
        new_state: ObjectLifecycleState,
    },
    /// AKP-0007 — Circle lifecycle transition accepted. Reflects
    /// `ak.circle.create` / `update` / `archive` / `restore` / `tombstone`
    /// projection writes; new state is reflected in
    /// `ProjectionState::circles` (and the durable `projection_circles`
    /// mirror once persistence is wired).
    CircleLifecycle {
        circle_id: String,
        new_state: CircleLifecycleState,
    },
    /// AKP-0007 — Circle membership transition. `target_state` is the
    /// `ak.circle.member.state` payload's `state` value (active / removed /
    /// banned / left / invited). The reducer applies the membership write
    /// only after the strict-subset invariant
    /// (`Circle.members ⊆ Realm.members`) has been satisfied.
    CircleMemberStateChanged {
        circle_id: String,
        member: String,
        target_state: String,
    },
    /// Applet registry projection updated (registration or discovery).
    AppletProjectionUpdated {
        applet_id: AppletId,
    },
    /// `ak.realm.policy_bundle` projected into the canonical
    /// `ak.component.realm.policy_bundle.v1` registered state model cell.
    RealmPolicyBundleProjected {
        realm_id: String,
    },
    /// A registry-validated Realm bootstrap facet was written to its exact
    /// single-target registered state model cell during the staged genesis transaction.
    RealmBootstrapFacetProjected {
        realm_id: String,
        kind: String,
    },
    RealmSearchPolicyProjected {
        realm_id: String,
    },
    RealmPreviewPolicyProjected {
        realm_id: String,
    },
    /// `discovery/read-receipts.md` section 2.5 -- `ak.scope.read_receipt_policy`
    /// projected into the `scope_read_receipt_policy` current result. That
    /// section names this kind the family's sole carrier.
    ScopeReadReceiptPolicyProjected {
        scope_ref: arkret_wire::ScopeRef,
    },
    RealmNotaryProjected {
        realm_id: String,
    },
    RealmDigestSuiteTransitionProjected {
        realm_id: String,
        digest_algorithm: String,
    },
    /// `ak.realm.media_service` projected into the canonical
    /// `ak.component.realm.media_service.v1` registered state model cell consumed by
    /// the AKP-0010 media token exchange.
    RealmMediaServiceProjected {
        realm_id: String,
    },
    /// `ak.call.state` projected into the canonical
    /// `ak.component.call.state.v1` cell. Carries the committed
    /// `session_focus` plus the orthogonal recording / transcribe /
    /// moderation projection (`call-state.md` §4.2 / §5).
    CallStateProjected {
        call_id: String,
    },
    /// Audit binding genesis/state projected. The immutable binding document
    /// and its lifecycle live in separate cells keyed by one AuditBindingId.
    AuditBindingProjected {
        binding_id: String,
        state: String,
    },
    /// `ak.audit.session.*` advanced the sealed release session transition.
    AuditSessionProjected {
        session_id: String,
        state: String,
    },
    /// `ak.audit.release` appended one release manifest to its session log.
    AuditReleaseProjected {
        session_id: String,
        release_id: String,
    },
    /// R3.1 — `ak.realm.link` event was projected into the
    /// `ak.component.realm.link.v1` transition cell + the `realm_links`
    /// structured cache.
    RealmLinkProjected {
        realm_id: String,
        target_realm_id: String,
        link_kind: String,
        status: String,
    },
    /// SOL-ORG-02 — `ak.realm.organization` relationship statement projected
    /// into the `ak.component.realm.organization.v1` registered state model cell keyed by
    /// `(organization_id, relationship)` + the `realm_organization_statements`
    /// structured cache. `status` is `active` (relationship live) or `revoked`
    /// (inactive, retained for audit).
    RealmOrganizationProjected {
        realm_id: String,
        organization_id: DidCoreId,
        relationship: String,
        status: String,
    },
    /// REDU-1 (R3 spec-sync 2026-05-27, arkret-spec b47ff6ec) — agent
    /// lifecycle transition transition projected. `agent_id` is the DID
    /// from the payload; `new_state` is the post-transition
    /// AgentLifecycleState. Bottom = `Reject`;
    /// Deactivated is terminal.
    AgentLifecycleProjected {
        agent_id: String,
        new_state: AgentLifecycleState,
    },
    /// `ak.agent.key.authorize` projected: the key is recorded in
    /// `agent_authorized_keys`. Realm grants are independent from pairing.
    AgentKeyAuthorizeProjected {
        agent_id: String,
        key_id: String,
    },
    /// AKP-0008 §4.11 — `ak.agent.key.revoke` projected: the key was removed
    /// from `agent_authorized_keys`.
    AgentKeyRevokeProjected {
        agent_id: String,
        key_id: String,
    },
    /// The registry classifies this committed Event as a durable fact with no
    /// typed current projection.  Emitting an explicit effect keeps that
    /// ownership distinguishable from an unimplemented reducer branch.
    DurableFactRetained {
        kind: EventKind,
        event_id: String,
    },
    /// A planned governance-Station change is owned by the authority-commit
    /// handoff service.  The shared product reducer acknowledges the committed
    /// fact without mirroring a governance counter in [`ProjectionState`].
    AuthorityCommitEffectAccepted {
        event_id: String,
        new_governance_station_id: DidCoreId,
    },
    /// MID-1..6 (R3.1/R3.2, arkret-spec @ b56cab1) —
    /// `ak.member.identity.update` accepted into the ordered-log
    /// `ak.component.member.identity.v1` cell. The actual replacement-edge
    /// filter + per-actor effective-set / `member_display_state_digest`
    /// materialization live on the `MemberIdentityRegistry`
    /// (`AppState::member_identity`) because they span cells; this effect
    /// just signals that an event landed.
    MemberIdentityProjected {
        realm_id: String,
        actor_id: String,
        segment: String,
        event_id: String,
    },
    /// G3.S1 — MLS lifecycle effect. One variant covers all four
    /// reducer paths (publish / claim / welcome_enqueue / commit_epoch)
    /// so the routing layer can dispatch on `MlsEffect` without
    /// growing four near-identical `ProjectionEffect` arms.
    Mls(MlsEffect),
    /// An accepted projection event referenced a target that has not reached
    /// this reducer yet. The operation is retained in
    /// `ProjectionState::pending_replay` and replayed once the target is
    /// materialized by backfill, snapshot restore, or a later create event.
    PendingReplayQueued {
        target_ref: String,
        operation_id: String,
        reason: String,
    },
    /// P2 — `ak.moderation.decision` projected as an or_set add into the
    /// `ak.component.moderation_state.v1` cell keyed by `payload.target_ref`
    /// (content-moderation.md §2.6). Carries an issuer/target_ref/decision
    /// snapshot for deterministic projection reads.
    ModerationDecisionProjected {
        decision_id: String,
        realm_id: String,
    },
    /// P2 — `ak.moderation.decision.lift` projected as an or_set
    /// observed-remove / supersede on the moderation_state target cell.
    /// Terminal: a re-add of a lifted decision_id
    /// stays lifted (mirrors capabilities.md §12.1).
    ModerationDecisionLifted {
        decision_id: String,
        realm_id: String,
    },
    /// `ak.policy.set` replaced the complete Policy document selected by
    /// `policy_id` in the governing Station's current-state projection.
    PolicyProjected {
        policy_id: String,
        realm_id: String,
    },
    /// `ak.policy.action` replaced one approval configuration. The selector
    /// branch stays explicit so a Policy id can never collide with an opaque
    /// Realm-local action id.
    PolicyActionProjected {
        selector_kind: &'static str,
        selector: String,
        realm_id: String,
    },
    /// State-machine rejected the operation per
    /// `common-fields.md §5.1`. Routing layer maps this to HTTP 412
    /// `failed_precondition` with the canonical reason_code.
    Rejected {
        reason: String,
    },
    Ignored,
}

/// G3.S1 — discriminated effect emitted by the MLS reducer helpers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MlsEffect {
    /// `apply_keypackage_publish` — a fresh KeyPackage row was stored
    /// for the exact endpoint branch under `actor_id`.
    KeyPackagePublished {
        keypackage_id: String,
        actor_id: String,
        device_id: Option<String>,
    },
    /// `apply_keypackage_claim` — the named KeyPackage was atomically
    /// claimed for `group_id`. CAS guarantees at-most-one of these per
    /// `keypackage_id`.
    KeyPackageClaimed {
        keypackage_id: String,
        group_id: String,
        intended_realm_id: Option<String>,
        last_resort: bool,
        claimed_at: i64,
    },
}

/// Which Space-container lifecycle transition is being attempted. Used by
/// `apply_space_container_lifecycle` to share the state-machine guard across
/// the three event kinds.
#[derive(Clone, Copy, Debug)]
pub(crate) enum SpaceContainerLifecycleTransition {
    Archive,
    Restore,
    Tombstone,
}

/// Strand / Morph lifecycle transition picker. Mirror of
/// `SpaceContainerLifecycleTransition` but for the two-event family (no tombstone).
#[derive(Clone, Copy, Debug)]
pub(crate) enum ObjectLifecycleTransition {
    Archive,
    Restore,
}
