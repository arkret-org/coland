//! The core [`ProjectionState`] struct and its inline `impl` (cell
//! helpers, push-route apply, dispatch entry points, and Strand / Morph
//! state-machine preflights).
//!
//! Split out of the `reducer` mod file; re-exported there so the
//! `crate::reducer::ProjectionState` path and sibling `super::*` access
//! stay unchanged. Additional `impl ProjectionState` blocks live in the
//! `apply_*` sibling modules.

use std::collections::{BTreeMap, BTreeSet};

use arkret_event_draft::ProjectedEventOperation as Operation;
use arkret_models_collaboration::agent_operations::AgentLifecycleState;
use arkret_models_collaboration::governance::agent_membership_cascade::AgentControllerMembershipBinding;
use arkret_wire::{AppletId, ProfileId};
use serde_json::Value;

use super::facets::{FacetRef, SettledFacet, facet};
use super::*;
use crate::hlc::ServerHlc;

/// In-memory projection state produced by the reducer.
#[derive(Clone, Debug, Default)]
pub struct ProjectionState {
    /// Messages keyed by event_id. LWW by created_at.
    pub messages: BTreeMap<String, MessageState>,
    /// Reactions keyed by (event_id, actor, reaction_key). OR-Set.
    pub reactions: BTreeMap<String, BTreeMap<String, BTreeMap<String, ReactionState>>>,
    /// Calendar RSVP projection keyed by the registered composite cell subject
    /// `(event_ref, occurrence, actor_id)`, where `occurrence` keeps the signed
    /// JSON null as `None` rather than a sentinel string.
    ///
    /// This mirrors the `ak.component.calendar.rsvp.v1` `causal_register` cell:
    /// it retains covered writes and exposes the deterministic current winner.
    pub rsvps: BTreeMap<(String, Option<String>, String), RsvpProjection>,
    /// Shared pin projection keyed by `(pin_scope_key, target_ref)`.
    /// Saved items remain holder-private account-data and never enter this
    /// shared Realm cache.
    pub pins: BTreeMap<(String, String), PinProjection>,
    /// Materialized Relation history keyed by event-derived relation_id.
    pub relations: BTreeMap<String, ColandRelationState>,
    /// Current Relation identity for each canonical
    /// `(realm_id, primary_conflict_domain)` subject. The durable authority
    /// transaction is the CAS authority; this rebuildable index keeps reducer
    /// replay on the same single-current-value model.
    pub relation_current: BTreeMap<(String, String), String>,
    /// Exact authoritative domain and RealmCommit revision for current
    /// Relation values loaded from durable storage. This is query metadata;
    /// the PostgreSQL authority row remains the only CAS source of truth.
    pub relation_current_metadata: BTreeMap<(String, String), RelationCurrentStateProjection>,
    /// Poll projections keyed by poll_id. Poll create is a message content
    /// block; current votes are derived from the complete response causal set.
    pub polls: BTreeMap<arkret_wire::MessageId, PollState>,
    /// Structured side-band cache keyed by
    /// `(realm_id, actor_id)`. Holds the transition state value plus `role` /
    /// `joined_at` / `updated_at` side-band data that doesn't fit in the
    /// `ak.component.member.state.v1` transition cell itself. Reads should go
    /// through helpers like [`ProjectionState::members_of_realm`] /
    /// [`ProjectionState::members_in_state`] / [`ProjectionState::member`]
    /// rather than touching this directly.
    ///
    /// Banned and knocking members are derived via `members_in_state`
    /// against the transition state field, not stored as separate collections.
    pub members: BTreeMap<(String, String), ColandMembershipState>,
    /// Exact controller authority and controller join generation carried by a
    /// Agent membership Event. Effective Agent membership is
    /// derived by joining this binding with the current controller member cell.
    pub agent_membership_bindings: BTreeMap<(String, String), AgentControllerMembershipBinding>,
    /// Immutable accepted decision payloads. OR-Set resolution returns only
    /// active adds and does not carry our local decision_id augmentation.
    pub moderation_decisions: BTreeMap<
        String,
        arkret_models_collaboration::events_payloads::moderation::ModerationDecisionPayload,
    >,
    /// Realm lifecycle state keyed by realm_id.
    pub realm_states: BTreeMap<String, ColandRealmState>,
    /// Redacted event IDs (tombstones). This stays as a flat
    /// fast-lookup index over the parallel [`Self::redaction_cells`] map.
    pub redactions: BTreeSet<String>,
    /// Parallel `redaction` cells keyed by the target
    /// event_id (subject). Each value is a [`RedactionCellValue`] holding
    /// the accepted redaction fact. The original message entry in [`Self::messages`] is
    /// left intact so the ordered-log historical entry id is preserved;
    /// the projection layer consults this map at read time and replaces
    /// the payload with the tombstone.
    pub redaction_cells: BTreeMap<String, RedactionCellValue>,
    /// Accepted projection operations whose local target is not materialized
    /// yet. Backfill/snapshot/create arrival drains this queue and replays the
    /// operations instead of losing them as accepted no-ops.
    pub pending_replay: BTreeMap<String, Vec<PendingReplayEntry>>,
    /// Settled product facets, keyed by `(realm_id, facet)`.
    ///
    /// Each accepted Event reaches the reducer in its stream's commit order,
    /// so a facet holds exactly one value and a write simply replaces the
    /// previous one. Read handlers query [`ProjectionState::facet_value`]
    /// instead of scanning the durable Event store.
    ///
    /// Event kinds that carry no facet -- `ak.message.*`, `ak.reaction.*`,
    /// `ak.relation.*`, `ak.redaction` -- keep their own structured fields
    /// above.
    pub facets: BTreeMap<(String, FacetRef), SettledFacet>,
    /// Effective `default_join_rule`, keyed by Realm. This mirrors the
    /// bootstrap/create value and later sealed join-rule facet so admission
    /// can select the protocol's C-axis gates without inventing a Realm id
    /// cell subject.
    pub realm_join_rules: BTreeMap<String, String>,
    /// Server-side Space-container projection —
    /// `container_space_id -> SpaceContainerProjection`.
    /// Maintains the canonical state-machine described in
    /// `arkret-spec/v1/zh/models/common-fields.md §5.1` for `ak.space.*`
    /// lifecycle events. Used by `event_log::submit_event` to reject
    /// invalid transitions with HTTP 412 before persisting. Reducer applies
    /// `ak.space.create` / update / parent / archive / restore / tombstone;
    /// mirror table is the `projection_space_containers` durable table.
    pub space_containers: BTreeMap<String, SpaceContainerProjection>,
    /// Server-side Strand projection. Mirrors the canonical state-machine
    /// for ak.strand.create / update / archive / restore. Unlike Space
    /// there is no dedicated `ak.strand.tombstone` event; terminal state
    /// is reached via `ak.redaction`. Mirror table is `projection_strands`
    /// (durable).
    pub strands: BTreeMap<String, StrandProjection>,
    /// AKP-0007 — server-side Circle projection. Mirrors the canonical
    /// state-machine for `ak.circle.*` lifecycle / membership events
    /// (spec b7d35be `zh/models/circle.md`). Keyed by `circle_id`
    /// (`ak:circle:<44-char event token>`); membership and parent-Realm binding live in
    /// the struct so the wire layer can enforce
    /// `Circle.members ⊆ Realm.members` without an extra DB hop.
    pub circles: BTreeMap<String, CircleProjection>,
    /// First-class Sidecars keyed by `sidecar_id`.
    pub sidecars: BTreeMap<String, SidecarProjection>,
    /// Native source-context mappings keyed by `(sidecar_id, kind:id)`.
    pub sidecar_contexts: BTreeMap<(String, String), SidecarContextProjection>,
    /// Accepted control ref that created each Sidecar.
    pub sidecar_create_refs: BTreeMap<String, String>,
    /// Current accepted join ref for each active Circle member.
    pub circle_member_join_refs: BTreeMap<(String, String), String>,
    /// Side-band membership boundaries for Circle history filtering. Keyed by
    /// `(circle_id, actor_id)` and retained across leave/ban transitions so
    /// read-side helpers can enforce invited/joined floors deterministically.
    pub circle_memberships: BTreeMap<(String, String), CircleMembershipState>,
    /// Server-side Morph projection. Same shape as Strand. Mirror table
    /// is `projection_morphs` (durable).
    pub morphs: BTreeMap<String, MorphProjection>,
    /// Server-side Applet registry projection, keyed by canonical `applet_id`.
    /// `service_id` remains an authority attribute and may identify multiple
    /// Applets. Populated by
    /// `ak.applet.registration` (initial registration / re-registration)
    /// and updated by `ak.applet.discovery` (freshness only). Used by
    /// `GET /_coland/admin/applets` admin snapshot. Runtime-private applet
    /// session progress is not a durable Arkret event and is not mirrored here.
    pub applets: BTreeMap<AppletId, AppletProjection>,
    /// R3 spec-sync (2026-05-27, arkret-spec b47ff6ec) — transition lifecycle
    /// state for each complete canonical Agent Account ActorId. Driven by
    /// `ak.agent.{pause,resume,deactivate}` (REDU-1). Default `Active`
    /// for any Agent Account we've seen; `Deactivated` is terminal
    /// (no transition out, no resume after).
    pub agent_lifecycles: BTreeMap<String, AgentLifecycleState>,
    /// Committed `ak.agent.action_approve` confirmations keyed by the complete
    /// `approved_event_id` whose nonce they allocated. Only an index: the
    /// act-on-behalf gate re-reads and verifies the committed Event itself.
    pub agent_action_confirmations: BTreeMap<String, arkret_wire::EventId>,
    /// Accepted, non-revoked agent key authorizations keyed by `agent_id`.
    /// An entry is the set of authorized `key_id`s the agent currently holds
    /// (cleared on `ak.agent.key.revoke`).
    /// Agent id -> (active key id -> accepted authorize Event id).
    pub agent_authorized_keys: BTreeMap<String, BTreeMap<String, String>>,
    /// R3.1 — Realm-link projection. Outer key is the source
    /// `realm_id` (the envelope `realm_id` of a `ak.realm.link` event);
    /// the inner Vec accumulates every directed link the Realm has
    /// declared, including non-`active` status entries (so admin tooling
    /// can render `rejected` / `tombstoned` history). The committed
    /// source is indexed by `(realm, target, link_kind)`; this local cache
    /// supports the query API.
    pub realm_links: BTreeMap<String, Vec<RealmLinkState>>,
    /// R3.1 — inverse index of [`Self::realm_links`] keyed by the
    /// target `realm_id`. Lets the query API answer
    /// `direction=inbound` in O(1) without a full scan.
    pub realm_links_inbound: BTreeMap<String, Vec<RealmLinkState>>,
    /// SOL-ORG-02 — `ak.realm.organization` relationship-statement
    /// projection, keyed by `(realm_id, organization_id, relationship)`.
    /// Committed statement semantics per `(organization_id, relationship)`
    /// subject — the latest statement (active or revoked) wins. Multiple
    /// owner / governance / sponsor / directory_certifier relationships for
    /// the same Realm coexist as independent rows. Committed statements
    /// use the composite `{organization_id}::{relationship}` subject; this
    /// local cache supports verified-relationship and effective-policy reads.
    pub realm_organization_statements:
        BTreeMap<(String, arkret_wire::DidCoreId, String), RealmOrganizationStatementState>,
    /// G3.S1 — published MLS KeyPackages keyed by `keypackage_id`. Each
    /// row is per `(actor_id, device_id)`; the `claimed_by` / claim-window
    /// slots flip on a successful CAS claim.
    pub mls_key_packages: BTreeMap<String, MlsKeyPackageProjection>,
}

impl ProjectionState {
    pub fn new() -> Self {
        super::assert_effect_dispatch_contract();
        Self::default()
    }

    pub(crate) fn queue_pending_replay(
        &mut self,
        target_ref: impl Into<String>,
        operation: &Operation,
        reason: impl Into<String>,
    ) -> ProjectionEffect {
        let target_ref = target_ref.into();
        let reason = reason.into();
        let operation_id = operation.operation_id.to_string();
        let queue = self.pending_replay.entry(target_ref.clone()).or_default();
        if !queue.iter().any(|entry| entry.operation_id == operation_id) {
            queue.push(PendingReplayEntry {
                target_ref: target_ref.clone(),
                reason: reason.clone(),
                operation_id: operation_id.clone(),
                operation: operation.clone(),
                queued_at: operation.created_at,
            });
        }
        ProjectionEffect::PendingReplayQueued {
            target_ref,
            operation_id,
            reason,
        }
    }

    pub(crate) fn projected_ref_exists(&self, target_ref: &str) -> bool {
        if target_ref.starts_with("ak:space:") {
            return self.space_containers.contains_key(target_ref);
        }
        if target_ref.starts_with("ak:strand:") {
            return self.strands.contains_key(target_ref);
        }
        if target_ref.starts_with("ak:morph:") {
            return self.morphs.contains_key(target_ref);
        }
        if target_ref.starts_with("ak:relation:") {
            return self.relations.contains_key(target_ref);
        }
        if arkret_identifiers::EventId::new(target_ref).is_ok()
            || arkret_identifiers::MessageId::new(target_ref).is_ok()
        {
            return self.message_by_target_ref(target_ref).is_some();
        }
        false
    }

    pub fn replay_resolved_pending(&mut self, hlc: &ServerHlc) -> usize {
        let mut replayed = 0usize;
        for _ in 0..128 {
            let ready_targets = self
                .pending_replay
                .keys()
                .filter(|target_ref| self.projected_ref_exists(target_ref))
                .cloned()
                .collect::<Vec<_>>();
            if ready_targets.is_empty() {
                break;
            }
            for target_ref in ready_targets {
                let Some(entries) = self.pending_replay.remove(&target_ref) else {
                    continue;
                };
                for entry in entries {
                    let _ = self.apply_once(&entry.operation, hlc);
                    replayed += 1;
                }
            }
        }
        replayed
    }

    /// Look up a settled facet value of one Realm.
    ///
    /// `None` means no accepted Event has written that facet yet. A total
    /// commit order leaves no conflict state to report.
    pub fn facet_value(&self, realm_id: &str, facet: &FacetRef) -> Option<&Value> {
        self.facets
            .get(&(realm_id.to_owned(), facet.clone()))
            .map(|settled| &settled.value)
    }

    /// Number of accepted writes to a facet. `0` means it has never been
    /// written, which is what an `expected_revision` precondition on a
    /// first write names.
    pub fn facet_revision(&self, realm_id: &str, facet: &FacetRef) -> u64 {
        self.facets
            .get(&(realm_id.to_owned(), facet.clone()))
            .map_or(0, |settled| settled.revision)
    }

    /// Write a facet of one Realm. The caller has already established that the
    /// Event was accepted and committed, so the write is unconditional.
    pub fn set_facet(&mut self, realm_id: &str, facet: FacetRef, value: Value) {
        let key = (realm_id.to_owned(), facet);
        let revision = self.facets.get(&key).map_or(0, |settled| settled.revision) + 1;
        self.facets.insert(key, SettledFacet { revision, value });
    }

    /// Write a Realm-singleton facet.
    pub fn set_realm_facet(&mut self, realm_id: &str, facet: &str, value: Value) {
        self.set_facet(realm_id, FacetRef::singleton(facet), value);
    }

    /// Remove a facet of one Realm.
    pub fn clear_facet(&mut self, realm_id: &str, facet: &FacetRef) -> Option<Value> {
        self.facets
            .remove(&(realm_id.to_owned(), facet.clone()))
            .map(|settled| settled.value)
    }

    /// Every settled facet of one Realm, in facet order.
    pub fn realm_facets(&self, realm_id: &str) -> impl Iterator<Item = (&FacetRef, &Value)> {
        self.facets
            .iter()
            .filter(move |((realm, _), _)| realm == realm_id)
            .map(|((_, facet), settled)| (facet, &settled.value))
    }
    /// Settled `container.order` facet value of one parent Space.
    pub fn child_order_facet_value(&self, parent_space_id: &str) -> Value {
        let mut children = self
            .space_containers
            .values()
            .filter(|container| container.parent_ref.as_deref() == Some(parent_space_id))
            .filter(|container| container.state == SpaceContainerLifecycleState::Active)
            .collect::<Vec<_>>();
        children.sort_by(|left, right| {
            left.rank
                .cmp(&right.rank)
                .then(left.title.cmp(&right.title))
                .then(left.container_space_id.cmp(&right.container_space_id))
        });
        let order = children
            .iter()
            .map(|container| container.container_space_id.clone())
            .collect::<Vec<_>>();
        let entries = children
            .iter()
            .enumerate()
            .map(|(index, container)| {
                serde_json::json!({
                    "index": index,
                    "space_id": container.container_space_id,
                    "realm_id": container.realm_id,
                    "kind": container.kind,
                    "title": container.title,
                    "rank": container.rank,
                    "state": container.state.as_str(),
                })
            })
            .collect::<Vec<_>>();
        serde_json::json!({
            "facet": facet::CONTAINER_ORDER,
            "parent_space_id": parent_space_id,
            "order": order,
            "children": entries,
        })
    }

    pub(crate) fn store_strand_position_relation(
        &mut self,
        strand_id: &str,
        realm_id: &str,
        board_space_id: &str,
        list_space_id: &str,
        rank: Option<&str>,
        now: chrono::DateTime<chrono::Utc>,
    ) {
        let relation_id = format!("ak:relation:kanban.position:{board_space_id}:{strand_id}");
        let scope_circle_id = self
            .strand_scope_circle_id(strand_id)
            .or_else(|| self.space_container_scope_circle_id(list_space_id));
        let relation = self
            .relations
            .entry(relation_id.clone())
            .or_insert_with(|| ColandRelationState {
                relation_id: relation_id.clone(),
                realm_id: realm_id.to_owned(),
                relation_kind: "contains".to_owned(),
                scope_circle_id: scope_circle_id.clone(),
                from_ref: Some(list_space_id.into()),
                to_ref: Some(strand_id.into()),
                rank: rank.map(ToOwned::to_owned),
                fields: BTreeMap::new(),
                state: "active".to_owned(),
                source_event_id: None,
                source_event_digest: None,
                created_at: now,
                updated_at: now,
            });
        relation.realm_id = realm_id.to_owned();
        relation.relation_kind = "contains".to_owned();
        relation.scope_circle_id = scope_circle_id;
        relation.from_ref = Some(list_space_id.into());
        relation.to_ref = Some(strand_id.into());
        relation.rank = rank.map(ToOwned::to_owned);
        relation.fields.insert(
            "board_space_id".to_owned(),
            Value::String(board_space_id.to_owned()),
        );
        relation.fields.insert(
            "list_space_id".to_owned(),
            Value::String(list_space_id.to_owned()),
        );
        relation.state = "active".to_owned();
        relation.updated_at = now;
    }

    /// Apply a single operation and return the effect.
    ///
    /// Per-kind cache dispatch uses [`APPLY_REGISTRY`], derived from the
    /// explicit canonical-ownership manifest. Every active kind needs an
    /// implemented cache adapter or a reviewed refusal before startup.
    ///
    /// A registry miss always fails closed. Non-reducer events have a separate,
    /// explicit service-effect dispatch below and may not enter this shared
    /// projection path as a successful no-op.
    ///
    /// Shared current is installed from accepted RealmCommit projections.
    /// These local caches do not independently establish protocol authority.
    fn apply_once(&mut self, operation: &Operation, hlc: &ServerHlc) -> ProjectionEffect {
        let Some(kind) = crate::kinds::canonical_kind_for_operation(operation) else {
            return ProjectionEffect::Rejected {
                reason: "unknown_event_kind".to_owned(),
            };
        };
        if kind == arkret_wire::EventKind::RealmDestroy
            || (self.realm_is_in_terminal_state(operation.realm_id.as_str())
                && !arkret_wire::events::kinds::is_audit_kind(&kind))
        {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::FAILED_PRECONDITION.to_owned(),
            };
        }
        match APPLY_REGISTRY.get(&kind) {
            Some(dispatch) => dispatch(self, operation, hlc),
            None => ProjectionEffect::Rejected {
                reason: if kind.is_reducer_input() {
                    "unregistered_reducer_event_kind"
                } else {
                    "non_reducer_event_on_shared_projection_path"
                }
                .to_owned(),
            },
        }
    }

    /// Apply the manifest's non-reducer service cache adapter. A private
    /// service remains responsible for its own durable acceptance; this
    /// function cannot make its Event advance a shared Realm frontier.
    fn apply_non_reducer_event(
        &mut self,
        kind: arkret_wire::EventKind,
        operation: &Operation,
        hlc: &ServerHlc,
    ) -> ProjectionEffect {
        super::dispatch::apply_service_effect(self, &kind, operation, hlc)
    }

    /// Reduce one Operation whose Event contract declares no cell write.
    ///
    /// Kinds that do declare writes reject with `reducer_projection_failed`
    /// here; the caller must use [`Self::apply_projected`] with the registry
    /// projection of the signed Event.
    pub fn apply(&mut self, operation: &Operation, hlc: &ServerHlc) -> ProjectionEffect {
        let Some(kind) = crate::kinds::canonical_kind_for_operation(operation) else {
            return ProjectionEffect::Rejected {
                reason: "unknown_event_kind".to_owned(),
            };
        };
        if !kind.is_reducer_input() {
            return self.apply_non_reducer_event(kind, operation, hlc);
        }
        self.apply_projected(operation, hlc)
    }

    /// Reduce one accepted Operation.
    pub fn apply_projected(&mut self, operation: &Operation, hlc: &ServerHlc) -> ProjectionEffect {
        let effect = self.apply_once(operation, hlc);
        self.replay_resolved_pending(hlc);
        effect
    }
    // ── Strand / Morph projection state machine ──

    /// Shared source-state guard for `ak.<kind>.stage.set`
    /// (`common-fields.md` §5.3.3 rules 1-2).
    ///
    /// A physically terminal object reports `<kind>_already_terminal`, an
    /// archived one `<kind>_not_active`; both surface as 412
    /// `failed_precondition` at admission. An unknown object is tolerated,
    /// matching the causal/backfill tolerance of the sibling preflights. No
    /// direction between the eight stage values is checked here or anywhere
    /// else: v1 registers no workflow-profile carrier (§5.3.4).
    fn check_stage_set_source_state(
        &self,
        state: Option<ObjectLifecycleState>,
        terminal_reason: &'static str,
        not_active_reason: &'static str,
    ) -> Result<(), &'static str> {
        let Some(state) = state else {
            return Ok(());
        };
        if state.is_terminal() {
            return Err(terminal_reason);
        }
        if state != ObjectLifecycleState::Active {
            return Err(not_active_reason);
        }
        Ok(())
    }

    /// Read-only preflight for `ak.redaction` events that
    /// target a Strand / Morph via `object_ref`. Per spec common-fields.md
    /// §5.1, redaction is legal only from `active` or `archived` source;
    /// terminal source MUST `failed_precondition` with
    /// `<kind>_already_terminal`. Unknown object tolerated (causal /
    /// backfill window). Space containers are excluded — spec routes their
    /// removal through `ak.space.tombstone` only.
    pub fn check_redaction_target_transition(
        &self,
        operation: &Operation,
    ) -> Result<(), &'static str> {
        if crate::kinds::canonical_kind_for_operation(operation)
            != Some(arkret_wire::EventKind::Redaction)
        {
            return Ok(());
        }
        let Some(object_ref) = redaction_object_ref(operation) else {
            return Ok(());
        };
        if let Some(strand) = self.strands.get(&object_ref) {
            if strand.state.is_terminal() {
                return Err("strand_already_terminal");
            }
            return Ok(());
        }
        if let Some(morph) = self.morphs.get(&object_ref) {
            if morph.state.is_terminal() {
                return Err("morph_already_terminal");
            }
            return Ok(());
        }
        Ok(())
    }

    /// Read-only state-machine preflight for a `ak.morph.*` lifecycle event.
    /// The Morph display preflight uses its current projected lifecycle.
    pub fn check_morph_lifecycle_transition(
        &self,
        operation: &Operation,
    ) -> Result<(), &'static str> {
        let kind = match crate::kinds::canonical_kind_for_operation(operation) {
            Some(k) => k,
            None => return Ok(()),
        };
        if kind == arkret_wire::EventKind::MorphStageSet {
            return self.check_stage_set_source_state(
                operation
                    .payload
                    .get("morph_id")
                    .and_then(Value::as_str)
                    .and_then(|morph_id| self.morphs.get(morph_id))
                    .map(|morph| morph.state),
                "morph_already_terminal",
                "morph_not_active",
            );
        }
        let (allowed_source, reason): (&[ObjectLifecycleState], &'static str) = match kind {
            arkret_wire::EventKind::MorphCreate => return Ok(()),
            arkret_wire::EventKind::MorphUpdate => {
                (&[ObjectLifecycleState::Active], "morph_not_active")
            }
            arkret_wire::EventKind::MorphArchive => {
                (&[ObjectLifecycleState::Active], "morph_not_active")
            }
            arkret_wire::EventKind::MorphRestore => {
                (&[ObjectLifecycleState::Archived], "morph_not_archived")
            }
            _ => return Ok(()),
        };
        let Some(morph_id) = operation.payload.get("target_ref").and_then(|v| v.as_str()) else {
            return Ok(());
        };
        let Some(morph) = self.morphs.get(morph_id) else {
            return Ok(());
        };
        if !allowed_source.contains(&morph.state) {
            return Err(reason);
        }
        Ok(())
    }

    /// Whether the Realm declared `ak.profile.principal_control_realm.v1`.
    ///
    /// PCR and Agent control Realms permanently pin history access to
    /// `since_join`.
    pub fn realm_is_principal_control(&self, realm_id: &str) -> bool {
        self.realm_schema_refs(realm_id)
            .iter()
            .any(|profile| profile == ProfileId::PRINCIPAL_CONTROL_REALM_V1)
    }

    /// Whether this explicitly selected Realm is a principal-control Realm
    /// owned by `principal_id`.
    ///
    /// This is intentionally scoped to one Realm and principal. The complete
    /// account identity is the `(principal_id, station_id)` pair; on
    /// its Station that pair owns one lifetime-local PCR lineage.
    pub fn realm_is_principal_control_for_actor(&self, realm_id: &str, principal_id: &str) -> bool {
        self.realm_states.get(realm_id).is_some_and(|realm| {
            realm.owner.as_deref() == Some(principal_id)
                && self
                    .realm_schema_refs(realm_id)
                    .iter()
                    .any(|profile| profile == ProfileId::PRINCIPAL_CONTROL_REALM_V1)
        })
    }
}
