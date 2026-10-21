//! Per-kind `apply_*_dispatch` adapters + the canonical
//! `event_kind → ApplyFn` registry consumed by
//! [`super::ProjectionState::apply`].
//!
//! The adapter free functions exist solely to turn the per-kind
//! `(now, hlc, lifecycle_enum_variant, ...)` arg signatures into the
//! uniform `(state, op, hlc) -> ProjectionEffect` shape the registry
//! needs. They contain no projection logic — that all stays in the
//! `apply_*` methods on `ProjectionState`.
//!
//! Split out of the `reducer` mod file; the registry, the `ApplyFn`
//! type, and the realm-link helpers are re-exported there so
//! the `crate::reducer::*` paths and sibling `super::*` access stay
//! unchanged.

use arkret_event_draft::ProjectedEventOperation as Operation;
use arkret_models_collaboration::agent_operations::AgentLifecycleState;
use arkret_models_identity::member_identity::MemberIdentityUpdatePayload;
use arkret_wire::{EventEffectOwnership, EventKind, EventWireScope};
use serde_json::Value;

use super::{
    CircleLifecycleState, ObjectLifecycleTransition, ProjectionEffect, ProjectionState,
    RealmLinkState, SpaceContainerLifecycleTransition,
};
use crate::hlc::ServerHlc;

/// R3.1 — upsert a realm-link row into a per-Realm Vec cache. Matches
/// on the composite key `(realm_id, target_realm_id, link_kind)`; an
/// update replaces in place (keeping the original `created_at`).
pub(crate) fn upsert_realm_link(vec: &mut Vec<RealmLinkState>, row: &RealmLinkState) {
    if let Some(existing) = vec.iter_mut().find(|r| {
        r.realm_id == row.realm_id
            && r.target_realm_id == row.target_realm_id
            && r.link_kind == row.link_kind
    }) {
        let created_at = existing.created_at;
        *existing = row.clone();
        existing.created_at = created_at;
    } else {
        vec.push(row.clone());
    }
}

// ────────────────────────── apply() dispatch registry ──────────────────────────
//
// `ProjectionState::apply()` used to be a 30-arm `match` on
// `canonical_kind_for_operation`. Each arm delegated to a `self.apply_*`
// helper, sometimes with extra carrier args (the lifecycle enums, the
// raw kind string for `apply_realm_lifecycle`, the HLC for relations).
//
// This registry keeps the dispatch table out of the match: every
// canonical event_kind maps to a single `ApplyFn` adapter that calls
// the corresponding `apply_*` helper with the per-kind extra args
// baked in. `apply()` becomes a typed HashMap lookup + indirect call.
// The explicit effect manifest owns every active kind, including deliberate
// refusals. Cache adapters do not replace the accepting transaction's owner.
// Canonical metadata is checked before deriving either runtime dispatch path.

fn projection_received_at(op: &Operation) -> chrono::DateTime<chrono::Utc> {
    op.payload
        .get("event_received_at")
        .and_then(Value::as_str)
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&chrono::Utc))
        .unwrap_or(op.created_at)
}

/// Adapter signature for entries in [`default_apply_registry`].
pub type ApplyFn = fn(&mut ProjectionState, &Operation, &ServerHlc) -> ProjectionEffect;

#[derive(Clone, Copy)]
enum CacheSlot {
    Shared(ApplyFn),
    Service(ApplyFn),
    FailClosed,
}

#[derive(Clone, Copy)]
struct EffectRegistration {
    kind: &'static str,
    owner: EventEffectOwnership,
    scope: EventWireScope,
    reducer_input: bool,
    slot: CacheSlot,
}

include!("effect_manifest.rs");

fn validate_effect_manifest(entries: &[EffectRegistration]) -> Result<(), String> {
    let mut registered = std::collections::HashSet::new();
    for entry in entries {
        let kind = EventKind::from(entry.kind);
        if !registered.insert(kind.clone()) {
            return Err(format!("duplicate effect slot: {}", entry.kind));
        }
        let Some(descriptor) = kind.effect_descriptor() else {
            return Err(format!("unregistered effect kind: {}", entry.kind));
        };
        if descriptor.ownership != entry.owner {
            return Err(format!("effect owner mismatch: {}", entry.kind));
        }
        if kind.wire_scope() != entry.scope || kind.is_reducer_input() != entry.reducer_input {
            return Err(format!("effect scope mismatch: {}", entry.kind));
        }
        match entry.slot {
            CacheSlot::Shared(_)
                if !entry.reducer_input || entry.scope != EventWireScope::DurableEvent =>
            {
                return Err(format!(
                    "private/service effect on shared reducer: {}",
                    entry.kind
                ));
            }
            CacheSlot::Service(_) if entry.reducer_input => {
                return Err(format!(
                    "shared reducer effect on service path: {}",
                    entry.kind
                ));
            }
            _ => {}
        }
    }
    let expected = EventKind::ALL
        .iter()
        .cloned()
        .collect::<std::collections::HashSet<_>>();
    if registered != expected {
        return Err(
            "active Event effect slots do not exactly cover the canonical registry".to_owned(),
        );
    }
    Ok(())
}

/// Mandatory in release builds too. An SDK registry addition without an
/// explicitly reviewed cache handler or refusal prevents service startup.
pub fn assert_effect_dispatch_contract() {
    std::sync::LazyLock::force(&APPLY_REGISTRY);
}

pub(crate) fn apply_service_effect(
    state: &mut ProjectionState,
    kind: &EventKind,
    operation: &Operation,
    hlc: &ServerHlc,
) -> ProjectionEffect {
    assert_effect_dispatch_contract();
    match EFFECT_MANIFEST
        .iter()
        .find(|entry| entry.kind == kind.as_str())
        .map(|entry| entry.slot)
    {
        Some(CacheSlot::Service(handler)) => handler(state, operation, hlc),
        _ => ProjectionEffect::Rejected {
            reason: "unregistered_private_event_effect".to_owned(),
        },
    }
}

fn apply_durable_fact_dispatch(
    _state: &mut ProjectionState,
    operation: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    ProjectionEffect::DurableFactRetained {
        kind: operation.event_kind.clone(),
        event_id: operation.context.event_id.to_string(),
    }
}

fn apply_message_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_message(op, op.created_at)
}
fn apply_message_revise_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_message_revise(op, op.created_at)
}
fn apply_redaction_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_redaction(op)
}
fn apply_reaction_add_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_reaction_add(op, op.created_at)
}
fn apply_reaction_remove_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_reaction_remove(op)
}
fn apply_rsvp_set_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_rsvp_set(op, op.created_at)
}
fn apply_pin_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_pin(op, op.created_at)
}
fn apply_relation_create_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_relation_create(op, op.created_at)
}
fn apply_relation_update_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_relation_update(op, op.created_at, hlc)
}
fn apply_relation_delete_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_relation_delete(op)
}
fn apply_membership_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_membership(op, projection_received_at(op))
}
fn apply_invite_third_party_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_invite_third_party(op, op.created_at)
}
fn apply_invite_claim_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_invite_claim(op, op.created_at)
}
fn apply_realm_create_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_lifecycle(op, op.created_at, arkret_wire::EventKind::RealmCreate)
}
fn apply_identity_resolution_update_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_identity_resolution_update(op)
}
fn apply_realm_profile_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_lifecycle(op, op.created_at, arkret_wire::EventKind::RealmProfile)
}
fn apply_realm_archive_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_lifecycle(op, op.created_at, arkret_wire::EventKind::RealmArchive)
}
fn apply_realm_restore_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_lifecycle(op, op.created_at, arkret_wire::EventKind::RealmRestore)
}
fn apply_realm_freeze_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_lifecycle(op, op.created_at, arkret_wire::EventKind::RealmFreeze)
}
fn apply_realm_unfreeze_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_lifecycle(op, op.created_at, arkret_wire::EventKind::RealmUnfreeze)
}
fn apply_realm_tombstone_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_lifecycle(op, op.created_at, arkret_wire::EventKind::RealmTombstone)
}
fn apply_realm_destroy_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_lifecycle(op, op.created_at, arkret_wire::EventKind::RealmDestroy)
}
fn apply_realm_owner_transfer_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_authority_transition(op, arkret_wire::EventKind::RealmOwnerTransfer)
}
fn apply_realm_governance_station_change_dispatch(
    _state: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    let payload = match serde_json::from_value::<
        arkret_models_collaboration::events_payloads::RealmGovernanceStationChangePayload,
    >(op.payload.clone())
    {
        Ok(payload) => payload,
        Err(_) => {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
            };
        }
    };
    ProjectionEffect::AuthorityCommitEffectAccepted {
        event_id: op.context.event_id.to_string(),
        new_governance_station_id: payload.new_governance_station_id,
    }
}
fn apply_realm_authority_reset_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_authority_transition(op, arkret_wire::EventKind::RealmAuthorityReset)
}
fn apply_realm_set_default_strand_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_set_default_strand(op, op.created_at)
}
fn apply_space_container_create_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_space_container_create(op, op.created_at)
}
fn apply_space_container_update_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_space_container_update(op, op.created_at)
}
fn apply_space_container_parent_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_space_container_parent(op, op.created_at)
}
fn apply_space_container_archive_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_space_container_lifecycle(
        op,
        op.created_at,
        SpaceContainerLifecycleTransition::Archive,
    )
}
fn apply_space_container_restore_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_space_container_lifecycle(
        op,
        op.created_at,
        SpaceContainerLifecycleTransition::Restore,
    )
}
fn apply_space_container_tombstone_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_space_container_lifecycle(
        op,
        op.created_at,
        SpaceContainerLifecycleTransition::Tombstone,
    )
}
fn apply_strand_create_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_strand_create(op, op.created_at)
}
fn apply_strand_update_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_strand_update(op, op.created_at)
}
fn apply_strand_archive_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_strand_lifecycle(op, op.created_at, ObjectLifecycleTransition::Archive)
}
fn apply_strand_restore_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_strand_lifecycle(op, op.created_at, ObjectLifecycleTransition::Restore)
}
fn apply_strand_stage_set_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_strand_stage_set(op, op.created_at)
}
fn apply_morph_stage_set_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_morph_stage_set(op, op.created_at)
}
fn apply_strand_position_touch_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_strand_position_touch(op, op.created_at)
}
fn apply_strand_track_touch_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_strand_track_touch(op, op.created_at)
}

fn apply_morph_create_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_morph_create(op, op.created_at)
}
fn apply_morph_update_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_morph_update(op, op.created_at)
}
fn apply_morph_archive_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_morph_lifecycle(op, op.created_at, ObjectLifecycleTransition::Archive)
}
fn apply_morph_restore_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_morph_lifecycle(op, op.created_at, ObjectLifecycleTransition::Restore)
}
// AKP-0007 — Circle dispatch wrappers.
fn apply_circle_create_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_circle_create(op, op.created_at)
}
fn apply_circle_update_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_circle_update(op, op.created_at)
}
fn apply_circle_archive_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_circle_lifecycle(op, op.created_at, CircleLifecycleState::Archived)
}
fn apply_circle_restore_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_circle_lifecycle(op, op.created_at, CircleLifecycleState::Active)
}
fn apply_circle_tombstone_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_circle_lifecycle(op, op.created_at, CircleLifecycleState::Tombstoned)
}
fn apply_circle_member_state_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_circle_member_state(op, projection_received_at(op))
}

fn apply_realm_history_access_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_history_access(op)
}

fn apply_circle_history_access_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_circle_history_access(op)
}

fn apply_sidecar_create_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_sidecar_create(op)
}

fn apply_sidecar_context_attach_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_sidecar_context_attach(op)
}

fn apply_sidecar_exchange_control_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_sidecar_exchange_control(op)
}

fn apply_applet_registration_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_applet_registration(op, op.created_at)
}
fn apply_applet_discovery_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_applet_discovery(op, op.created_at)
}

// REDU-1 (R3 spec-sync 2026-05-27, arkret-spec b47ff6ec) — transition-state model
// dispatch for `ak.agent.{pause,resume,deactivate}`. Bottom = `Reject`;
// `Deactivated` is terminal (no transition out, no resume after).
fn apply_agent_pause_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_agent_lifecycle(op, AgentLifecycleState::Paused)
}
fn apply_agent_resume_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_agent_lifecycle(op, AgentLifecycleState::Active)
}
fn apply_agent_deactivate_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_agent_lifecycle(op, AgentLifecycleState::Deactivated)
}

/// Dispatch for `ak.agent.key.authorize`. Pairing records the authorized key
/// without changing independent Realm grants.
fn apply_agent_key_authorize_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_agent_key_authorize(op)
}

/// Dispatch for `ak.agent.action_approve`: a durable confirmation fact in
/// the target Realm. The request it confirms is controller-private state that
/// no shared reducer holds (actor-private-effects.md §3.2); the reducer only
/// indexes the confirmation by the complete `approved_event_id` whose nonce it
/// allocated, first confirmation wins.
fn apply_agent_action_approve_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    let Some(approved_event_id) = op
        .payload
        .get("approved_event_id")
        .and_then(Value::as_str)
        .filter(|value| arkret_wire::EventId::new(*value).is_ok())
    else {
        return ProjectionEffect::Rejected {
            reason: "agent_action_approval_missing_event_id".to_owned(),
        };
    };
    s.agent_action_confirmations
        .entry(approved_event_id.to_owned())
        .or_insert_with(|| op.context.event_id.clone());
    ProjectionEffect::DurableFactRetained {
        kind: EventKind::AgentActionApprove,
        event_id: op.context.event_id.to_string(),
    }
}

/// AKP-0008 §4.11 — dispatch for `ak.agent.key.revoke`.
fn apply_agent_key_revoke_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_agent_key_revoke(op)
}

/// MID-1..6 (R3.1/R3.2, arkret-spec @ b56cab1) — reducer-side dispatch for
/// `ak.member.identity.update`. The full ordered-log projection +
/// per-actor effective-set / `member_display_state_digest` materialization
/// happens on `AppState::member_identity` (see
/// `routing::events::projection::project_member_identity_update`);
/// `ProjectionState` itself doesn't hold a MemberIdentity facet, so this
/// dispatcher only emits the lifecycle effect.
fn apply_member_identity_update_dispatch(
    _s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    if op
        .payload
        .get("segment")
        .and_then(Value::as_str)
        .is_some_and(|segment| segment != "member_identity")
    {
        return ProjectionEffect::Rejected {
            reason: arkret_wire::ReasonCode::MEMBER_IDENTITY_UNKNOWN_SEGMENT.to_owned(),
        };
    }
    let Ok(payload) = serde_json::from_value::<MemberIdentityUpdatePayload>(op.payload.clone())
    else {
        return ProjectionEffect::Rejected {
            reason: "member_identity_update_missing_subject".to_owned(),
        };
    };
    ProjectionEffect::MemberIdentityProjected {
        realm_id: payload.realm_id.to_string(),
        actor_id: payload.member_id.to_string(),
        segment: "member_identity".to_owned(),
        event_id: op.operation_id.to_string(),
    }
}

/// Dispatch for the four closed Realm-bootstrap facet kinds. Each writes
/// exactly one Realm-singleton facet write-once; `apply_realm_bootstrap_facet`
/// rejects every other kind with `out_of_order_bootstrap`, so only these four
/// may be registered here.
fn apply_realm_bootstrap_facet_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_bootstrap_facet(op)
}

/// Dispatch for `ak.realm.policy_bundle`; cell family is
/// `ak.component.realm.policy_bundle.v1`.
fn apply_realm_policy_bundle_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_policy_bundle(op)
}

fn apply_realm_search_policy_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_search_policy(op)
}

/// Dispatch for `ak.scope.read_receipt_policy`; writes the
/// `scope_read_receipt_policy` current result named by
/// `discovery/read-receipts.md` section 2.5.
fn apply_scope_read_receipt_policy_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_scope_read_receipt_policy(op)
}

fn apply_realm_preview_policy_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_preview_policy(op)
}

/// Dispatch for `ak.realm.media_service`; cell family is
/// `ak.component.realm.media_service.v1`.
fn apply_realm_media_service_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_media_service(op)
}

/// Dispatch for `ak.call.create`; CallId is derived from the accepted Event.
fn apply_call_create_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_call_create(op)
}

/// Dispatch for `ak.call.state`; cell family is
/// `ak.component.call.state.v1` (`cell_subject = payload.call_id`).
fn apply_call_state_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_call_state(op)
}

fn apply_call_recording_start_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_call_recording_start(op)
}

/// R3.1 — dispatch for `ak.realm.link`. Projects the typed link payload
/// into the `ak.component.realm.link.v1` transition cell + structured
/// `realm_links` / `realm_links_inbound` caches.
fn apply_realm_link_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_link(op, op.created_at)
}

/// SOL-ORG-02 — dispatch for `ak.realm.organization`. Projects the
/// organization-authorized Realm relationship statement (registered state model cell
/// keyed by `(organization_id, relationship)` + structured cache) after the
/// SDK organization-side verifier passes.
fn apply_realm_organization_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_organization(op, op.created_at)
}

fn apply_policy_set_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_policy_set(op)
}

fn apply_policy_action_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_policy_action(op)
}

/// P2 — dispatch for `ak.moderation.decision`. Projects the decision snapshot
/// as an or_set add into the `ak.component.moderation_state.v1` cell keyed by
/// `payload.target_ref`.
fn apply_moderation_decision_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_moderation_decision(op)
}

/// P2 — dispatch for `ak.moderation.decision.lift`. Projects an observed-
/// remove / supersede on the moderation_state target cell, marking the
/// `payload.decision_ref` decision lifted.
fn apply_moderation_decision_lift_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_moderation_decision_lift(op, op.created_at)
}

/// Derive implemented shared cache handlers from the validated manifest.
/// Deliberately unsupported slots remain refusals; their existence does not
/// claim a durable accepting writer or an implemented private service.
pub fn default_apply_registry() -> std::collections::HashMap<EventKind, ApplyFn> {
    validate_effect_manifest(EFFECT_MANIFEST).expect("invalid Event effect dispatch ownership");
    EFFECT_MANIFEST
        .iter()
        .filter_map(|entry| match entry.slot {
            CacheSlot::Shared(handler) => Some((EventKind::from(entry.kind), handler)),
            _ => None,
        })
        .collect()
}

pub(crate) static APPLY_REGISTRY: std::sync::LazyLock<
    std::collections::HashMap<EventKind, ApplyFn>,
> = std::sync::LazyLock::new(default_apply_registry);

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use arkret_wire::EventKind;

    use super::default_apply_registry;

    #[test]
    fn effect_manifest_exactly_covers_canonical_owners_and_cache_handlers() {
        super::validate_effect_manifest(super::EFFECT_MANIFEST).unwrap();
        let registry = default_apply_registry();
        assert_eq!(
            registry.len(),
            super::EFFECT_MANIFEST
                .iter()
                .filter(|entry| matches!(entry.slot, super::CacheSlot::Shared(_)))
                .count()
        );
        for kind in [
            EventKind::SelfModerationReport,
            EventKind::MlsGenesis,
            EventKind::MlsCommit,
        ] {
            let entry = super::EFFECT_MANIFEST
                .iter()
                .find(|entry| entry.kind == kind.as_str())
                .unwrap();
            assert_eq!(
                entry.owner,
                arkret_wire::EventEffectOwnership::TypedResultWriter
            );
            assert!(matches!(entry.slot, super::CacheSlot::Shared(_)));
            assert!(!kind.effect_descriptor().unwrap().result_families.is_empty());
        }
    }

    #[test]
    fn effect_manifest_rejects_missing_extra_and_duplicate_slots() {
        let mut entries = super::EFFECT_MANIFEST.to_vec();
        entries.pop();
        assert!(
            super::validate_effect_manifest(&entries)
                .unwrap_err()
                .contains("exactly cover")
        );
        let mut entries = super::EFFECT_MANIFEST.to_vec();
        entries.push(entries[0]);
        assert!(
            super::validate_effect_manifest(&entries)
                .unwrap_err()
                .contains("duplicate")
        );
        let mut entries = super::EFFECT_MANIFEST.to_vec();
        entries[0].kind = "ak.unregistered.effect";
        assert!(
            super::validate_effect_manifest(&entries)
                .unwrap_err()
                .contains("unregistered")
        );
    }

    #[test]
    fn effect_manifest_rejects_owner_scope_and_execution_path_mutations() {
        let mut entries = super::EFFECT_MANIFEST.to_vec();
        let index = entries
            .iter()
            .position(|entry| entry.kind == EventKind::MessageCreate.as_str())
            .unwrap();
        entries[index].owner = arkret_wire::EventEffectOwnership::DurableFactNoCurrentProjection;
        assert!(
            super::validate_effect_manifest(&entries)
                .unwrap_err()
                .contains("owner mismatch")
        );
        let mut entries = super::EFFECT_MANIFEST.to_vec();
        entries[index].scope = arkret_wire::EventWireScope::ActorPrivateEvent;
        assert!(
            super::validate_effect_manifest(&entries)
                .unwrap_err()
                .contains("scope mismatch")
        );
        let mut entries = super::EFFECT_MANIFEST.to_vec();
        entries[index].slot = super::CacheSlot::Service(super::apply_message_dispatch);
        assert!(
            super::validate_effect_manifest(&entries)
                .unwrap_err()
                .contains("shared reducer effect")
        );
        let mut entries = super::EFFECT_MANIFEST.to_vec();
        let private = entries
            .iter()
            .position(|entry| entry.kind == EventKind::AccountDataSet.as_str())
            .unwrap();
        entries[private].slot = super::CacheSlot::Shared(super::apply_message_dispatch);
        assert!(
            super::validate_effect_manifest(&entries)
                .unwrap_err()
                .contains("private/service effect")
        );
    }

    #[test]
    fn effect_manifest_refusal_paths_do_not_mutate_product_state() {
        let mut state = super::ProjectionState::new();
        state
            .realm_join_rules
            .insert("existing-realm".to_owned(), "closed".to_owned());
        let baseline = format!("{state:?}");
        let hlc = super::ServerHlc::new("effect-refusal");
        for kind in [
            EventKind::AccountDataSet,
            EventKind::InviteCreate,
            EventKind::Unknown("ak.unregistered.effect".to_owned()),
        ] {
            assert!(matches!(
                state.apply(&operation(&kind), &hlc),
                super::ProjectionEffect::Rejected { .. }
            ));
            assert_eq!(format!("{state:?}"), baseline);
        }
        // A private Event forced onto the shared cache path still cannot
        // dispatch its owning private service or mutate Realm state.
        assert!(matches!(
            state.apply_projected(&operation(&EventKind::AccountDataSet), &hlc),
            super::ProjectionEffect::Rejected { .. }
        ));
        assert_eq!(format!("{state:?}"), baseline);
    }

    #[test]
    fn effect_manifest_service_ack_uses_its_registered_durable_owner() {
        let kind = EventKind::AuditErasureReceipt;
        assert_eq!(
            kind.effect_ownership(),
            Some(arkret_wire::EventEffectOwnership::DurableFactNoCurrentProjection)
        );
        let mut state = super::ProjectionState::new();
        let baseline = format!("{state:?}");
        assert!(
            matches!(state.apply(&operation(&kind), &super::ServerHlc::new("service-owner")), super::ProjectionEffect::DurableFactRetained { kind: effect_kind, .. } if effect_kind == kind)
        );
        assert_eq!(format!("{state:?}"), baseline);
    }

    fn operation(kind: &EventKind) -> arkret_event_draft::ProjectedEventOperation {
        arkret_event_draft::test_support::raw_projected_operation(
            arkret_identifiers::OperationId::new(format!("ak:operation:{}", uuid::Uuid::now_v7()))
                .unwrap(),
            arkret_identifiers::RealmId::new(
                "ak:realm:AW2XhEBfjbMHqDBzRGwBXCaBZtSGUQTBe5CkC4pjU8O2",
            )
            .unwrap(),
            kind.as_str(),
            serde_json::json!({}),
        )
    }

    #[test]
    fn member_identity_dispatch_preserves_the_complete_actor() {
        let realm_id = arkret_identifiers::RealmId::new(
            "ak:realm:AXqIXbu56hFXteZXtkBsqJxy_puV4mhSv1U0ZkUldxAL",
        )
        .unwrap();
        let mut actors = Vec::new();
        for station in [
            "ak:did_core:web:first.example",
            "ak:did_core:web:second.example",
        ] {
            let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                arkret_wire::DidCoreId::new(station).unwrap(),
            ));
            let mut operation = arkret_event_draft::test_support::raw_projected_operation(
                arkret_identifiers::OperationId::new(
                    "ak:operation:01904100-0000-7000-8000-57d7d85564c5",
                )
                .unwrap(),
                realm_id.clone(),
                EventKind::MemberIdentityUpdate.as_str(),
                serde_json::json!({
                    "realm_id": realm_id,
                    "member_id": actor,
                    "segment": "member_identity",
                    "identity_payload": { "encrypted_content": {} },
                }),
            );
            let mut state = super::ProjectionState::default();
            let hlc = super::ServerHlc::new("member-identity-test");
            let super::ProjectionEffect::MemberIdentityProjected { actor_id, .. } =
                super::apply_member_identity_update_dispatch(&mut state, &operation, &hlc)
            else {
                panic!("complete Actor must project")
            };
            assert_eq!(actor_id, actor.to_string());
            actors.push(actor_id);
            operation.payload["actor_id"] = serde_json::json!(actor.signing_principal_id());
            assert!(matches!(
                super::apply_member_identity_update_dispatch(&mut state, &operation, &hlc),
                super::ProjectionEffect::Rejected { .. },
            ));
        }
        assert_ne!(actors[0], actors[1]);
    }

    #[test]
    fn apply_registry_contains_only_active_reducer_inputs() {
        let actual = default_apply_registry().into_keys().collect::<HashSet<_>>();
        assert!(actual.iter().all(EventKind::is_reducer_input));
        assert!(actual.contains(&EventKind::AppletBridgeError));
        assert!(actual.contains(&EventKind::AuditAccessed));
        assert!(actual.contains(&EventKind::RealmGovernanceStationChange));
    }

    #[test]
    fn realm_actor_typed_writers_cannot_become_durable_fact_noops() {
        let registry = default_apply_registry();
        let mut state = super::ProjectionState::default();
        let baseline = format!("{state:?}");
        let hlc = super::ServerHlc::new("realm-actor-writer-test");
        for kind in [
            EventKind::RealmActorCreate,
            EventKind::RealmActorControlUpdate,
            EventKind::RealmActorManagerChange,
            EventKind::RealmActorStatusSet,
            EventKind::RealmActorRecoverySet,
            EventKind::RealmActorRecoveryBegin,
            EventKind::RealmActorControlReset,
            EventKind::RealmActorDevicesReset,
        ] {
            assert!(kind.is_reducer_input());
            let descriptor = kind.effect_descriptor().unwrap();
            assert_eq!(
                descriptor.ownership,
                super::EventEffectOwnership::TypedResultWriter
            );
            assert!(!descriptor.result_families.is_empty());
            assert!(!registry.contains_key(&kind));
            assert!(matches!(
                state.apply_projected(&operation(&kind), &hlc),
                super::ProjectionEffect::Rejected { .. }
            ));
            assert_eq!(format!("{state:?}"), baseline);
        }
    }

    #[test]
    fn durable_fact_owners_have_an_explicit_non_projection_effect() {
        let mut state = super::ProjectionState::default();
        let hlc = super::ServerHlc::new("durable-fact-owner-test");
        for kind in [
            EventKind::AppletBridgeError,
            EventKind::AuditAccessed,
            EventKind::SelfModerationReport,
        ] {
            let effect = state.apply_projected(&operation(&kind), &hlc);
            assert!(
                matches!(
                    effect,
                    super::ProjectionEffect::DurableFactRetained {
                        kind: effect_kind,
                        ..
                    } if effect_kind == kind
                ),
                "{kind} must be acknowledged as a durable fact"
            );
        }
    }

    #[test]
    fn unimplemented_reducer_inputs_fail_closed_instead_of_becoming_noops() {
        let registry = default_apply_registry();
        let kind = EventKind::InviteCreate;
        assert!(kind.is_reducer_input());
        assert!(!registry.contains_key(&kind));
        let mut state = super::ProjectionState::default();
        let effect = state.apply_projected(
            &operation(&kind),
            &super::ServerHlc::new("missing-effect-owner-test"),
        );
        assert!(matches!(
            effect,
            super::ProjectionEffect::Rejected { ref reason }
                if reason == "unregistered_reducer_event_kind"
        ));
    }
}
