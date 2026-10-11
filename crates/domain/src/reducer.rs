//! Deterministic product projection over authority-ordered Events.
//!
//! Producers do not declare predecessors. Ordering is supplied exclusively by
//! the current governance Station's [`arkret_wire::RealmCommit`]: the Realm,
//! each Circle and each Sidecar carry independent linear streams, and this
//! module never derives order from a producer Event or from a peer-merge
//! graph. [`CommitStreamProjection`] owns the per-stream succession check;
//! [`ProjectionState`] folds the accepted [`arkret_wire::CommittedEventFullView`] into the
//! product projection once that check passes.

// Independent per-stream head tracking for accepted committed Events.
mod commit_stream;
// Domain coordinates for the Station's local product projection.
mod facets;

// Per-kind product projection helpers (additional `impl ProjectionState`
// blocks) split out of this file.
mod apply_capability;
mod apply_history_access;
mod apply_identity_resolution;
mod apply_invites;
mod apply_messages;
mod apply_moderation;
mod apply_objects;
mod apply_policy_current;
mod apply_realm_lifecycle;
mod apply_realm_organization;
mod apply_realm_policy;
mod apply_relations;
mod apply_space_container;
mod capability_helpers;
pub mod mls;
pub mod realm_links;
// Top-level projection types, free helpers, the dispatch registry, and the
// `ProjectionState` struct plus its inline impl.
mod dispatch;
mod effects;
mod message_helpers;
mod patch_helpers;
mod policy_validation;
mod projection_state;
mod projections;

// Shared imports that the sibling `impl ProjectionState` blocks reach through
// `use super::*;`.
use std::collections::{BTreeMap, BTreeSet};

pub use apply_objects::DeferredParentMembershipAdmission;
pub use apply_realm_policy::{
    join_policy_declares_an_automatic_gate, join_rule_requires_an_automatic_gate,
};
use arkret_event_draft::ProjectedEventOperation as Operation;
use arkret_models_collaboration::agent_operations::AgentLifecycleState;
pub(crate) use capability_helpers::*;
pub use commit_stream::{CommitStreamEffect, CommitStreamProjection};
pub(crate) use dispatch::{APPLY_REGISTRY, upsert_realm_link};
pub use dispatch::{ApplyFn, assert_effect_dispatch_contract, default_apply_registry};
pub use effects::{MlsEffect, ProjectionEffect};
pub(crate) use effects::{ObjectLifecycleTransition, SpaceContainerLifecycleTransition};
pub use facets::{FacetRef, SettledFacet, facet};
pub(crate) use message_helpers::*;
pub use message_helpers::{
    message_id_from_event_id, message_id_from_payload_or_event_id, message_redaction_target_ref,
};
pub(crate) use patch_helpers::*;
pub use patch_helpers::{
    REALM_DESTROY_FANOUT_WINDOW_DAYS, morph_document_body, validate_patch_semantic_safety,
};
pub use policy_validation::validate_join_policy_payload;
pub(crate) use policy_validation::*;
pub use projection_state::ProjectionState;
pub(crate) use projections::space_container_id_from_payload;
pub use projections::{
    AppletProjection, CircleLifecycleState, CircleMembershipState, CircleProjection,
    ColandMembershipState, ColandRealmState, ColandRelationState, DocumentVersionProjection,
    InviteProjection, KeyPackageLifetimeProjection, MessageState, MlsKeyPackageProjection,
    MorphProjection, ObjectLifecycleState, PendingReplayEntry, PinProjection, PollState,
    ProjectedMessageView, ReactionState, RealmLinkState, RealmOrganizationStatementState,
    RedactionCellValue, RelationCurrentResultProjection, RsvpProjection, SidecarContextProjection,
    SidecarProjection, SpaceContainerLifecycleState, SpaceContainerProjection, StrandProjection,
    object_stage_from_wire_value, object_stage_wire_value,
};
use serde_json::Value;

pub use crate::hlc::ServerHlc;

#[cfg(test)]
mod tests;
