//! Space/Strand current and Morph accepted-source reads retain one caller
//! disclosure cut through the physical response-body handoff. Product-private
//! Relation reads remain separate from these registered native read surfaces.
//!
//! These endpoints let inkson (and other clients) re-hydrate the
//! optimistic Archive / Restore state after a page refresh, so a
//! `ak.space.archive` accepted by the server doesn't appear "unarchived"
//! again when the kanban view re-mounts.
//!
//! - `GET /_arkret/self/realms/{realm_id}/spaces` — canonical projection endpoint listing Space
//!   containers in a Realm scope, with `state` ∈ {active, archived, tombstoned} (spec
//!   `common-fields.md §5.1`).
//! - `GET /_arkret/self/realms/{realm_id}/strands` — same for Strands (state ∈ {active, archived,
//!   redacted}).
//! - `GET /_arkret/self/realms/{realm_id}/morphs` — same for Morphs (same enum as Strands).
//!
//! All three endpoints are authenticated. Resource visibility check
//! piggy-backs on `realm_id_accessible` so a non-member can't probe
//! Space-container / Strand / Morph lifecycle state via this surface.
//!
//! Handlers use the SDK response DTOs so generated OpenAPI stays aligned with
//! the spec artifact registry.
//!
//! Terminal-state visibility filter: each endpoint accepts an optional
//! `include_terminal=true|false` query parameter. Default is `false`:
//!   - Space container: tombstoned rows excluded.
//!   - Strand / Morph: redacted rows excluded.
//!
//! Spec rationale: tombstoned / redacted are unrecoverable terminals per
//! common-fields.md §5.1; clients hydrating a kanban view shouldn't see them by
//! default. Explicit `include_terminal=true` returns the full set for audit /
//! debugging UIs.

use std::collections::{BTreeMap, BTreeSet};

use arkret_identifiers::{MorphId, RealmId, RelationId};
#[cfg(test)]
use arkret_models_collaboration::objects::query_projection::ProjectionAssignedToRelation;
use arkret_models_collaboration::objects::query_projection::{
    DocumentMorphProjectionOutcome, ProjectionMorphList, ProjectionMorphRow, ProjectionSpaceList,
    ProjectionStrandList, ReferenceProjectionState,
};
use arkret_models_collaboration::objects::relation::RelationEndpoint;
use arkret_wire::ObjectState;
use chrono::{DateTime, Utc};
use coland_domain::reducer::{
    ColandRelationState, MessageState, MorphProjection, ObjectLifecycleState, ProjectionState,
    SpaceContainerLifecycleState,
};
use coland_http::error::AppError;
use coland_http::result::{GuardedJsonResult, JsonResult, guarded_json_ok, json_ok};
use coland_services::identity::SessionIdentityState as SessionRecord;
use coland_services::projection::morph_document_body;
use salvo::oapi::extract::{PathParam, QueryParam};
use salvo::prelude::*;
use serde_json::{Value, json};

use super::{realm_history_access, realm_id_accessible};
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;

pub(super) fn protocol_router() -> Router {
    Router::new()
        .push(Router::with_path("realms/{realm_id}/spaces").get(list_space_container_projections))
        .push(Router::with_path("realms/{realm_id}/strands").get(list_strand_projections))
        .push(Router::with_path("realms/{realm_id}/morphs").get(list_morph_projections))
        .push(Router::with_path("realms/{realm_id}/morphs/{morph_id}").get(get_document_projection))
}

/// Product-private relation read surface (`/_coland/self/relations`).
/// This implementation-only read exposes the active edge sets needed by
/// product invariant assertions. Strand state uses the registered signed
/// Snapshot/current readers instead of an independent mutable projection GET.
pub(super) fn local_router() -> Router {
    Router::new().push(Router::with_path("relations").get(list_relation_projections))
}

// ── Helpers ────────────────────────────────────────────────────────────

/// Terminal-state check for Strand / Morph. Mirror of
/// `ObjectLifecycleState::is_terminal` but inlined here so the
/// `filter` chain in the handlers reads as
/// `!is_object_terminal(f.state)` for symmetry with the Space-container
/// check (`state != SpaceContainerLifecycleState::Tombstoned`).
fn is_object_terminal(state: ObjectLifecycleState) -> bool {
    state.is_terminal()
}

fn validate_realm_id(realm_id: String) -> Result<String, AppError> {
    RealmId::new(realm_id.clone())
        .map_err(|_| AppError::param_invalid("invalid realm_id format"))?;
    Ok(realm_id)
}

fn projection_object_state(state: ObjectLifecycleState) -> ObjectState {
    match state {
        ObjectLifecycleState::Active => ObjectState::Active,
        ObjectLifecycleState::Archived => ObjectState::Archived,
        ObjectLifecycleState::Redacted => ObjectState::Redacted,
    }
}

fn parse_projection_id<T>(value: &str, field: &str) -> Result<T, AppError>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    value
        .parse::<T>()
        .map_err(|_| AppError::internal(format!("invalid {field} in projection state")))
}

fn parse_projection_actor(value: &str, field: &str) -> Result<arkret_wire::ActorId, AppError> {
    serde_json::from_str(value)
        .map_err(|_| AppError::internal(format!("invalid {field} in projection state")))
}

/// Parent lifecycle for live structural navigation, from durable current only.
pub(crate) async fn structural_navigation_available(
    state: &AppState,
    realm_id: &str,
) -> Result<bool, AppError> {
    let realm = parse_projection_id::<arkret_wire::RealmId>(realm_id, "Realm id")?;
    let material = state
        .authority_commits()
        .realm_state_snapshot_material(&realm)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    Ok(material.is_some_and(|snapshot| {
        !snapshot.current_state_entries.iter().any(|row| {
            matches!(
                row,
                arkret_wire::TypedCurrentRow::Value {
                    selector: arkret_wire::CurrentSelector::RealmTombstone,
                    ..
                }
            )
        })
    }))
}

fn total_count(len: usize) -> Result<u64, AppError> {
    u64::try_from(len).map_err(|_| AppError::internal("projection row count overflow"))
}

fn projection_row_visible_to_session(
    state: &AppState,
    projection: &ProjectionState,
    realm_id: &str,
    session: &SessionRecord,
    sender: &str,
    created_at: DateTime<Utc>,
    scope_circle_id: Option<&str>,
    history_access: &str,
) -> bool {
    let Ok(actor) =
        crate::routing::identity::session_actor::session_actor_from_credential(state, session)
    else {
        return false;
    };
    let actor_key = actor.to_string();
    if sender == actor_key {
        return true;
    }
    if !projection_realm_history_allows(projection, realm_id, &actor, history_access, created_at) {
        return false;
    }
    scope_circle_id.is_none_or(|circle_id| {
        projection.circle_scope_visible_to_actor_at(circle_id, &actor_key, created_at)
    })
}

#[cfg(test)]
/// Current object projections are a baseline, not an Event-history window.
///
/// `history_access=since_join` limits historical Event bodies and old object
/// revisions. It must not hide the current Space/Strand row from an active
/// Realm member merely because the object was created before that member
/// joined. Circle-scoped rows still require current Circle visibility.
fn current_projection_scope_visible_to_actor(
    projection: &ProjectionState,
    actor: &arkret_wire::ActorId,
    scope_circle_id: Option<&str>,
) -> bool {
    scope_circle_id.is_none_or(|circle_id| {
        projection.circle_scope_visible_to_actor(circle_id, &actor.to_string())
    })
}

fn projection_realm_history_allows(
    projection: &ProjectionState,
    realm_id: &str,
    actor: &arkret_wire::ActorId,
    history_access: &str,
    created_at: DateTime<Utc>,
) -> bool {
    let Some(member) = projection.member(realm_id, &actor.to_string()) else {
        return false;
    };
    if member.state != "join" {
        return false;
    }
    match history_access {
        "all_history_for_current_members" => true,
        "since_join" => created_at >= member.joined_at,
        _ => false,
    }
}

#[cfg(test)]
fn strand_assigned_to_relations(
    projection: &ProjectionState,
    strand_id: &str,
) -> Result<Vec<ProjectionAssignedToRelation>, AppError> {
    let mut relation_refs = projection
        .relations
        .values()
        .filter(|relation| relation.is_active())
        .filter(|relation| relation.relation_kind == "assigned_to")
        .filter(|relation| relation.from_object_ref() == Some(strand_id))
        .filter_map(|relation| {
            relation
                .to_ref
                .as_ref()
                .and_then(RelationEndpoint::as_actor_id)
                .map(|actor_id| (actor_id.clone(), relation.relation_id.clone()))
        })
        .collect::<Vec<_>>();
    relation_refs.sort();
    relation_refs
        .into_iter()
        .map(|(actor_id, relation_id)| {
            Ok(ProjectionAssignedToRelation {
                relation_id: parse_projection_id::<RelationId>(
                    &relation_id,
                    "assigned_to_relations.relation_id",
                )?,
                actor_id,
            })
        })
        .collect()
}

// ── Handlers ───────────────────────────────────────────────────────────

fn document_projection_document(
    morph: &MorphProjection,
    body: Value,
) -> Result<arkret_models_collaboration::objects::query_projection::DocumentMorphProjection, AppError>
{
    parse_projection_id::<MorphId>(&morph.morph_id, "document.morph_id")?;
    parse_projection_id::<RealmId>(&morph.realm_id, "document.realm_id")?;
    let created_by = parse_projection_actor(&morph.created_by, "document.created_by")?;
    let updated_by = morph
        .updated_by
        .as_deref()
        .map(|actor| parse_projection_actor(actor, "document.updated_by"))
        .transpose()?;

    let mut document = serde_json::Map::new();
    document.insert("morph_id".to_owned(), Value::String(morph.morph_id.clone()));
    document.insert("realm_id".to_owned(), Value::String(morph.realm_id.clone()));
    document.insert(
        "morph_kind".to_owned(),
        Value::String(morph.morph_kind.clone()),
    );
    if let Some(title) = &morph.title {
        document.insert("title".to_owned(), Value::String(title.clone()));
    }
    document.insert(
        "state".to_owned(),
        json!(projection_object_state(morph.state)),
    );
    if let Some(state_changed_at) = morph.state_changed_at {
        document.insert(
            "state_changed_at".to_owned(),
            Value::String(arkret_canonical::format_timestamp_canonical(
                state_changed_at,
            )),
        );
    }
    document.insert("fields".to_owned(), json!(morph.fields));
    document.insert("body".to_owned(), body);
    document.insert("schema_refs".to_owned(), json!(morph.schema_refs));
    // The stored projection indexes facet parameters by facet name; the
    // document view schema (`view.schema.json` document_morph_projection) is
    // the ordered facet-name list.
    document.insert(
        "facets".to_owned(),
        json!(morph.facets.keys().collect::<Vec<_>>()),
    );
    document.insert("created_by".to_owned(), json!(created_by));
    document.insert(
        "created_at".to_owned(),
        Value::String(arkret_canonical::format_timestamp_canonical(
            morph.created_at,
        )),
    );
    if let Some(updated_by) = updated_by {
        document.insert("updated_by".to_owned(), json!(updated_by));
    }
    if let Some(updated_at) = morph.updated_at {
        document.insert(
            "updated_at".to_owned(),
            Value::String(arkret_canonical::format_timestamp_canonical(updated_at)),
        );
    }
    serde_json::from_value(Value::Object(document))
        .map_err(|error| AppError::internal(format!("invalid document projection: {error}")))
}

fn document_projection_versions(morph: &MorphProjection) -> Vec<BTreeMap<String, Value>> {
    morph
        .versions
        .iter()
        .map(|version| {
            let author = if version.author.trim().is_empty() {
                morph.created_by.as_str()
            } else {
                version.author.as_str()
            };
            json_object(json!({
                "version_id": version.version_id,
                "event_id": version.event_id,
                "author": author,
                "created_at": arkret_canonical::format_timestamp_canonical(version.created_at),
                "body_digest": version.body_digest,
                "body": version.body,
            }))
        })
        .collect()
}

fn document_relation_visible_to_actor(
    projection: &ProjectionState,
    relation: &ColandRelationState,
    actor: &arkret_wire::ActorId,
) -> bool {
    relation.scope_circle_id.as_deref().is_none_or(|circle_id| {
        projection.circle_scope_visible_to_actor_at(
            circle_id,
            &actor.to_string(),
            relation.created_at,
        )
    })
}

#[derive(Clone, Debug)]
struct DocumentRelationSnapshot {
    relation: ColandRelationState,
    anchor_ref: String,
    direction: &'static str,
    target_home_realm_id: Option<String>,
    target_row_visibility: Option<TargetRowVisibilitySnapshot>,
    target_projection_visible: bool,
    target_requires_projection: bool,
}

#[derive(Clone, Debug)]
struct TargetRowVisibilitySnapshot {
    sender: String,
    created_at: DateTime<Utc>,
    scope_circle_id: Option<String>,
}

/// Whether this reference names a projected object the read path must resolve
/// before it can answer. Only canonical typed ids do: a value that is not a
/// valid id of one of these kinds resolves to no projection row.
fn projection_ref_requires_lookup(ref_id: &str) -> bool {
    arkret_identifiers::RealmId::new(ref_id).is_ok()
        || arkret_identifiers::SpaceId::new(ref_id).is_ok()
        || arkret_identifiers::StrandId::new(ref_id).is_ok()
        || arkret_identifiers::MorphId::new(ref_id).is_ok()
        || arkret_identifiers::RelationId::new(ref_id).is_ok()
        || arkret_identifiers::EventId::new(ref_id).is_ok()
        || arkret_identifiers::MessageId::new(ref_id).is_ok()
}

fn message_event_id_from_projection_ref(ref_id: &str) -> String {
    ref_id
        .strip_prefix("ak:message:")
        .map(|suffix| format!("ak:event:{suffix}"))
        .unwrap_or_else(|| ref_id.to_owned())
}

fn target_info_for_relation_ref(
    projection: &ProjectionState,
    target_ref: Option<&str>,
    actor: &arkret_wire::ActorId,
) -> (
    Option<String>,
    bool,
    bool,
    Option<TargetRowVisibilitySnapshot>,
) {
    let Some(target_ref) = target_ref else {
        return (None, true, false, None);
    };
    if target_ref.starts_with("ak:realm:") {
        return (Some(target_ref.to_owned()), true, true, None);
    }
    if let Some(space) = projection.space_containers.get(target_ref) {
        return (
            Some(space.realm_id.clone()),
            !space.orphaned
                && !projection.realm_is_in_terminal_state(&space.realm_id)
                && space.state != SpaceContainerLifecycleState::Tombstoned
                && space.scope_circle_id.as_deref().is_none_or(|circle_id| {
                    projection.circle_scope_visible_to_actor_at(
                        circle_id,
                        &actor.to_string(),
                        space.created_at,
                    )
                }),
            true,
            Some(TargetRowVisibilitySnapshot {
                sender: space.created_by.clone(),
                created_at: space.created_at,
                scope_circle_id: space.scope_circle_id.clone(),
            }),
        );
    }
    if let Some(strand) = projection.strands.get(target_ref) {
        return (
            Some(strand.realm_id.clone()),
            !strand.state.is_terminal()
                && strand.scope_circle_id.as_deref().is_none_or(|circle_id| {
                    projection.circle_scope_visible_to_actor_at(
                        circle_id,
                        &actor.to_string(),
                        strand.created_at,
                    )
                }),
            true,
            Some(TargetRowVisibilitySnapshot {
                sender: strand.created_by.clone(),
                created_at: strand.created_at,
                scope_circle_id: strand.scope_circle_id.clone(),
            }),
        );
    }
    if let Some(morph) = projection.morphs.get(target_ref) {
        return (
            Some(morph.realm_id.clone()),
            !morph.state.is_terminal()
                && morph.scope_circle_id.as_deref().is_none_or(|circle_id| {
                    projection.circle_scope_visible_to_actor_at(
                        circle_id,
                        &actor.to_string(),
                        morph.created_at,
                    )
                }),
            true,
            Some(TargetRowVisibilitySnapshot {
                sender: morph.created_by.clone(),
                created_at: morph.created_at,
                scope_circle_id: morph.scope_circle_id.clone(),
            }),
        );
    }
    if let Some(relation) = projection.relations.get(target_ref) {
        return (
            Some(relation.realm_id.clone()),
            relation.is_active() && document_relation_visible_to_actor(projection, relation, actor),
            true,
            None,
        );
    }
    if arkret_identifiers::EventId::new(target_ref).is_ok()
        || arkret_identifiers::MessageId::new(target_ref).is_ok()
    {
        let event_id = message_event_id_from_projection_ref(target_ref);
        if let Some(message) = projection
            .messages
            .get(target_ref)
            .or_else(|| projection.messages.get(&event_id))
        {
            return (
                Some(message.realm_id.clone()),
                !projection.redactions.contains(&message.event_id)
                    && message_scope_circle_id(message).is_none_or(|circle_id| {
                        projection.circle_scope_visible_to_actor_at(
                            circle_id,
                            &actor.to_string(),
                            message.created_at,
                        )
                    }),
                true,
                Some(TargetRowVisibilitySnapshot {
                    sender: message.sender.clone(),
                    created_at: message.created_at,
                    scope_circle_id: message_scope_circle_id(message).map(ToOwned::to_owned),
                }),
            );
        }
        return (None, false, true, None);
    }
    (None, true, projection_ref_requires_lookup(target_ref), None)
}

fn document_relation_snapshot(
    projection: &ProjectionState,
    relation: &ColandRelationState,
    morph_id: &str,
    actor: &arkret_wire::ActorId,
) -> DocumentRelationSnapshot {
    let (target_ref, direction) = if relation.from_object_ref() == Some(morph_id) {
        (relation.to_ref.clone(), "outgoing")
    } else {
        (relation.from_ref.clone(), "incoming")
    };
    let (
        target_home_realm_id,
        target_projection_visible,
        target_requires_projection,
        target_row_visibility,
    ) = target_info_for_relation_ref(
        projection,
        target_ref
            .as_ref()
            .and_then(RelationEndpoint::as_object_ref),
        actor,
    );
    DocumentRelationSnapshot {
        relation: relation.clone(),
        anchor_ref: morph_id.to_owned(),
        direction,
        target_home_realm_id,
        target_row_visibility,
        target_projection_visible,
        target_requires_projection,
    }
}

async fn document_relation_reference_status(
    state: &AppState,
    snapshot: &DocumentRelationSnapshot,
    realm_id: &str,
    session: &SessionRecord,
) -> ReferenceProjectionState {
    if !snapshot.target_projection_visible {
        return ReferenceProjectionState::Locked;
    }
    let Some(target_home_realm_id) = snapshot.target_home_realm_id.as_deref() else {
        return if snapshot.target_requires_projection {
            ReferenceProjectionState::Locked
        } else {
            ReferenceProjectionState::Accessible
        };
    };
    if target_home_realm_id == realm_id {
        return if document_relation_target_row_visible(
            state,
            snapshot,
            target_home_realm_id,
            session,
        )
        .await
        {
            ReferenceProjectionState::Accessible
        } else {
            ReferenceProjectionState::Locked
        };
    }
    if realm_id_accessible(state, target_home_realm_id, Some(session)).await
        && document_relation_target_row_visible(state, snapshot, target_home_realm_id, session)
            .await
    {
        ReferenceProjectionState::LazyLink
    } else {
        ReferenceProjectionState::Locked
    }
}

async fn document_relation_target_row_visible(
    state: &AppState,
    snapshot: &DocumentRelationSnapshot,
    target_realm_id: &str,
    session: &SessionRecord,
) -> bool {
    let Some(row) = snapshot.target_row_visibility.as_ref() else {
        return true;
    };
    let history_access = realm_history_access(state, target_realm_id).await;
    let projection = state.projections().snapshot();
    projection_row_visible_to_session(
        state,
        &projection,
        target_realm_id,
        session,
        &row.sender,
        row.created_at,
        row.scope_circle_id.as_deref(),
        &history_access,
    )
}

fn document_relation_reference_projection(
    status: ReferenceProjectionState,
    relation: &ColandRelationState,
) -> Value {
    let mut projection = serde_json::Map::new();
    projection.insert("status".to_owned(), json!(status));
    if matches!(status, ReferenceProjectionState::LazyLink)
        && let Some(source_event_digest) = relation.source_event_digest.as_deref()
    {
        projection.insert(
            "source_event_digest".to_owned(),
            Value::String(source_event_digest.to_owned()),
        );
    }
    Value::Object(projection)
}

fn document_relation_row(
    snapshot: &DocumentRelationSnapshot,
    status: ReferenceProjectionState,
) -> Result<Value, AppError> {
    parse_projection_id::<RelationId>(&snapshot.relation.relation_id, "relations.relation_id")?;
    let reference_projection = document_relation_reference_projection(status, &snapshot.relation);
    if status == ReferenceProjectionState::Accessible {
        return Ok(json!({
            "relation_id": snapshot.relation.relation_id.clone(),
            "relation_kind": snapshot.relation.relation_kind.clone(),
            "from": snapshot.relation.from_ref,
            "to": snapshot.relation.to_ref,
            "fields": snapshot.relation.fields.clone(),
            "state": snapshot.relation.state.clone(),
            "created_at": snapshot.relation.created_at,
            "updated_at": snapshot.relation.updated_at,
            "reference_projection": reference_projection,
        }));
    }
    let mut row = serde_json::Map::new();
    row.insert(
        "relation_id".to_owned(),
        Value::String(snapshot.relation.relation_id.clone()),
    );
    row.insert(
        "relation_kind".to_owned(),
        Value::String(snapshot.relation.relation_kind.clone()),
    );
    row.insert(
        "anchor_ref".to_owned(),
        Value::String(snapshot.anchor_ref.clone()),
    );
    row.insert(
        "direction".to_owned(),
        Value::String(snapshot.direction.to_owned()),
    );
    row.insert(
        "state".to_owned(),
        Value::String(snapshot.relation.state.clone()),
    );
    row.insert("reference_projection".to_owned(), reference_projection);
    match status {
        ReferenceProjectionState::LazyLink => {
            row.insert("lazy_link".to_owned(), Value::Bool(true));
            if let Some(source_event_id) = snapshot.relation.source_event_id.as_deref() {
                row.insert(
                    "source_event_id".to_owned(),
                    Value::String(source_event_id.to_owned()),
                );
            }
        }
        ReferenceProjectionState::Locked => {
            row.insert("locked".to_owned(), Value::Bool(true));
        }
        ReferenceProjectionState::Accessible => {}
    }
    Ok(Value::Object(row))
}

async fn document_projection_relations(
    state: &AppState,
    morph_id: &str,
    realm_id: &str,
    session: &SessionRecord,
) -> Result<Vec<BTreeMap<String, Value>>, AppError> {
    let actor =
        crate::routing::identity::session_actor::session_actor_from_credential(state, session)?;
    let snapshots = {
        let projection = state.projections().snapshot();
        projection
            .relations
            .values()
            .filter(|relation| relation.realm_id == realm_id)
            .filter(|relation| relation.is_active())
            .filter(|relation| {
                relation.from_object_ref() == Some(morph_id)
                    || relation.to_object_ref() == Some(morph_id)
            })
            .filter(|relation| document_relation_visible_to_actor(&projection, relation, &actor))
            .map(|relation| {
                parse_projection_id::<RelationId>(&relation.relation_id, "relations.relation_id")?;
                Ok(document_relation_snapshot(
                    &projection,
                    relation,
                    morph_id,
                    &actor,
                ))
            })
            .collect::<Result<Vec<_>, AppError>>()?
    };
    let mut relations = Vec::with_capacity(snapshots.len());
    for snapshot in snapshots {
        let status = document_relation_reference_status(state, &snapshot, realm_id, session).await;
        relations.push((
            snapshot.relation.relation_kind.clone(),
            snapshot.relation.relation_id.clone(),
            document_relation_row(&snapshot, status)?,
        ));
    }
    relations.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
    Ok(relations
        .into_iter()
        .map(|(_, _, relation)| json_object(relation))
        .collect())
}

fn json_object(value: Value) -> BTreeMap<String, Value> {
    value
        .as_object()
        .expect("projection row must be an object")
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

fn document_comment_anchor(content: &Value, morph_id: &str) -> Option<Value> {
    let anchor = content.get("anchor_range")?;
    (anchor.get("target_ref").and_then(Value::as_str) == Some(morph_id)).then(|| anchor.clone())
}

fn document_comment_body(content: &Value) -> Option<String> {
    content
        .get("body")
        .or_else(|| content.get("text"))
        .or_else(|| content.get("label"))
        .and_then(Value::as_str)
        .or_else(|| content.as_str())
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
}

fn document_body_text_len(body: &Value) -> usize {
    if let Some(text) = body.as_str() {
        return text.chars().count();
    }
    if let Some(blocks) = body.get("blocks").and_then(Value::as_array) {
        return blocks
            .iter()
            .filter_map(|block| {
                block
                    .get("content")
                    .or_else(|| block.get("text"))
                    .or_else(|| block.get("body"))
                    .and_then(Value::as_str)
            })
            .map(|text| text.chars().count())
            .sum();
    }
    body.get("content")
        .or_else(|| body.get("text"))
        .or_else(|| body.get("body"))
        .and_then(Value::as_str)
        .map(|text| text.chars().count())
        .unwrap_or_default()
}

fn document_comment_state(anchor_range: &Value, body: &Value) -> String {
    let Some(end) = anchor_range.get("end").and_then(Value::as_u64) else {
        return "active".to_owned();
    };
    let Ok(end) = usize::try_from(end) else {
        return "orphaned".to_owned();
    };
    if end > document_body_text_len(body) {
        "orphaned".to_owned()
    } else {
        "active".to_owned()
    }
}

fn message_scope_circle_id(message: &MessageState) -> Option<&str> {
    message
        .content
        .get("scope_circle_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
}

fn document_projection_comments(
    state: &AppState,
    projection: &ProjectionState,
    morph: &MorphProjection,
    body: &Value,
    session: &SessionRecord,
    history_access: &str,
) -> Vec<BTreeMap<String, Value>> {
    let mut comments = projection
        .messages
        .values()
        .filter(|message| message.realm_id == morph.realm_id)
        .filter(|message| !projection.redactions.contains(&message.event_id))
        .filter_map(|message| {
            let anchor_range = document_comment_anchor(&message.content, &morph.morph_id)?;
            let body_text = document_comment_body(&message.content)?;
            Some((message, anchor_range, body_text))
        })
        .filter(|(message, ..)| {
            projection_row_visible_to_session(
                state,
                projection,
                &morph.realm_id,
                session,
                &message.sender,
                message.created_at,
                message_scope_circle_id(message),
                history_access,
            )
        })
        .map(|(message, anchor_range, body_text)| {
            let actor_id = if message.sender.trim().is_empty() {
                morph.created_by.as_str()
            } else {
                message.sender.as_str()
            };
            (
                message.created_at,
                message.event_id.clone(),
                json!({
                    "event_id": message.event_id,
                    "actor_id": actor_id,
                    "created_at": message.created_at,
                    "body": body_text,
                    "anchor_range": anchor_range,
                    "state": document_comment_state(&anchor_range, body),
                    "content": message.content,
                }),
            )
        })
        .collect::<Vec<_>>();
    comments.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
    comments
        .into_iter()
        .map(|(_, _, comment)| json_object(comment))
        .collect()
}

#[salvo::oapi::endpoint(operation_id = "ak.self.space.read.list", tags("events"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.space.read.list.v1"))]
async fn list_space_container_projections(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
    include_terminal: QueryParam<bool, false>,
) -> GuardedJsonResult<ProjectionSpaceList> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let session_actor =
        crate::routing::identity::session_actor::session_actor_from_credential(state, &session)?;
    let realm_id = validate_realm_id(realm_id.into_inner())?;
    let realm_id =
        RealmId::new(realm_id).map_err(|_| AppError::param_invalid("invalid realm_id format"))?;
    let include_terminal = include_terminal.into_inner().unwrap_or(false);
    let lists = state
        .authority_commits()
        .object_projection_delivery_for_actor(&realm_id, &session_actor, include_terminal)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| crate::app_error!(NotFound, "Realm not found"))?;
    let input = coland_storage::AccountContentDeliveryInput {
        realms: vec![realm_id.clone()],
        current_views: vec![lists.2],
        projection_lists: vec![(realm_id, include_terminal, lists.0.clone(), lists.1)],
        ..Default::default()
    };
    let guard =
        crate::routing::events::sync::content_delivery_guard(state, &session, &input).await?;
    guarded_json_ok(lists.0, guard)
}

#[salvo::oapi::endpoint(operation_id = "ak.self.strand.read.list", tags("events"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.strand.read.list.v1"))]
async fn list_strand_projections(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
    include_terminal: QueryParam<bool, false>,
) -> GuardedJsonResult<ProjectionStrandList> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let session_actor =
        crate::routing::identity::session_actor::session_actor_from_credential(state, &session)?;
    let realm_id = validate_realm_id(realm_id.into_inner())?;
    let realm_id =
        RealmId::new(realm_id).map_err(|_| AppError::param_invalid("invalid realm_id format"))?;
    let include_terminal = include_terminal.into_inner().unwrap_or(false);
    let lists = state
        .authority_commits()
        .object_projection_delivery_for_actor(&realm_id, &session_actor, include_terminal)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| crate::app_error!(NotFound, "Realm not found"))?;
    let input = coland_storage::AccountContentDeliveryInput {
        realms: vec![realm_id.clone()],
        current_views: vec![lists.2],
        projection_lists: vec![(realm_id, include_terminal, lists.0, lists.1.clone())],
        ..Default::default()
    };
    let guard =
        crate::routing::events::sync::content_delivery_guard(state, &session, &input).await?;
    guarded_json_ok(lists.1, guard)
}

/// One relation edge in the `org.arkret.coland.relations.list` response.
/// Mirrors the projected [`ColandRelationState`] fields surfaced by the
/// product-private `/_coland/self/relations` read. `fields` stays a free-form
/// `serde_json` map (arbitrary relation payload values).
#[derive(Debug, serde::Serialize, salvo::oapi::ToSchema)]
struct RelationEdgeView {
    relation_id: String,
    realm_id: String,
    relation_kind: String,
    from_ref: Option<RelationEndpoint>,
    to_ref: Option<RelationEndpoint>,
    rank: Option<String>,
    fields: BTreeMap<String, Value>,
    state: String,
    scope_circle_id: Option<String>,
    #[serde(serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp")]
    created_at: DateTime<Utc>,
    #[serde(serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp")]
    updated_at: DateTime<Utc>,
    /// Present only for the current value of a directly writable primary
    /// domain. Historical/derived edges have no Relation CAS revision.
    #[serde(skip_serializing_if = "Option::is_none")]
    primary_conflict_domain:
        Option<arkret_models_collaboration::objects::relation::RelationPrimaryConflictDomain>,
    #[serde(skip_serializing_if = "Option::is_none")]
    current_revision: Option<arkret_wire::CurrentRevision>,
}

/// Strongly-typed response body for `org.arkret.coland.relations.list`
/// (`GET /_coland/self/relations`). coland product-private projection read;
/// the DTO stays next to its implementation-private relation handler.
#[derive(Debug, serde::Serialize, salvo::oapi::ToSchema)]
struct RelationEdgeList {
    items: Vec<RelationEdgeView>,
    total: u64,
}

fn relation_edge_view(relation: ColandRelationState) -> RelationEdgeView {
    RelationEdgeView {
        relation_id: relation.relation_id,
        realm_id: relation.realm_id,
        relation_kind: relation.relation_kind,
        from_ref: relation.from_ref,
        to_ref: relation.to_ref,
        rank: relation.rank,
        fields: relation.fields,
        state: relation.state,
        scope_circle_id: relation.scope_circle_id,
        created_at: relation.created_at,
        updated_at: relation.updated_at,
        primary_conflict_domain: None,
        current_revision: None,
    }
}

/// Convert one authoritative Relation current-result row into the private
/// read model. Unlike the reducer projection, this record carries the exact
/// accepting RealmCommit revision needed by the next CAS operation.
fn relation_current_edge_view(
    record: coland_storage::RelationCurrentResultRecord,
) -> Result<RelationEdgeView, AppError> {
    let relation = record.relation;
    let relation_id = relation
        .id
        .ok_or_else(|| AppError::internal("durable Relation current result has no relation_id"))?;
    let relation_state = relation
        .state
        .ok_or_else(|| AppError::internal("durable Relation current result has no state"))?;
    let state = match relation_state {
        arkret_wire::RelationState::Active => "active",
        arkret_wire::RelationState::Tombstoned => "tombstoned",
    };
    Ok(RelationEdgeView {
        relation_id: relation_id.to_string(),
        realm_id: relation.realm_id.to_string(),
        relation_kind: relation.relation_kind.as_str().to_owned(),
        from_ref: Some(relation.from_ref),
        to_ref: Some(relation.to_ref),
        rank: relation.rank,
        fields: relation.fields,
        state: state.to_owned(),
        scope_circle_id: relation
            .scope_circle_id
            .map(|circle_id| circle_id.to_string()),
        created_at: relation.created_at,
        updated_at: relation.updated_at.unwrap_or(relation.created_at),
        primary_conflict_domain: Some(record.primary_conflict_domain),
        current_revision: Some(record.revision),
    })
}

fn relation_edge_matches_filters(
    relation: &RelationEdgeView,
    state_filter: &str,
    from_ref: Option<&RelationEndpoint>,
    to_ref: Option<&RelationEndpoint>,
    relation_kind: Option<&str>,
) -> bool {
    (matches!(state_filter, "any" | "all") || relation.state == state_filter)
        && from_ref.is_none_or(|value| relation.from_ref.as_ref() == Some(value))
        && to_ref.is_none_or(|value| relation.to_ref.as_ref() == Some(value))
        && relation_kind.is_none_or(|value| relation.relation_kind == value)
}

/// Parse an endpoint transported in a URL query: object ids are plain text,
/// while an Actor uses one JSON object (URL encoded). The stored/projection
/// value remains typed; a JSON string containing Actor JSON is rejected.
fn parse_relation_endpoint_query(value: &str) -> Result<RelationEndpoint, AppError> {
    let value = if value.starts_with('{') {
        serde_json::from_str(value)
            .map_err(|_| AppError::param_invalid("invalid relation Actor endpoint"))?
    } else {
        Value::String(value.to_owned())
    };
    serde_json::from_value(value).map_err(|_| AppError::param_invalid("invalid relation endpoint"))
}

#[cfg(test)]
mod relation_actor_endpoint_tests {
    use arkret_identifiers::DidCoreId;

    use super::*;

    #[test]
    fn current_relation_view_exposes_the_exact_authority_revision() {
        let realm_id = "ak:realm:AUGIFvQctz4TjQTmvvO4Wdy-xdc5XP2ZnJ5Qpbh4s8Ru"
            .parse()
            .unwrap();
        let primary_conflict_domain = serde_json::from_value(serde_json::json!({
            "domain_kind":"tuple",
            "relation_kind":"references",
            "from_ref":"ak:strand:AUifoAUG8AEOHYXp999WnI7WlLt19ByDoqYUsFwbw4A4",
            "to_ref":"ak:strand:AQdknt9AByYY2gb16KB093xeB4J8b02mTEd4Mt8z2rO-"
        }))
        .unwrap();
        let revision = arkret_wire::CurrentRevision {
            commit_id: arkret_wire::RealmCommitId::from_digest([0x44; 32]),
            stream_position: 7,
        };
        let relation = serde_json::from_value(serde_json::json!({
            "schema":"ak.schema.relation.v1",
            "id":"ak:relation:AcFfzgdHkT6eFkto1gjLaKniVuMXx9sD0GKQwk8BXykz",
            "realm_id":realm_id,
            "effective_scope":{
                "kind":"realm",
                "realm_id":"ak:realm:AUGIFvQctz4TjQTmvvO4Wdy-xdc5XP2ZnJ5Qpbh4s8Ru"
            },
            "relation_kind":"references",
            "from_ref":"ak:strand:AUifoAUG8AEOHYXp999WnI7WlLt19ByDoqYUsFwbw4A4",
            "to_ref":"ak:strand:AQdknt9AByYY2gb16KB093xeB4J8b02mTEd4Mt8z2rO-",
            "state":"active",
            "created_by":{
                "kind":"account",
                "account_id":{
                    "principal_id":"ak:did_core:web:relation-author.example",
                    "station_id":"ak:did_core:web:relation-station.example"
                }
            },
            "created_at":"2026-09-21T00:00:00.000Z"
        }))
        .unwrap();
        let view = relation_current_edge_view(coland_storage::RelationCurrentResultRecord {
            realm_id,
            domain_key: arkret_canonical::canonical_json_string(&primary_conflict_domain).unwrap(),
            primary_conflict_domain,
            relation,
            revision: revision.clone(),
        })
        .unwrap();
        let wire = serde_json::to_value(view).unwrap();
        assert_eq!(wire["current_revision"], serde_json::json!(revision));
        assert_eq!(
            wire["primary_conflict_domain"]["relation_kind"],
            "references"
        );
    }

    #[test]
    fn document_authorship_serializes_complete_station_accounts() {
        let actor = |station: &str| {
            arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                DidCoreId::new(format!("ak:did_core:web:{station}.example")).unwrap(),
            ))
        };
        let creator = actor("station-a");
        let editor = actor("station-b");
        let mut morph = MorphProjection {
            morph_id: "ak:morph:AYqyX_pkT3hbwKscye0o3wq75G7axNkEMZADE88iy_gD".into(),
            realm_id: "ak:realm:AYqyX_pkT3hbwKscye0o3wq75G7axNkEMZADE88iy_gD".into(),
            scope_circle_id: None,
            morph_kind: "document".into(),
            title: None,
            fields: BTreeMap::new(),
            schema_refs: Vec::new(),
            facets: BTreeMap::new(),
            versions: Vec::new(),
            content: None,
            encrypted_content: None,
            state: ObjectLifecycleState::Active,
            state_changed_at: None,
            stage: None,
            stage_changed_at: None,
            created_by: creator.to_string(),
            created_at: Utc::now(),
            updated_by: Some(editor.to_string()),
            updated_at: None,
        };
        let document = document_projection_document(&morph, json!({})).unwrap();
        assert_eq!(document.created_by, Some(creator.clone()));
        assert_eq!(document.updated_by, Some(editor.clone()));
        let wire = serde_json::to_value(document).unwrap();
        assert_eq!(wire["created_by"], json!(creator));
        assert_eq!(wire["updated_by"], json!(editor));
        morph.created_by = creator.signing_principal_id().to_string();
        assert!(document_projection_document(&morph, json!({})).is_err());
    }

    #[test]
    fn projection_history_and_authorship_do_not_cross_stations() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            coland_storage_postgres::Db { pool: None },
        );
        let principal = DidCoreId::new("ak:did_core:web:alice.example").unwrap();
        let local = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            principal.clone(),
            state.service_core_id(),
        ));
        let foreign = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            principal.clone(),
            DidCoreId::new("ak:did_core:web:other.example").unwrap(),
        ));
        let now = Utc::now();
        let session = SessionRecord {
            token_hash: "test".into(),
            account_pk: None,
            actor: principal.to_string(),
            endpoint: coland_services::identity::SessionEndpointState::HumanDevice {
                device_id: "device".into(),
            },
            audience: state.service_id().clone(),
            session_public_key: None,
            session_grant: None,
            expires_at: now + chrono::Duration::hours(1),
            created_at: now,
            revoked_at: None,
        };
        let realm = "test-realm";
        let mut projection = ProjectionState::new();
        assert!(projection_row_visible_to_session(
            &state,
            &projection,
            realm,
            &session,
            &local.to_string(),
            now,
            None,
            "since_join"
        ));
        assert!(!projection_row_visible_to_session(
            &state,
            &projection,
            realm,
            &session,
            &foreign.to_string(),
            now,
            None,
            "since_join"
        ));
        assert!(!projection_row_visible_to_session(
            &state,
            &projection,
            realm,
            &session,
            principal.as_str(),
            now,
            None,
            "since_join"
        ));
        projection.members.insert(
            (realm.into(), local.to_string()),
            coland_domain::reducer::ColandMembershipState {
                member: local.to_string(),
                realm_id: realm.into(),
                state: "join".into(),
                role: "member".into(),
                membership_event_ref: None,
                invited_at: None,
                joined_at: now,
                updated_at: now,
                reason: None,
            },
        );
        assert!(projection_realm_history_allows(
            &projection,
            realm,
            &local,
            "since_join",
            now
        ));
        assert!(!projection_realm_history_allows(
            &projection,
            realm,
            &foreign,
            "since_join",
            now
        ));
    }

    #[test]
    fn current_circle_projection_visibility_uses_complete_actor() {
        let local = actor("station-a.example");
        let foreign = actor("station-b.example");
        let now = Utc::now();
        let mut projection = ProjectionState::new();
        projection.circles.insert(
            "circle".into(),
            coland_domain::reducer::CircleProjection {
                circle_id: "circle".into(),
                realm_id: "realm".into(),
                profile_ref: None,
                title: "Scoped".into(),
                summary: None,
                display: json!({}),
                directory_visibility: "members".into(),
                join_rule: "invite".into(),
                history_access: "since_join".into(),
                mls_group_ref: None,
                state: coland_domain::reducer::CircleLifecycleState::Active,
                state_changed_at: None,
                created_by: local.to_string(),
                created_at: now,
                updated_by: None,
                updated_at: None,
                members: std::collections::BTreeSet::from([local.to_string()]),
            },
        );
        assert!(current_projection_scope_visible_to_actor(
            &projection,
            &local,
            Some("circle")
        ));
        assert!(!current_projection_scope_visible_to_actor(
            &projection,
            &foreign,
            Some("circle")
        ));
    }

    fn actor(station: &str) -> arkret_wire::ActorId {
        arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            DidCoreId::new("ak:did_core:web:assignee.example").unwrap(),
            DidCoreId::new(format!("ak:did_core:web:{station}")).unwrap(),
        ))
    }

    #[test]
    fn assignment_projection_and_query_keep_same_principal_stations_separate() {
        let first = actor("station-a.example");
        let second = actor("station-b.example");
        let strand = "ak:strand:AUifoAUG8AEOHYXp999WnI7WlLt19ByDoqYUsFwbw4A4";
        let mut projection = ProjectionState::new();
        for (seed, actor) in [(1_u8, &first), (2_u8, &second)] {
            let event = arkret_wire::EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [seed; 32],
            );
            let relation_id = RelationId::from_event_id(&event).to_string();
            projection.relations.insert(
                relation_id.clone(),
                ColandRelationState {
                    relation_id,
                    realm_id: RealmId::from_event_id(&event).to_string(),
                    relation_kind: "assigned_to".to_owned(),
                    scope_circle_id: None,
                    from_ref: Some(strand.into()),
                    to_ref: Some(actor.clone().into()),
                    rank: None,
                    fields: BTreeMap::new(),
                    state: "active".to_owned(),
                    source_event_id: Some(event.to_string()),
                    source_event_digest: None,
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                },
            );
        }
        let assignments = strand_assigned_to_relations(&projection, strand).unwrap();
        assert_eq!(assignments.len(), 2);
        assert_eq!(
            assignments
                .iter()
                .map(|entry| entry.actor_id.clone())
                .collect::<std::collections::BTreeSet<_>>(),
            std::collections::BTreeSet::from([first.clone(), second.clone()])
        );
        let endpoint =
            parse_relation_endpoint_query(&serde_json::to_string(&first).unwrap()).unwrap();
        assert_eq!(
            projection
                .relations
                .values()
                .filter(|relation| relation.to_ref.as_ref() == Some(&endpoint))
                .count(),
            1
        );
        assert!(serde_json::to_value(&endpoint).unwrap().is_object());
        assert!(parse_relation_endpoint_query("ak:did_core:web:assignee.example").is_err());
        assert!(
            parse_relation_endpoint_query(&serde_json::to_string(&first.to_string()).unwrap())
                .is_err()
        );
    }
}

/// `GET /_coland/self/relations?from_ref=&to_ref=&relation_kind=&state=` —
/// list relation edges projected from accepted Events. Directly writable
/// current values are restart-hydrated from their authority CAS rows, while
/// derived edges remain reducer projections. Backs the
/// relation-cardinality invariant checks (e.g. asserting at most one active
/// `has_default_view` edge per `from_ref`). Filters are AND-combined; `state`
/// defaults to `active`. Only edges whose `realm_id` is accessible to the
/// caller are returned, so non-members can't enumerate another Realm's graph.
#[salvo::oapi::endpoint(operation_id = "org.arkret.coland.relations.list", tags("events"))]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.relations.list"))]
async fn list_relation_projections(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<RelationEdgeList> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let session_actor =
        crate::routing::identity::session_actor::session_actor_from_credential(state, &session)?;
    let from_ref = coland_http::util::query_param(req, "from_ref")
        .map(|value| parse_relation_endpoint_query(&value))
        .transpose()?;
    let to_ref = coland_http::util::query_param(req, "to_ref")
        .map(|value| parse_relation_endpoint_query(&value))
        .transpose()?;
    let relation_kind = coland_http::util::query_param(req, "relation_kind");
    let state_filter =
        coland_http::util::query_param(req, "state").unwrap_or_else(|| "active".to_owned());

    let durable_current = state
        .persistence()
        .relation_current_results()
        .await
        .map_err(|error| {
            AppError::internal(format!(
                "authoritative Relation current-result read failed: {error}"
            ))
        })?;
    let durable_current_ids = durable_current
        .iter()
        .filter_map(|record| record.relation.id.as_ref().map(ToString::to_string))
        .collect::<BTreeSet<_>>();

    let proj = state.projections().snapshot();
    let mut candidates = durable_current
        .into_iter()
        .map(relation_current_edge_view)
        .collect::<Result<Vec<_>, _>>()?;
    candidates.retain(|relation| {
        relation_edge_matches_filters(
            relation,
            &state_filter,
            from_ref.as_ref(),
            to_ref.as_ref(),
            relation_kind.as_deref(),
        ) && relation.scope_circle_id.as_deref().is_none_or(|circle_id| {
            proj.circle_scope_visible_to_actor_at(
                circle_id,
                &session_actor.to_string(),
                relation.created_at,
            )
        })
    });
    candidates.extend(
        proj.relations
            .values()
            .filter(|relation| !durable_current_ids.contains(&relation.relation_id))
            .filter(|relation| match state_filter.as_str() {
                "any" | "all" => true,
                other => relation.state == other,
            })
            .filter(|relation| {
                from_ref
                    .as_ref()
                    .is_none_or(|value| relation.from_ref.as_ref() == Some(value))
            })
            .filter(|relation| {
                to_ref
                    .as_ref()
                    .is_none_or(|value| relation.to_ref.as_ref() == Some(value))
            })
            .filter(|relation| {
                relation_kind
                    .as_deref()
                    .is_none_or(|value| relation.relation_kind == value)
            })
            .filter(|relation| {
                relation.scope_circle_id.as_deref().is_none_or(|circle_id| {
                    proj.circle_scope_visible_to_actor_at(
                        circle_id,
                        &session_actor.to_string(),
                        relation.created_at,
                    )
                })
            })
            .cloned()
            .map(relation_edge_view),
    );

    let mut items = Vec::new();
    let mut structural_realms = BTreeMap::new();
    for relation in candidates {
        if !realm_id_accessible(state, &relation.realm_id, Some(&session)).await {
            continue;
        }
        if relation.relation_kind == "contains" {
            // Structural navigation consumes the durable parent terminal fence,
            // including after cold hydration. The canonical edge remains history.
            let available = match structural_realms.get(&relation.realm_id) {
                Some(available) => *available,
                None => {
                    let available =
                        structural_navigation_available(state, &relation.realm_id).await?;
                    structural_realms.insert(relation.realm_id.clone(), available);
                    available
                }
            };
            if !available {
                continue;
            }
        }
        items.push(relation);
    }
    items.sort_by(|left, right| left.relation_id.cmp(&right.relation_id));
    let total = total_count(items.len())?;
    json_ok(RelationEdgeList { items, total })
}

#[salvo::oapi::endpoint(operation_id = "ak.self.morph.resource.get", tags("events"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.morph.resource.get.v1"))]
async fn get_document_projection(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
    morph_id: PathParam<String>,
) -> GuardedJsonResult<DocumentMorphProjectionOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let actor =
        crate::routing::identity::session_actor::session_actor_from_credential(state, &session)?;
    let realm = RealmId::new(validate_realm_id(realm_id.into_inner())?)
        .map_err(|_| AppError::param_invalid("invalid realm_id"))?;
    let morph = MorphId::new(morph_id.into_inner())
        .map_err(|_| AppError::param_invalid("invalid morph_id"))?;
    let observation = if session.agent_session().is_none() {
        let account = actor
            .as_account_id()
            .ok_or_else(|| AppError::capability_denied("Morph caller is not an Account"))?;
        Some(super::peer::refresh_current_account_status(state, account).await?)
    } else {
        None
    };
    let output = state
        .authority_commits()
        .document_morph_for_actor(&realm, &morph, &actor, &state.service_core_id())
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let Some(output) = output else {
        let input = coland_storage::AccountContentDeliveryInput {
            realms: vec![realm.clone()],
            morph_absences: vec![(realm, morph)],
            account_status_observations: observation.into_iter().collect(),
            credential_expires_at: Some(session.expires_at),
            ..Default::default()
        };
        let guard =
            crate::routing::events::sync::content_delivery_guard(state, &session, &input).await?;
        return crate::result::guarded_json_not_found(guard);
    };
    let input = coland_storage::AccountContentDeliveryInput {
        realms: vec![realm.clone()],
        morph_documents: vec![(realm, morph, output.clone())],
        account_status_observations: observation.into_iter().collect(),
        credential_expires_at: Some(session.expires_at),
        ..Default::default()
    };
    let guard =
        crate::routing::events::sync::content_delivery_guard(state, &session, &input).await?;
    guarded_json_ok(output, guard)
}

#[salvo::oapi::endpoint(operation_id = "ak.self.morph.read.list", tags("events"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.morph.read.list.v1"))]
async fn list_morph_projections(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
    include_terminal: QueryParam<bool, false>,
) -> GuardedJsonResult<ProjectionMorphList> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let actor =
        crate::routing::identity::session_actor::session_actor_from_credential(state, &session)?;
    let realm = RealmId::new(validate_realm_id(realm_id.into_inner())?)
        .map_err(|_| AppError::param_invalid("invalid realm_id"))?;
    let include_terminal = include_terminal.into_inner().unwrap_or(false);
    let observation = if session.agent_session().is_none() {
        let account = actor
            .as_account_id()
            .ok_or_else(|| AppError::capability_denied("Morph caller is not an Account"))?;
        Some(super::peer::refresh_current_account_status(state, account).await?)
    } else {
        None
    };
    let output = state
        .authority_commits()
        .morph_list_for_actor(&realm, &actor, &state.service_core_id(), include_terminal)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::not_found("Realm not found"))?;
    let input = coland_storage::AccountContentDeliveryInput {
        realms: vec![realm.clone()],
        morph_lists: vec![(realm, include_terminal, output.clone())],
        account_status_observations: observation.into_iter().collect(),
        credential_expires_at: Some(session.expires_at),
        ..Default::default()
    };
    let guard =
        crate::routing::events::sync::content_delivery_guard(state, &session, &input).await?;
    guarded_json_ok(output, guard)
}
