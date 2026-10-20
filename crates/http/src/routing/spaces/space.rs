//! Realm lifecycle read and export surfaces.
//!
//! Surfaces that remain:
//! - `GET    /_arkret/self/realms/{realm_id}` — read a Realm lifecycle response.
//! - `GET    /_arkret/self/realms/{realm_id}/export` — full event log + projection dump.
//!
//! Everything else in this module is the visibility / membership
//! query helper surface that every other domain (federation, message, blob,
//! directory, mimi, …) calls into to resolve "is this actor allowed to see /
//! write in this Realm?".

use arkret_identifiers::RealmId;
use arkret_models_collaboration::governance::realm_governance::{RealmExport, RealmLifecycleView};
#[cfg(test)]
use arkret_wire::PlaintextDataClassKind;
use chrono::{DateTime, Utc};
use coland_http::error::AppError;
use coland_http::result::{GuardedJsonResult, guarded_json_ok};
use coland_services::identity::SessionIdentityState as SessionRecord;
use salvo::oapi::extract::PathParam;
use salvo::prelude::*;
use serde_json::Value;

use super::AuthArgs;
use crate::state::AppState;
#[cfg(test)]
use crate::wire::now;

/// Spec `realm_read` operation group (`ak.self.realm.*`): Realm lifecycle read
/// and full export. Canonical path
/// `/_arkret/self/realms/{realm_id}*`.
pub(super) fn protocol_router() -> Router {
    Router::new().push(
        Router::with_path("realms/{realm_id}")
            .get(get_realm)
            .push(Router::with_path("export").get(export_realm)),
    )
}

#[salvo::oapi::endpoint(operation_id = "ak.self.realm.resource.get", tags("spaces"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.realm.resource.get.v1"))]
async fn get_realm(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
) -> GuardedJsonResult<RealmLifecycleView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let actor =
        crate::routing::identity::session_actor::validated_session_actor(state, &session).await?;
    let realm_id = RealmId::new(realm_id.into_inner())
        .map_err(|_| AppError::param_invalid("invalid realm_id"))?;
    let view = state
        .authority_commits()
        .realm_lifecycle_for_actor(&realm_id, &actor)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::not_found("not found"))?;
    let input = coland_storage::AccountContentDeliveryInput {
        realms: vec![realm_id],
        realm_lifecycle_reads: vec![view.clone()],
        ..Default::default()
    };
    let guard =
        crate::routing::events::sync::content_delivery_guard(state, &session, &input).await?;
    guarded_json_ok(view, guard)
}

#[salvo::oapi::endpoint(operation_id = "ak.self.realm.read.export", tags("spaces"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.realm.read.export.v1"))]
async fn export_realm(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
) -> GuardedJsonResult<RealmExport> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let actor =
        crate::routing::identity::session_actor::validated_session_actor(state, &session).await?;
    let realm_id = RealmId::new(realm_id.into_inner())
        .map_err(|_| AppError::param_invalid("invalid realm_id"))?;
    let (export, sources) = state
        .authority_commits()
        .realm_export_for_actor(&realm_id, &actor, &state.service_core_id())
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::not_found("not found"))?;
    let input = coland_storage::AccountContentDeliveryInput {
        realms: vec![realm_id],
        committed_events: sources,
        realm_exports: vec![export.clone()],
        ..Default::default()
    };
    let guard =
        crate::routing::events::sync::content_delivery_guard(state, &session, &input).await?;
    guarded_json_ok(export, guard)
}

// ── Helpers shared with the parent module ───────────────────────────────────
//
// Each is re-exported from `crate::routing::*` so sibling modules use the
// same Realm metadata and membership checks.

// ── Visibility + membership query helpers ─────────────────────────────────

pub fn realm_scope_to_realm_id(scope_id: &str) -> Option<String> {
    RealmId::new(scope_id.to_owned())
        .ok()
        .map(|realm_id| realm_id.as_str().to_owned())
}

pub async fn is_realm_deleted(state: &AppState, realm_or_internal_id: &str) -> bool {
    match realm_scope_to_realm_id(realm_or_internal_id) {
        Some(realm_id) => realm_meta_deleted(state, &realm_id).await,
        None => false,
    }
}

pub async fn realm_discoverability(state: &AppState, realm_or_internal_id: &str) -> String {
    match realm_scope_to_realm_id(realm_or_internal_id) {
        Some(realm_id) => realm_discoverability_for_id(state, &realm_id).await,
        None => "invite_only".to_owned(),
    }
}

pub async fn realm_has_member(state: &AppState, realm_or_internal_id: &str, actor: &str) -> bool {
    match realm_scope_to_realm_id(realm_or_internal_id) {
        Some(realm_id) => realm_has_member_by_id(state, &realm_id, actor).await,
        None => false,
    }
}

pub async fn realm_id_accessible(
    state: &AppState,
    realm_or_internal_id: &str,
    session: Option<&SessionRecord>,
) -> bool {
    match realm_scope_to_realm_id(realm_or_internal_id) {
        Some(realm_id) => realm_id_accessible_for_id(state, &realm_id, session).await,
        None => false,
    }
}

pub async fn realm_history_access(state: &AppState, realm_or_internal_id: &str) -> String {
    match realm_scope_to_realm_id(realm_or_internal_id) {
        Some(realm_id) => realm_history_access_for_id(state, &realm_id).await,
        None => "since_join".to_owned(),
    }
}

fn projection_member_is_joined(
    projection: &coland_domain::reducer::ProjectionState,
    realm_id: &str,
    actor: &arkret_wire::ActorId,
    actor_key: &str,
) -> bool {
    if projection
        .member(realm_id, actor_key)
        .is_some_and(|member| member.state == "join")
    {
        return true;
    }

    // Membership authority is the Realm-scoped sealed transition cell. The
    // structured `members` map is a side-band cache and can legitimately be
    // absent after cold hydration or during the narrow Commit projection window.
    // Falling back to the confirmed cell preserves the exact ActorId subject
    // and never grants access from an unsealed Event or a principal-only row.
    let Ok(actor_key) = actor.canonical_key() else {
        return false;
    };
    projection
        .facet_value(
            realm_id,
            &coland_domain::reducer::FacetRef::new(
                coland_domain::reducer::facet::MEMBER_STATE,
                actor_key,
            ),
        )
        .and_then(Value::as_str)
        == Some("join")
}

pub async fn realm_member_joined_at(
    state: &AppState,
    realm_or_internal_id: &str,
    actor: &str,
) -> Option<DateTime<Utc>> {
    match realm_scope_to_realm_id(realm_or_internal_id) {
        Some(realm_id) => realm_member_joined_at_for_id(state, &realm_id, actor).await,
        None => None,
    }
}

pub async fn realm_event_visible_to_session(
    state: &AppState,
    realm_or_internal_id: &str,
    event_created_at: DateTime<Utc>,
    _sender: Option<&str>,
    session: Option<&SessionRecord>,
) -> bool {
    let Some(session) = session else {
        return false;
    };
    let Ok(actor) =
        crate::routing::identity::session_actor::session_actor_from_credential(state, session)
    else {
        return false;
    };
    let actor_key = actor.to_string();
    if !realm_active_member_at_read_time(state, realm_or_internal_id, &actor_key).await {
        return false;
    }
    match realm_history_access(state, realm_or_internal_id)
        .await
        .as_str()
    {
        "all_history_for_current_members" => true,
        "since_join" => realm_member_joined_at(state, realm_or_internal_id, &actor_key)
            .await
            .is_some_and(|joined_at| event_created_at >= joined_at),
        _ => false,
    }
}

#[cfg(test)]
pub async fn realm_allows_plaintext_service_for_data_class(
    state: &AppState,
    realm_or_internal_id: &str,
    data_class: PlaintextDataClassKind,
) -> bool {
    match realm_scope_to_realm_id(realm_or_internal_id) {
        Some(realm_id) => {
            realm_allows_plaintext_service_for_data_class_id(state, &realm_id, data_class).await
        }
        None => false,
    }
}

pub async fn realm_meta_deleted(state: &AppState, realm_id: &str) -> bool {
    state
        .realms()
        .realm_metadata(realm_id)
        .await
        .ok()
        .flatten()
        .is_some_and(|record| record.deleted)
}

pub async fn realm_discoverability_for_id(state: &AppState, realm_id: &str) -> String {
    // The accepted control projection is authoritative. Live semantic apply
    // stores Realm create entries as `{object: Realm}`, while canonical Commit
    // replay stores the ordered-log value as `{value: Realm + entry_id}`.
    // Resolve both before consulting the service-local metadata mirror, which
    // may legitimately lag a freshly materialized Commit.
    let projected = {
        let projection = state.projections().snapshot();
        projection
            .realm_facet_value(realm_id, coland_domain::reducer::facet::REALM_DISCOVERY)
            .and_then(|value| {
                value
                    .get("value")
                    .and_then(Value::as_str)
                    .or_else(|| value.as_str())
            })
            .map(ToOwned::to_owned)
    };
    if let Some(discoverability) = projected {
        return discoverability;
    }
    state
        .realms()
        .realm_metadata(realm_id)
        .await
        .ok()
        .flatten()
        .map(|record| record.discoverability)
        .unwrap_or_else(|| {
            if directory_realm_is_public(state, realm_id) {
                "public".to_owned()
            } else {
                "invite_only".to_owned()
            }
        })
}

pub async fn realm_has_member_by_id(state: &AppState, realm_id: &str, actor: &str) -> bool {
    if realm_meta_deleted(state, realm_id).await {
        tracing::warn!(%realm_id, %actor, "realm_has_member_by_id: realm marked deleted");
        return false;
    }
    let Ok(_realm_id_typed) = RealmId::new(realm_id.to_owned()) else {
        tracing::warn!(%realm_id, %actor, "realm_has_member_by_id: invalid realm_id shape");
        return false;
    };
    let Ok(actor_typed) = serde_json::from_str::<arkret_wire::ActorId>(actor) else {
        tracing::warn!(%realm_id, %actor, "realm_has_member_by_id: invalid ActorId shape");
        return false;
    };
    if state
        .projections()
        .snapshot()
        .realm_is_principal_control_for_actor(realm_id, actor)
    {
        return true;
    }
    {
        let projection = state.projections().snapshot();
        if !projection_member_is_joined(&projection, realm_id, &actor_typed, actor) {
            return false;
        }
        if projection
            .agent_membership_binding(realm_id, actor)
            .is_none()
        {
            return true;
        }
        if !projection.effective_agent_membership_base(realm_id, actor) {
            return false;
        }
    }
    if matches!(&actor_typed, arkret_wire::ActorId::Account { account_id: arkret_wire::AccountId { station_id, .. } } if *station_id == state.service_core_id())
        && let Ok(Some(agent)) = state
            .agent_pairings()
            .agent(actor_typed.signing_principal_id().as_str())
            .await
        && crate::routing::identity::agent_pcr::validate_effective_agent_realm_membership(
            state,
            &agent,
            realm_id,
            chrono::Utc::now(),
        )
        .await
        .is_err()
    {
        return false;
    }
    // Only the exact projected member and its effective Agent binding prove
    // membership. Principal-only directory entries are not authority.
    true
}

/// Check if a Realm is accessible for backfill/subscribe.
///
/// Data-plane backfill and subscription require the session's actor to read
/// the Realm in this Station's accepted typed current -- a current joined
/// member, governed here or held as a verified replica, or the owner of its
/// principal-control Realm. Discoverability and the history range ratchet
/// never grant timeline access.
pub async fn realm_id_accessible_for_id(
    state: &AppState,
    realm_id: &str,
    session: Option<&SessionRecord>,
) -> bool {
    let Some(session) = session else {
        return false;
    };
    let Ok(actor) =
        crate::routing::identity::session_actor::session_actor_from_credential(state, session)
    else {
        return false;
    };
    let Ok(realm_id) = RealmId::new(realm_id.to_owned()) else {
        return false;
    };
    state
        .authority_commits()
        .accepted_realm_reader(&realm_id, &actor)
        .await
        .unwrap_or(false)
}

/// Look up the current one-way `history_access` ratchet value. Missing or
/// unrecognized state fails closed to `since_join`.
pub async fn realm_history_access_for_id(state: &AppState, realm_id: &str) -> String {
    if let Some(value) = state
        .projections()
        .snapshot()
        .realm_history_access(realm_id)
    {
        return value;
    }
    state
        .realms()
        .realm_metadata(realm_id)
        .await
        .ok()
        .flatten()
        .map(|record| record.history_access.clone())
        .filter(|value| {
            matches!(
                value.as_str(),
                "since_join" | "all_history_for_current_members"
            )
        })
        .unwrap_or_else(|| "since_join".to_owned())
}

fn directory_realm_is_public(state: &AppState, realm_id: &str) -> bool {
    let Ok(realm_id) = RealmId::new(realm_id.to_owned()) else {
        return false;
    };
    state
        .realm_directory()
        .snapshot()
        .get(&realm_id)
        .is_some_and(|entry| entry.public)
}

/// Best-effort joined-at timestamp for event history filtering.
///
/// The reducer's member projection is authoritative when present. Bootstrap
/// owners predate that side-band cache, so only the owner falls back to the
/// Realm creation time. Non-owner members without joined_at are hidden by
/// `history_access=since_join` instead of leaking pre-join history.
pub async fn realm_member_joined_at_for_id(
    state: &AppState,
    realm_id: &str,
    actor: &str,
) -> Option<DateTime<Utc>> {
    {
        let projection = state.projections().snapshot();
        if let Some(member) = projection.member(realm_id, actor)
            && member.state == "join"
        {
            return Some(member.joined_at);
        }
    }
    let meta = state.realms().realm_metadata(realm_id).await.ok().flatten();
    if meta.as_ref().is_some_and(|record| record.owner == actor) {
        return meta.map(|record| record.created_at);
    }
    None
}

async fn realm_active_member_at_read_time(
    state: &AppState,
    realm_or_internal_id: &str,
    actor: &str,
) -> bool {
    match realm_scope_to_realm_id(realm_or_internal_id) {
        Some(realm_id) => {
            {
                let projection = state.projections().snapshot();
                if let Some(member) = projection.member(&realm_id, actor) {
                    return member.state == "join";
                }
            }
            realm_has_member_by_id(state, &realm_id, actor).await
        }
        None => false,
    }
}

#[cfg(test)]
/// Whether the Realm's current `plaintext_visible_services` declaration in
/// this Station's accepted typed current -- governing or held as an anchored
/// replica -- lists this Station for `data_class`, unexpired. The
/// machine-checkable `data_classes[]` alone authorizes plaintext.
pub async fn realm_allows_plaintext_service_for_data_class_id(
    state: &AppState,
    realm_id: &str,
    data_class: PlaintextDataClassKind,
) -> bool {
    let Ok(realm_id) = RealmId::new(realm_id.to_owned()) else {
        return false;
    };
    let Ok(Some(declared)) = state
        .authority_commits()
        .accepted_plaintext_visible_services(&realm_id)
        .await
    else {
        return false;
    };
    let now = now();
    let station = state.service_core_id();
    declared.services.iter().any(|service| {
        service.service_id == station
            && service.data_classes.contains(&data_class)
            && service.expires_at.is_none_or(|expires_at| expires_at > now)
    })
}
