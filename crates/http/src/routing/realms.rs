//! Realm governance HTTP surface.
//!
//! Surfaces:
//! - `GET /_arkret/self/realms/{realm_id}/links?direction=outbound|inbound|both&link_kind_allow=...
//!   ` — list the typed cross-Realm links projected from `ak.realm.link` events. Powered by
//!   [`coland_domain::reducer::ProjectionState::realm_links_query`].
use arkret_identifiers::RealmId;
use arkret_models_collaboration::governance::realm_governance::{
    RealmLinkDirection, RealmLinkEntry, RealmLinkKind, RealmLinkList, RealmLinkStatus,
};
use coland_domain::reducer::RealmLinkState;
use coland_http::error::AppError;
use coland_http::result::{JsonResult, json_ok};
use salvo::oapi::endpoint;
use salvo::oapi::extract::{PathParam, QueryParam};
use salvo::prelude::*;

use super::AuthArgs;
use crate::state::AppState;

/// Protocol-surface realm governance routes, mounted under
/// `/_arkret/self/realms/...`. Only spec-registered `ak.self.realm_link.*`
/// operations live here — every URL has an `operation-registry.json` entry.
pub(crate) fn router() -> Router {
    Router::with_path("realms").push(Router::with_path("{realm_id}/links").get(list_realm_links))
}

fn stored_realm_id(field: &str, value: &str) -> Result<RealmId, AppError> {
    RealmId::new(value.to_owned())
        .map_err(|e| AppError::internal(format!("stored realm link {field}: {e}")))
}

fn stored_link_kind(value: &str) -> Result<RealmLinkKind, AppError> {
    RealmLinkKind::parse(value)
        .ok_or_else(|| AppError::internal(format!("stored realm link link_kind: {value}")))
}

fn stored_link_status(value: &str) -> Result<RealmLinkStatus, AppError> {
    RealmLinkStatus::parse(value)
        .ok_or_else(|| AppError::internal(format!("stored realm link status: {value}")))
}

fn realm_link_entry_from(row: &RealmLinkState) -> Result<RealmLinkEntry, AppError> {
    Ok(RealmLinkEntry {
        realm_id: stored_realm_id("realm_id", &row.realm_id)?,
        target_realm_id: stored_realm_id("target_realm_id", &row.target_realm_id)?,
        link_kind: stored_link_kind(&row.link_kind)?,
        status: stored_link_status(&row.status)?,
        label: row.label.clone(),
        commitment: row.commitment.clone(),
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}

#[endpoint(
    operation_id = "ak.self.realm_link.read.list",
    summary = "List typed cross-Realm links",
    tags("realm_links")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.realm_link.read.list.v1"))]
pub(crate) async fn list_realm_links(
    aa: AuthArgs,
    realm_id: PathParam<String>,
    direction: QueryParam<String, false>,
    link_kind_allow: QueryParam<String, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<RealmLinkList> {
    let session = {
        let state = depot.get_typed::<AppState>().expect("state injected");
        aa.authenticated_session(state, req).await?
    };
    list_realm_links_impl(session, realm_id, direction, link_kind_allow, depot).await
}

#[endpoint(
    operation_id = "org.arkret.coland.admin.realm_link.query.list",
    summary = "List typed cross-Realm links for administration",
    tags("admin", "realm_links")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.admin.realm_link.query.list"))]
pub(crate) async fn admin_list_realm_links(
    admin: super::admin::AdminAuth,
    realm_id: PathParam<String>,
    direction: QueryParam<String, false>,
    link_kind_allow: QueryParam<String, false>,
    depot: &mut Depot,
) -> JsonResult<RealmLinkList> {
    let session = admin.session()?;
    list_realm_links_impl(session, realm_id, direction, link_kind_allow, depot).await
}

/// `_session` is the caller already authenticated by the wrapping endpoint
/// (the self bearer path or the `RequireAdmin` gate).
async fn list_realm_links_impl(
    _session: coland_services::identity::SessionIdentityState,
    realm_id: PathParam<String>,
    direction: QueryParam<String, false>,
    link_kind_allow: QueryParam<String, false>,
    depot: &mut Depot,
) -> JsonResult<RealmLinkList> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let realm_id = RealmId::new(realm_id.into_inner())
        .map_err(|e| AppError::param_invalid(format!("realm_id: {e}")))?;
    let direction_str = direction.into_inner().unwrap_or_else(|| "both".to_owned());
    let direction_enum = RealmLinkDirection::parse(&direction_str)
        .ok_or_else(|| AppError::param_invalid("direction MUST be one of outbound|inbound|both"))?;
    // `link_kind_allow` is a comma-separated list — keeps the query
    // surface dense and avoids repeated query params.
    let allow_raw = link_kind_allow.into_inner();
    let allow: Option<Vec<String>> = allow_raw
        .as_ref()
        .map(|s| {
            s.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|value| {
                    RealmLinkKind::parse(value)
                        .map(|kind| kind.as_str().to_owned())
                        .ok_or_else(|| {
                            AppError::param_invalid(format!(
                                "link_kind_allow contains unknown kind '{value}'"
                            ))
                        })
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?;

    let projection = state.projections().snapshot();
    let rows = projection.realm_links_query(realm_id.as_str(), direction_enum, allow.as_deref());
    let entries = rows
        .iter()
        .map(realm_link_entry_from)
        .collect::<Result<Vec<_>, _>>()?;

    json_ok(RealmLinkList {
        realm_id,
        direction: direction_enum,
        links: entries,
    })
}
