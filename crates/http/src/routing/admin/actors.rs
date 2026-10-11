//! Actor admin surface (production, D14).
//!
//! `GET /_coland/admin/actors` — typed cursor-paginated list (see
//! [`super::queries`]); `GET /_coland/admin/actors/{actor_id}` — one
//! [`AdminActor`] row with the account lifecycle linkage codmin needs.

use coland_contracts::admin::AdminActor;
use salvo::oapi::extract::PathParam;
use salvo::prelude::*;
use serde_json::json;

use super::{AdminAuth, append_audit_log, queries, require_admin_principal};
use crate::state::AppState;
use crate::{JsonResult, json_ok};

pub(super) fn router() -> Router {
    Router::with_path("actors")
        .get(queries::admin_list_actors)
        .push(Router::with_path("{actor_id}").get(get_actor))
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.coland.admin.actors.get",
    tags("coland_admin")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.admin.actors.get"))]
async fn get_actor(
    admin: AdminAuth,
    actor_id: PathParam<String>,
    depot: &mut Depot,
) -> JsonResult<AdminActor> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = admin.session()?;
    let session = require_admin_principal(state, session)?;
    let actor_id = actor_id.into_inner();
    let principal_id = arkret_wire::DidCoreId::new(actor_id.clone()).map_err(|_| {
        coland_http::error::AppError::param_invalid("invalid local account principal")
    })?;
    let account_id = arkret_wire::AccountId::new(principal_id, state.service_core_id());

    let account = state
        .identities()
        .account(&account_id)
        .await
        .map_err(|error| {
            tracing::error!(%error, "failed to load local account");
            coland_http::error::AppError::internal("account store unavailable")
        })?
        .ok_or_else(|| coland_http::error::AppError::not_found("actor not found"))?;
    let (device_counts, realm_counts) = queries::actor_count_maps(state).await;
    let deactivated = state.account_lifecycle_status(account.principal_id.as_str())
        == arkret_models_collaboration::objects::account_status::AccountStatus::Deactivated;
    let propagation_state = queries::account_status_propagation_state_for_admin(
        state,
        &account.account_id,
        deactivated,
    )
    .await?;
    let actor = queries::admin_actor_row(
        state,
        &account,
        &device_counts,
        &realm_counts,
        propagation_state,
    )
    .ok_or_else(|| coland_http::error::AppError::not_found("actor not found"))?;

    append_audit_log(
        state,
        Some(&session.actor),
        "admin.actors.get",
        json!({
            "actor_id": actor_id,
            "device_id": session.require_human_device_id(),
        }),
        "accepted",
    )
    .await;

    json_ok(actor)
}
