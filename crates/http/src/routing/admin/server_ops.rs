//! Product-local coland operator endpoints.
//!
//! The public Arkret protocol namespace does not define admin operations.
//! coland serves operator-only controls under `/_coland/admin/*`
//! with local `org.arkret.coland.*` operation IDs and the `coland-admin`
//! OpenAPI tag. These endpoints share that
//! namespace with the coland operator infrastructure (seal DAG, bottom-cell
//! repair -- see [`super::seal`]) and the admin collection snapshot
//! (see [`super::collection`]); salvo router fallthrough keeps the three
//! sub-trees from colliding.

use arkret_identifiers::DidCoreId;
use coland_contracts::admin::{
    AdminServerInfo, AdminServerStats, AdminServerStatus, AdminServerStatusCounts,
};
use coland_http::error::AppError;
use coland_http::result::{JsonResult, json_ok};
use salvo::oapi::endpoint;
use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::audit::append_audit_log;
use super::{AdminAuth, require_admin_principal};
use crate::routing::identity::account::{AccountLifecycleChange, set_account_lifecycle_state};
use crate::state::AppState;

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
struct ColandAdminAccountStatusRequestBody {
    status: String,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, salvo::oapi::ToSchema)]
struct AdminAccountStateActionRequestBody {
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
struct AdminAccountLifecycleOutcome {
    account_id: arkret_wire::DidCoreId,
    previous_state: String,
    protocol_state: String,
    state: String,
    status: String,
    management_status: String,
    reason: Option<String>,
    updated_by: DidCoreId,
    changed_by: DidCoreId,
    updated_at: String,
    changed_at: String,
    sessions_revoked: usize,
    devices_revoked: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
struct AdminModerationQueueOutcome {
    /// `moderation-queue-item.schema.json` View items.
    #[salvo(schema(value_type = Vec<serde_json::Value>))]
    items: Vec<arkret_models_collaboration::governance::moderation_queue::ModerationQueueItem>,
    /// Original accepted Events whose require_review add is still active.
    #[salvo(schema(value_type = Vec<serde_json::Value>))]
    pending_review_events: Vec<arkret_wire::Event>,
    total: usize,
    generated_at: String,
}

pub(super) fn router() -> Router {
    Router::with_path("admin")
        .push(Router::with_path("server/status").get(get_server_status))
        .push(Router::with_path("server/info").get(get_server_info))
        .push(Router::with_path("server/stats").get(get_server_stats))
        .push(Router::with_path("accounts/{account_id}/status").post(update_account_status))
        .push(Router::with_path("accounts/{account_id}/lock").post(lock_account))
        .push(Router::with_path("accounts/{account_id}/unlock").post(unlock_account))
        .push(Router::with_path("accounts/{account_id}/suspend").post(suspend_account))
        .push(Router::with_path("accounts/{account_id}/unsuspend").post(unsuspend_account))
        .push(Router::with_path("accounts/{account_id}/deactivate").post(deactivate_account))
        // `GET /_coland/admin/moderation/queue` is the caller's moderation
        // queue View; the queue holds no writable state of its own.
        .push(Router::with_path("moderation/queue").get(get_moderation_queue))
}

#[endpoint(
    operation_id = "org.arkret.coland.admin.get_server_status",
    tags("coland_admin")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.admin.get_server_status"))]
async fn get_server_status(admin: AdminAuth, depot: &mut Depot) -> JsonResult<AdminServerStatus> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = admin.session()?;
    let session = require_admin_principal(state, session)?;
    let account_count = state
        .identities()
        .accounts()
        .await
        .map(|items| items.len())
        .ok();
    let device_count = state
        .identities()
        .devices()
        .await
        .map(|items| items.len())
        .ok();
    let realm_count = state
        .realm_directory()
        .snapshot()
        .search(Default::default())
        .len();
    json_ok(AdminServerStatus {
        status: AdminServerStatus::OK.to_owned(),
        service_id: DidCoreId::new(state.service_id().clone())
            .expect("AppState service_id must be a validated DID core id"),
        storage: state.jobs().storage_mode().to_owned(),
        development_mode: state.config().development_mode,
        checked_by: DidCoreId::new(session.actor)
            .expect("authenticated session actor must be a validated DID core id"),
        generated_at: arkret_canonical::format_timestamp_canonical(super::now()),
        counts: AdminServerStatusCounts {
            accounts: account_count,
            devices: device_count,
            realms: realm_count,
        },
    })
}

#[endpoint(
    operation_id = "org.arkret.coland.admin.get_server_info",
    tags("coland_admin")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.admin.get_server_info"))]
async fn get_server_info(admin: AdminAuth, depot: &mut Depot) -> JsonResult<AdminServerInfo> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = admin.session()?;
    let _ = require_admin_principal(state, session)?;
    json_ok(AdminServerInfo {
        server_version: env!("CARGO_PKG_VERSION").to_owned(),
        protocol_version: Some(arkret_wire::constants::PROTOCOL_VERSION.to_owned()),
        server_name: Some(state.service_id().clone()),
        uptime: None,
        service_id: DidCoreId::new(state.service_id().clone())
            .expect("AppState service_id must be a validated DID core id"),
        trust_domain: state.config().trust_domain.to_string(),
        development_mode: state.config().development_mode,
        allow_public_registration: state.account_registration_policy().enabled,
    })
}

#[endpoint(
    operation_id = "org.arkret.coland.admin.get_server_stats",
    tags("coland_admin")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.admin.get_server_stats"))]
async fn get_server_stats(admin: AdminAuth, depot: &mut Depot) -> JsonResult<AdminServerStats> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = admin.session()?;
    let _ = require_admin_principal(state, session)?;

    let accounts = state.identities().accounts().await.unwrap_or_default();
    let actor_count = accounts.len() as u64;
    let active_actor_count = accounts
        .iter()
        .filter(|account| state.account_lifecycle_state(account.principal_id.as_str()) == "active")
        .count() as u64;
    let realm_count = state
        .realm_directory()
        .snapshot()
        .search(Default::default())
        .len() as u64;
    let device_count = state
        .identities()
        .devices()
        .await
        .map(|items| items.len() as u64)
        .unwrap_or(0);
    let report_count = state
        .governance()
        .moderation_report_count()
        .await
        .unwrap_or(0);
    let federation_peer_count = state.settings().federation_peers.len() as u64;
    let applet_count = {
        let proj = state.projections().snapshot();
        proj.applets.len() as u64
    };
    let blobs = state.deliveries().blobs().await.unwrap_or_default();
    let blob_count = blobs.len() as u64;
    let blob_total_size = blobs.iter().map(|blob| blob.size_bytes as u64).sum();

    json_ok(AdminServerStats {
        actor_count,
        active_actor_count,
        realm_count,
        device_count,
        report_count,
        federation_peer_count,
        applet_count,
        blob_count,
        blob_total_size,
        generated_at: arkret_canonical::format_timestamp_canonical(super::now()),
    })
}

#[endpoint(
    operation_id = "org.arkret.coland.admin.update_account_status",
    tags("coland_admin")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.admin.update_account_status"))]
async fn update_account_status(
    admin: AdminAuth,
    depot: &mut Depot,
    account_id: PathParam<String>,
    body: JsonBody<ColandAdminAccountStatusRequestBody>,
) -> JsonResult<AdminAccountLifecycleOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = admin.session()?;
    let session = require_admin_principal(state, session)?;
    let account_id = account_id.into_inner();
    let body = body.into_inner();
    let status = body.status.trim();
    if status.is_empty() {
        return Err(AppError::param_invalid("status is required"));
    }
    let status = status.to_owned();
    admin_set_account_status(state, &session.actor, &account_id, &status, body.reason).await
}

#[endpoint(
    operation_id = "org.arkret.coland.admin.lock_account",
    tags("coland_admin")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.admin.lock_account"))]
async fn lock_account(
    admin: AdminAuth,
    depot: &mut Depot,
    account_id: PathParam<String>,
    body: JsonBody<AdminAccountStateActionRequestBody>,
) -> JsonResult<AdminAccountLifecycleOutcome> {
    admin_account_state_action(admin, depot, account_id, body, "locked").await
}

#[endpoint(
    operation_id = "org.arkret.coland.admin.unlock_account",
    tags("coland_admin")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.admin.unlock_account"))]
async fn unlock_account(
    admin: AdminAuth,
    depot: &mut Depot,
    account_id: PathParam<String>,
    body: JsonBody<AdminAccountStateActionRequestBody>,
) -> JsonResult<AdminAccountLifecycleOutcome> {
    admin_account_state_action(admin, depot, account_id, body, "active").await
}

#[endpoint(
    operation_id = "org.arkret.coland.admin.suspend_account",
    tags("coland_admin")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.admin.suspend_account"))]
async fn suspend_account(
    admin: AdminAuth,
    depot: &mut Depot,
    account_id: PathParam<String>,
    body: JsonBody<AdminAccountStateActionRequestBody>,
) -> JsonResult<AdminAccountLifecycleOutcome> {
    admin_account_state_action(admin, depot, account_id, body, "suspended").await
}

#[endpoint(
    operation_id = "org.arkret.coland.admin.unsuspend_account",
    tags("coland_admin")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.admin.unsuspend_account"))]
async fn unsuspend_account(
    admin: AdminAuth,
    depot: &mut Depot,
    account_id: PathParam<String>,
    body: JsonBody<AdminAccountStateActionRequestBody>,
) -> JsonResult<AdminAccountLifecycleOutcome> {
    admin_account_state_action(admin, depot, account_id, body, "active").await
}

#[endpoint(
    operation_id = "org.arkret.coland.admin.deactivate_account",
    tags("coland_admin")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.admin.deactivate_account"))]
async fn deactivate_account(
    admin: AdminAuth,
    depot: &mut Depot,
    account_id: PathParam<String>,
    body: JsonBody<AdminAccountStateActionRequestBody>,
) -> JsonResult<AdminAccountLifecycleOutcome> {
    admin_account_state_action(admin, depot, account_id, body, "deactivated").await
}

async fn admin_account_state_action(
    admin: AdminAuth,
    depot: &mut Depot,
    account_id: PathParam<String>,
    body: JsonBody<AdminAccountStateActionRequestBody>,
    next_state: &str,
) -> JsonResult<AdminAccountLifecycleOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = admin.session()?;
    let session = require_admin_principal(state, session)?;
    admin_set_account_status(
        state,
        &session.actor,
        &account_id.into_inner(),
        next_state,
        body.into_inner().reason,
    )
    .await
}

async fn admin_set_account_status(
    state: &AppState,
    admin_actor: &str,
    account_id: &str,
    next_state: &str,
    reason: Option<String>,
) -> JsonResult<AdminAccountLifecycleOutcome> {
    let normalized = normalize_admin_account_status(next_state, reason)?;
    let reason = normalized.reason.clone();
    let change = set_account_lifecycle_state(
        state,
        account_id,
        normalized.protocol_state,
        admin_actor,
        reason.clone(),
    )
    .await?;
    append_audit_log(
        state,
        Some(admin_actor),
        "admin.account.set_status",
        json!({
            "account_id": account_id,
            "status": normalized.management_status,
            "protocol_state": normalized.protocol_state,
            "reason": reason,
        }),
        "accepted",
    )
    .await;
    json_ok(account_lifecycle_change_response(
        change,
        normalized.management_status,
    ))
}

struct AdminAccountStatusProjection {
    protocol_state: &'static str,
    management_status: String,
    reason: Option<String>,
}

fn normalize_admin_account_status(
    status: &str,
    reason: Option<String>,
) -> Result<AdminAccountStatusProjection, AppError> {
    let management_status = status.trim();
    if management_status.is_empty() {
        return Err(AppError::param_invalid("status is required"));
    }
    let reason = reason
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    let (protocol_state, default_reason) = match management_status {
        "active" => ("active", None),
        "locked" => ("locked", None),
        "suspended" => ("suspended", None),
        "deactivated" => ("deactivated", None),
        "disabled" => ("deactivated", Some("disabled")),
        "recovery_locked" => ("locked", Some("recovery_locked")),
        "pending_deletion" | "erasure_pending" => {
            return Err(AppError::param_invalid(
                "pending deletion must use the account erasure flow",
            ));
        }
        _ => {
            return Err(AppError::param_invalid(
                "status must be active, locked, suspended, deactivated, disabled, or recovery_locked",
            ));
        }
    };
    let reason = reason.or_else(|| default_reason.map(str::to_owned));
    Ok(AdminAccountStatusProjection {
        protocol_state,
        management_status: management_status.to_owned(),
        reason,
    })
}

fn account_lifecycle_change_response(
    change: AccountLifecycleChange,
    management_status: String,
) -> AdminAccountLifecycleOutcome {
    let principal_id = change.principal_id;
    let state = change.state;
    let changed_by = change.changed_by;
    let changed_at = arkret_canonical::format_timestamp_canonical(change.changed_at);
    AdminAccountLifecycleOutcome {
        account_id: principal_id,
        previous_state: change.previous_state,
        protocol_state: state.clone(),
        state: state.clone(),
        status: management_status.clone(),
        management_status,
        reason: change.reason,
        updated_by: changed_by.clone(),
        changed_by,
        updated_at: changed_at.clone(),
        changed_at,
        sessions_revoked: change.sessions_revoked,
        devices_revoked: change.devices_revoked,
    }
}

#[endpoint(
    operation_id = "org.arkret.coland.admin.get_moderation_queue",
    tags("coland_admin")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.admin.get_moderation_queue"))]
async fn get_moderation_queue(
    admin: AdminAuth,
    depot: &mut Depot,
) -> JsonResult<AdminModerationQueueOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = admin.session()?;
    let session = require_admin_principal(state, session)?;
    let view = crate::routing::interop::moderation::moderation_management_view_for_session(
        state,
        &session.actor,
        None,
    )
    .await?;
    let total = view.items.len() + view.pending_review_events.len();
    json_ok(AdminModerationQueueOutcome {
        items: view.items,
        pending_review_events: view.pending_review_events,
        total,
        generated_at: arkret_canonical::format_timestamp_canonical(super::now()),
    })
}
