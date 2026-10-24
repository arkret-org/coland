//! Operator handle-management admin surface (Wave 3 / T6.2 §2).
//!
//! Endpoints (product-local operator surface, `org.arkret.coland.*` op IDs):
//!
//! - `GET  /_coland/admin/handles` — paginated list of handle rows.
//! - `GET  /_coland/admin/handles/{id}` — single handle row.
//! - `GET  /_coland/admin/handles/{id}/audit` — handle audit trail from the shared audit table.
//! - `POST /_coland/admin/handles/{id}/revoke` — operator-level handle revocation (releases the
//!   durable account binding + records the audit trail).
//! - `POST /_coland/admin/handles/{id}/reassign` — operator-level re-bind of a handle to a new
//!   subject DID.
//!
//! Authoritative data source: the durable `account_localparts` table. Each row
//! carries a bare `localpart`; the canonical handle is `@<localpart>`. The
//! handle id surfaced to operators is the localpart (stable and URL-safe).
//! The local handle-claim evidence cache
//! ([`crate::state::MemberIdentityRegistry`]) enriches rows with
//! issuer / binding-state metadata when present. Wire shapes mirror codmin's
//! `HandleRecord` / `HandleAuditEvent` / `HandleReassignRequest` DTOs
//! (`codmin/src/types/handles.rs`).
//!
//! The collection list (`GET /_coland/admin/handles`) is also reachable via
//! the generic `/_coland/admin/{resource}` snapshot — both share
//! [`admin_handle_items`].

use coland_contracts::admin::handles::{
    AdminHandleAuditEvent, AdminHandleAuditPage, AdminHandlePage, AdminHandleReassignBody,
    AdminHandleRevokeBody, AdminHandleView,
};
use coland_http::error::AppError;
use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use serde_json::{Value, json};

use super::{AdminAuth, append_audit_log, require_admin_principal};
use crate::state::AppState;

const DESTRUCTIVE_REASON_MAX_CHARS: usize = 512;
use crate::{JsonResult, json_ok};

fn validate_destructive_reason(reason: &str) -> Result<String, AppError> {
    let reason = reason.trim();
    if reason.is_empty() {
        return Err(AppError::param_invalid("reason is required"));
    }
    if reason.chars().count() > DESTRUCTIVE_REASON_MAX_CHARS {
        return Err(AppError::param_invalid(
            "reason must not exceed 512 characters",
        ));
    }
    if reason.chars().any(char::is_control) {
        return Err(AppError::param_invalid("reason must be a single line"));
    }

    let lower = reason.to_ascii_lowercase();
    const SENSITIVE_MARKERS: &[&str] = &[
        "-----begin private key",
        "authorization:",
        "bearer ey",
        "password=",
        "secret=",
        "token=",
    ];
    if SENSITIVE_MARKERS
        .iter()
        .any(|marker| lower.contains(marker))
    {
        return Err(AppError::param_invalid(
            "reason must not contain credentials or secrets",
        ));
    }
    Ok(reason.to_owned())
}

pub(super) fn router() -> Router {
    Router::with_path("handles").get(list_handles).push(
        Router::with_path("{handle_id}")
            .get(get_handle)
            .push(Router::with_path("audit").get(get_handle_audit))
            .push(Router::with_path("revoke").post(revoke_handle))
            .push(Router::with_path("reassign").post(reassign_handle)),
    )
}

/// Build the full handle row set off the durable accounts table, enriched
/// with local handle-claim evidence. Shared with the generic admin
/// collection snapshot (`/_coland/admin/handles`).
pub(super) async fn admin_handle_items(state: &AppState) -> Vec<AdminHandleView> {
    // Index handle-claim evidence by subject DID so account rows can pick
    // up issuer / status metadata when a directory-issued claim is
    // cached locally.
    let claims_by_subject = state.handle_claims_snapshot();

    let accounts = state.identities().accounts().await.unwrap_or_default();

    let mut rows = Vec::new();
    for account in accounts {
        let localparts = state
            .identities()
            .account_localparts(account.pk)
            .await
            .unwrap_or_default();
        for localpart in localparts {
            let evidence = claims_by_subject.get(&account.principal_id);
            let primary_claim = evidence.and_then(|records| records.first());
            let status = match primary_claim {
                Some(record) => record.status.clone(),
                None => "active".to_owned(),
            };
            let handle = format!("@{}", localpart.localpart);
            rows.push(AdminHandleView {
                id: localpart.localpart.clone(),
                canonical_uri: format!("ak:handle:{handle}"),
                aliases: vec![handle],
                issuer_id: primary_claim
                    .map(|record| record.issuer_id.clone())
                    .unwrap_or_else(|| {
                        arkret_wire::DidCoreId::new(state.service_id().clone())
                            .expect("runtime service_id must be a DidCoreId")
                    }),
                subject_id: account.principal_id.clone(),
                assigned_at: Some(arkret_canonical::format_timestamp_canonical(
                    localpart.created_at,
                )),
                expires_at: primary_claim.and_then(|record| {
                    record
                        .expires_at
                        .map(arkret_canonical::format_timestamp_canonical)
                }),
                last_reassignment_at: None,
                status: Some(status),
            });
        }
    }
    rows
}

/// Resolve a single handle row by its operator id (the account localpart).
async fn handle_record_by_id(
    state: &AppState,
    handle_id: &str,
) -> Result<AdminHandleView, AppError> {
    admin_handle_items(state)
        .await
        .into_iter()
        .find(|record| record.id == handle_id)
        .ok_or_else(|| AppError::not_found("handle not found"))
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.coland.admin.handles.list",
    tags("coland_admin")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.admin.handles.list"))]
async fn list_handles(
    admin: AdminAuth,
    page: QueryParam<u64, false>,
    per_page: QueryParam<u64, false>,
    search: QueryParam<String, false>,
    depot: &mut Depot,
) -> JsonResult<AdminHandlePage> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = admin.session()?;
    let _ = require_admin_principal(state, session)?;

    let page = page.into_inner().unwrap_or(1).max(1);
    let per_page = per_page.into_inner().unwrap_or(50).clamp(1, 500);
    let search = search.into_inner().unwrap_or_default();
    let needle = search.trim().to_lowercase();

    let mut rows = admin_handle_items(state).await;
    if !needle.is_empty() {
        rows.retain(|row| {
            row.id.to_lowercase().contains(&needle)
                || row.canonical_uri.to_lowercase().contains(&needle)
                || row.subject_id.as_str().to_lowercase().contains(&needle)
                || row
                    .aliases
                    .iter()
                    .any(|alias| alias.to_lowercase().contains(&needle))
        });
    }
    rows.sort_by(|a, b| a.id.cmp(&b.id));

    let total = rows.len() as u64;
    let start = ((page - 1) * per_page) as usize;
    let window: Vec<AdminHandleView> = rows
        .into_iter()
        .skip(start)
        .take(per_page as usize)
        .collect();
    let has_more = (start as u64) + (window.len() as u64) < total;
    let next_cursor = has_more.then(|| (page + 1).to_string());

    json_ok(AdminHandlePage {
        data: window,
        total,
        next_cursor,
    })
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.coland.admin.handles.get",
    tags("coland_admin")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.admin.handles.get"))]
async fn get_handle(
    admin: AdminAuth,
    handle_id: PathParam<String>,
    depot: &mut Depot,
) -> JsonResult<AdminHandleView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = admin.session()?;
    let _ = require_admin_principal(state, session)?;
    json_ok(handle_record_by_id(state, &handle_id.into_inner()).await?)
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.coland.admin.handles.audit",
    tags("coland_admin")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.admin.handles.audit"))]
async fn get_handle_audit(
    admin: AdminAuth,
    handle_id: PathParam<String>,
    depot: &mut Depot,
) -> JsonResult<AdminHandleAuditPage> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = admin.session()?;
    let _ = require_admin_principal(state, session)?;
    let handle_id = handle_id.into_inner();
    // Confirm the handle exists so the operator gets a clean 404 rather
    // than an empty list for a non-existent handle.
    let record = handle_record_by_id(state, &handle_id).await?;
    let handle_at = record.aliases.first().cloned().unwrap_or_default();

    let entries = state.governance().audit_entries().await.unwrap_or_default();
    let mut data: Vec<AdminHandleAuditEvent> = entries
        .into_iter()
        .filter(|entry| audit_entry_mentions_handle(entry, &handle_id, &handle_at))
        .map(audit_entry_to_handle_event)
        .collect();
    data.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
    let total = data.len() as u64;

    json_ok(AdminHandleAuditPage {
        data,
        total,
        next_cursor: None,
    })
}

/// True when an audit entry references the handle by its localpart id or by
/// its `@<localpart>` form. Handle-related actions are matched both on the
/// action verb and on a payload mention so re-keyed actions still surface.
fn audit_entry_mentions_handle(entry: &Value, handle_id: &str, handle_at: &str) -> bool {
    let action = entry.get("action").and_then(Value::as_str).unwrap_or("");
    if !action.contains("handle") {
        return false;
    }
    let serialized = entry.to_string();
    serialized.contains(handle_id) || (!handle_at.is_empty() && serialized.contains(handle_at))
}

fn audit_entry_to_handle_event(entry: Value) -> AdminHandleAuditEvent {
    let payload = entry.get("payload");
    AdminHandleAuditEvent {
        id: entry
            .get("id")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .unwrap_or_default(),
        action: entry
            .get("action")
            .and_then(Value::as_str)
            .unwrap_or("handle")
            .to_owned(),
        actor_id: entry
            .get("actor")
            .or_else(|| entry.get("actor_id"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        timestamp: entry
            .get("created_at")
            .or_else(|| entry.get("timestamp"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        reason: payload
            .and_then(|value| value.get("reason"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        previous_subject_id: payload
            .and_then(|value| value.get("previous_subject_id"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        new_subject_id: payload
            .and_then(|value| value.get("new_subject_id"))
            .and_then(Value::as_str)
            .map(str::to_owned),
    }
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.coland.admin.handles.revoke",
    tags("coland_admin")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.admin.handles.revoke"))]
async fn revoke_handle(
    admin: AdminAuth,
    handle_id: PathParam<String>,
    body: JsonBody<AdminHandleRevokeBody>,
    depot: &mut Depot,
) -> JsonResult<AdminHandleView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = admin.session()?;
    let session = require_admin_principal(state, session)?;
    let handle_id = handle_id.into_inner();
    let reason = body.into_inner().reason;

    let record = handle_record_by_id(state, &handle_id).await?;
    let subject_id = record.subject_id.clone();

    // Operator revocation releases the durable account-localpart binding and
    // records the release in the post-release grace ledger.
    let released = handle_id.clone();
    if let Some(owner) = state
        .identities()
        .localpart_owner(&released)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
    {
        state
            .identities()
            .remove_localpart(owner.account_pk, &released)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?;
    }
    crate::routing::identity::account::record_handle_release(state, &released)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;

    append_audit_log(
        state,
        Some(&session.actor),
        "admin.handle.revoke",
        json!({
            "handle_id": handle_id,
            "handle": format!("@{released}"),
            "previous_subject_id": subject_id,
            "reason": reason,
        }),
        "accepted",
    )
    .await;

    let mut revoked = record;
    revoked.status = Some("revoked".to_owned());
    json_ok(revoked)
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.coland.admin.handles.reassign",
    tags("coland_admin")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.admin.handles.reassign"))]
async fn reassign_handle(
    admin: AdminAuth,
    handle_id: PathParam<String>,
    body: JsonBody<AdminHandleReassignBody>,
    depot: &mut Depot,
) -> JsonResult<AdminHandleView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = admin.session()?;
    let session = require_admin_principal(state, session)?;
    let handle_id = handle_id.into_inner();
    let body = body.into_inner();
    let new_subject_id = body.new_subject_id;
    let reason = validate_destructive_reason(&body.reason)?;

    let record = handle_record_by_id(state, &handle_id).await?;
    let previous_subject_id = record.subject_id.clone();

    // The localpart that backs this handle is the operator id itself.
    let localpart = record
        .aliases
        .first()
        .map(|alias| alias.trim_start_matches('@').to_owned())
        .unwrap_or_else(|| handle_id.clone());

    // Target account must exist before we re-bind onto it.
    let target = state
        .identities()
        .account(&arkret_wire::AccountId::new(
            new_subject_id.clone(),
            state.service_core_id().clone(),
        ))
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::not_found("target subject account not found"))?;

    // Detach the handle from its current holder, if a different account
    // still carries the localpart.
    if previous_subject_id != new_subject_id
        && let Some(owner) = state
            .identities()
            .localpart_owner(&localpart)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
    {
        state
            .identities()
            .remove_localpart(owner.account_pk, &localpart)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?;
    }

    state
        .identities()
        .add_localpart(target.pk, &localpart, true)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;

    let now = super::now();
    append_audit_log(
        state,
        Some(&session.actor),
        "admin.handle.reassign",
        json!({
            "handle_id": handle_id,
            "handle": format!("@{localpart}"),
            "previous_subject_id": previous_subject_id,
            "new_subject_id": new_subject_id,
            "reason": reason,
        }),
        "accepted",
    )
    .await;

    let mut reassigned = record;
    reassigned.subject_id = new_subject_id;
    reassigned.last_reassignment_at = Some(arkret_canonical::format_timestamp_canonical(now));
    reassigned.status = Some("active".to_owned());
    json_ok(reassigned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destructive_reason_policy_rejects_secrets_and_multiline_text() {
        assert!(validate_destructive_reason("SEC-1234 forced reassignment").is_ok());
        assert!(validate_destructive_reason("first\nsecond").is_err());
        assert!(validate_destructive_reason("password=hunter2").is_err());
        assert!(validate_destructive_reason(&"x".repeat(513)).is_err());
    }

    #[test]
    fn destructive_reason_policy_trims_and_blocks_all_credential_markers() {
        assert_eq!(
            validate_destructive_reason("  incident INC-42  ").unwrap(),
            "incident INC-42"
        );
        assert!(validate_destructive_reason("authorization: Bearer abc").is_err());
        assert!(validate_destructive_reason("BEARER eyJhbGciOi").is_err());
        assert!(validate_destructive_reason("secret=rotation-key").is_err());
        assert!(validate_destructive_reason("token=opaque-value").is_err());
        assert!(validate_destructive_reason("-----BEGIN PRIVATE KEY-----").is_err());
        assert!(validate_destructive_reason("\t").is_err());
    }
}
