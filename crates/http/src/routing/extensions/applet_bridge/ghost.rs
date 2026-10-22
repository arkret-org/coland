//! Installation revocation and exact Ghost creation permission selection.
use arkret_wire::CapabilityActionId;
use coland_http::error::AppError;
use serde_json::json;

use super::record::{applet_record, fence_applet_record};
use super::types::AppletRecord;
use crate::state::AppState;

pub(super) async fn revoke_applet_record_after_admin_gate(
    state: &AppState,
    actor: &str,
    applet_id: &str,
    service_id: &str,
    effective_scope: &arkret_wire::ScopeRef,
) -> Result<(), AppError> {
    revoke_applet_record_inner(state, actor, applet_id, service_id, effective_scope).await
}

async fn revoke_applet_record_inner(
    state: &AppState,
    actor: &str,
    applet_id: &str,
    service_id: &str,
    effective_scope: &arkret_wire::ScopeRef,
) -> Result<(), AppError> {
    let mut attempts = 0_u8;
    let (record, globally_fenced) = loop {
        let current = applet_record(state, applet_id, service_id, effective_scope)
            .await?
            .ok_or_else(|| AppError::not_found("applet is not registered"))?;
        if current.status == "revoked" {
            break (
                current.clone(),
                current.identity.globally_fenced_at.is_some(),
            );
        }
        let mut replacement = current.clone();
        let fenced_at = chrono::Utc::now();
        replacement.status = "revoked".to_owned();
        replacement.revoked_at = Some(fenced_at);
        let outcome = fence_applet_record(state, &current, &replacement, fenced_at).await?;
        if outcome.updated {
            break (replacement, outcome.globally_fenced);
        }
        attempts += 1;
        if attempts >= 8 {
            return Err(
                AppError::conflict("Applet record changed repeatedly during revoke")
                    .with_wire_code("cas_conflict"),
            );
        }
    };
    if record.revoked_at.is_none() {
        return Err(AppError::internal("revoked Applet has no revoked_at"));
    }
    crate::routing::append_audit_log(
        state,
        Some(actor),
        "extensions.applet.revoke",
        json!({
            "applet_id": record.applet_id.clone(),
            "bot_actor_ids": record.bots.iter().map(|bot| &bot.bot_actor_id).collect::<Vec<_>>(),
            "ghost_count": record.ghosts.len(),
            "globally_fenced": globally_fenced,
        }),
        "accepted",
    )
    .await;
    Ok(())
}

pub(super) fn ghost_provision_authorization_ref(record: &AppletRecord) -> Result<String, AppError> {
    if !record
        .capabilities
        .iter()
        .any(|action| action == CapabilityActionId::APPLET_GHOST_PROVISION)
    {
        return Err(AppError::capability_denied(
            "applet install does not grant ak.applet.ghost.provision",
        ));
    }
    for event in &record.capability_grant_events {
        let payload = serde_json::from_value::<
            arkret_models_collaboration::events_payloads::CapabilityGrantPayload,
        >(serde_json::to_value(&event.payload).map_err(|error| {
            AppError::internal(format!(
                "stored Applet capability grant payload cannot be encoded: {error}"
            ))
        })?)
        .map_err(|error| {
            AppError::internal(format!(
                "stored Applet capability grant payload is invalid: {error}"
            ))
        })?;
        if payload
            .grant
            .actions
            .iter()
            .any(|action| action == CapabilityActionId::APPLET_GHOST_PROVISION)
        {
            return Ok(arkret_identifiers::GrantId::from_event_id(&event.event_id).to_string());
        }
    }
    Err(
        AppError::conflict("applet ghost provisioning grant projection is incomplete")
            .with_internal_reason("applet_install_projection_incomplete"),
    )
}
