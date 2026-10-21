//! Realm Device Welcome queue access without constructing a bearer Session.
use super::*;
use crate::routing::identity::applet_managed_device::{self, VerifiedAppletManagedDevice};

fn unavailable(error: coland_services::ServiceError) -> AppError {
    tracing::debug!(%error, "native recipient queue admission unavailable");
    match error {
        coland_services::ServiceError::Conflict(detail)
            if detail.starts_with("cursor_expired:") =>
        {
            crate::app_error!(CursorExpired, "native queue cursor expired")
        }
        coland_services::ServiceError::Conflict(detail)
            if detail.starts_with("cursor_revoked:") =>
        {
            crate::app_error!(CursorRevoked, "native queue cursor authority was revoked")
        }
        coland_services::ServiceError::Conflict(detail)
            if detail.starts_with("cursor_integrity_invalid:") =>
        {
            crate::app_error!(
                CursorIntegrityInvalid,
                "native queue cursor does not match this endpoint and scope"
            )
        }
        coland_services::ServiceError::Conflict(_) | coland_services::ServiceError::NotFound(_) => {
            AppError::not_found("native recipient queue is unavailable")
        }
        _ => crate::app_error!(
            TemporarilyUnavailable,
            "native recipient queue persistence is unavailable"
        ),
    }
}

pub(super) async fn list(
    state: &AppState,
    native: &VerifiedAppletManagedDevice,
    after: Option<&str>,
    limit: Option<u32>,
) -> coland_http::result::GuardedJsonResult<DeviceMessagesGetOutcome> {
    if native.operation != arkret_wire::ServiceOperationId::SelfDeviceMessagesReadListV1 {
        return Err(AppError::capability_denied(
            "native queue operation is invalid",
        ));
    }
    let limit = match limit {
        Some(0) => return Err(AppError::param_invalid("limit must be greater than zero")),
        Some(value) => (value as usize).min(TO_DEVICE_PAGE_LIMIT),
        None => TO_DEVICE_DEFAULT_PAGE_LIMIT,
    };
    let endpoint = applet_managed_device::scope_guard(state, native).await?;
    let page = state
        .deliveries()
        .applet_device_queue(coland_storage::AppletDeviceQueueRead {
            endpoint: &endpoint,
            after,
            limit,
            transport_expires_at: native.transport_expires_at,
        })
        .await
        .map_err(unavailable)?;
    coland_http::result::guarded_json_ok(page.outcome, Some(page.guard))
}

pub(super) async fn ack(
    state: &AppState,
    native: &VerifiedAppletManagedDevice,
    body: &DeviceMessagesAckRequestBody,
) -> JsonResult<DeviceMessagesAckOutcome> {
    if native.operation != arkret_wire::ServiceOperationId::SelfDeviceMessagesCommandAckV1 {
        return Err(AppError::capability_denied(
            "native ACK operation is invalid",
        ));
    }
    let count = state
        .deliveries()
        .ack_applet_device_queue(coland_storage::AppletDeviceQueueAck {
            authority: &native.authority,
            effective_scope: &native.metadata.effective_scope,
            body,
            transport_expires_at: native.transport_expires_at,
        })
        .await
        .map_err(unavailable)?
        .ok_or_else(|| {
            AppError::param_invalid("invalid ack token")
                .with_reason_code(arkret_wire::ReasonCode::INVALID_ACK_TOKEN)
        })?;
    json_ok(DeviceMessagesAckOutcome {
        pruned_count: count as u64,
    })
}
