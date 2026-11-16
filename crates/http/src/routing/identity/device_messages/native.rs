//! Realm Device Welcome queue access without constructing a bearer Session.
use super::*;
use crate::routing::identity::applet_managed_device::{self, VerifiedAppletManagedDevice};

fn unavailable(error: coland_services::ServiceError) -> AppError {
    tracing::debug!(%error, "native recipient queue admission unavailable");
    if error.conflict_code() == Some(coland_storage::ConflictCode::TemporarilyUnavailable) {
        return crate::app_error!(
            TemporarilyUnavailable,
            "native recipient queue authority cut is unavailable"
        );
    }
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
) -> coland_http::result::GuardedJsonResult<DeviceMessagesGetResponseBody> {
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
    body: &DeviceMessagesAcknowledgementRequestBody,
) -> JsonResult<DeviceMessagesAcknowledgementResponseBody> {
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
    json_ok(DeviceMessagesAcknowledgementResponseBody {
        pruned_count: count as u64,
    })
}

#[cfg(test)]
mod queue_error_tests {
    use salvo::http::StatusCode;

    use super::*;

    #[test]
    fn original_typed_queue_authority_busy_stays_503() {
        let error = unavailable(
            coland_storage::PersistenceError::Conflict(
                "temporarily_unavailable: the native authority cut lost a concurrent write race"
                    .into(),
            )
            .into(),
        );
        assert_eq!(error.code, arkret_wire::ErrorCode::TemporarilyUnavailable);
        assert_eq!(error.http_status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn missing_or_refused_queue_is_not_reclassified_by_diagnostic_text() {
        for error in [
            coland_storage::PersistenceError::NotFound("native queue".into()),
            coland_storage::PersistenceError::Conflict(
                "capability_denied: recipient scope refused".into(),
            ),
            coland_storage::PersistenceError::Conflict(
                "failed_precondition: diagnostic merely mentions temporarily_unavailable".into(),
            ),
        ] {
            let error = unavailable(error.into());
            assert_eq!(error.http_status(), StatusCode::NOT_FOUND);
        }
        let expired = unavailable(
            coland_storage::PersistenceError::Conflict(
                "cursor_expired: original expiry ended".into(),
            )
            .into(),
        );
        assert_eq!(expired.code, arkret_wire::ErrorCode::CursorExpired);
    }
}
