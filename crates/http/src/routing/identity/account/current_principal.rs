use arkret_models_identity::{CurrentPrincipalOutcome, CurrentPrincipalRequestBody};
use arkret_wire::ErrorCode;
use coland_storage::CurrentPrincipalRead;

use super::*;

fn validation(error: arkret_wire::WireError) -> AppError {
    match error {
        arkret_wire::WireError::ProtocolCode { code, message } => {
            AppError::from_rejection(code, message)
        }
        error => crate::app_error!(SchemaViolation, error.to_string()),
    }
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.current_principal.read.resolve",
    tags("identity")
)]
pub(super) async fn resolve(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<CurrentPrincipalOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let bytes = req
        .payload()
        .await
        .map_err(|_| crate::app_error!(SchemaViolation, "invalid current principal request",))?;
    if bytes.len() > arkret_models_identity::identity_resolution::CURRENT_PRINCIPAL_MAX_BYTES {
        return Err(crate::app_error!(
            PayloadTooLarge,
            "current principal request exceeds byte budget",
        ));
    }
    let body: CurrentPrincipalRequestBody = serde_json::from_slice(bytes)
        .map_err(|_| crate::app_error!(SchemaViolation, "invalid current principal request",))?;
    body.validate().map_err(validation)?;
    if body.account_id.principal_id.as_str() != session.actor
        || body.account_id.station_id.as_str() != state.service_id()
    {
        return Err(AppError::not_found("current principal not found"));
    }
    let read = state
        .persistence()
        .current_principal(&body.account_id)
        .await
        .map_err(|_| crate::app_error!(TemporarilyUnavailable, "current principal unavailable",))?;
    let CurrentPrincipalRead::Ready {
        pcr_realm_id,
        projection,
        ..
    } = read
    else {
        // Authentication establishes that this own account exists; no creation
        // anchor/current cell yet is unavailable, not an absent profile.
        return Err(crate::app_error!(
            TemporarilyUnavailable,
            "current principal unavailable",
        ));
    };
    let result = CurrentPrincipalOutcome {
        request_id: body.request_id.clone(),
        account_id: body.account_id.clone(),
        principal_control_realm_id: pcr_realm_id,
        resolution_projection: projection,
    };
    result.validate_for_request(&body).map_err(|error| {
        let code = if error.error_code() == Some(ErrorCode::LimitExceeded) {
            ErrorCode::LimitExceeded
        } else {
            ErrorCode::TemporarilyUnavailable
        };
        AppError::from_rejection(code, "current principal result unavailable")
    })?;
    json_ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn budget_errors_keep_their_registered_codes() {
        for code in [ErrorCode::PayloadTooLarge, ErrorCode::LimitExceeded] {
            assert_eq!(
                validation(arkret_wire::WireError::ProtocolCode {
                    code,
                    message: "budget".into()
                })
                .code,
                code
            );
        }
    }
}
