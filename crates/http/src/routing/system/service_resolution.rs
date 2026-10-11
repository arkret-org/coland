use arkret_models_identity::{AuthenticatedServiceResolution, DidDocument};
use arkret_wire::DidCoreId;
use chrono::Utc;
use coland_http::error::AppError;
use salvo::oapi::extract::PathParam;
use salvo::prelude::*;

use crate::AppResult;
use crate::state::AppState;
const MAX_AUTHENTICATED_RESOLUTION_BYTES: usize = 1024 * 1024;
pub(super) fn open_router() -> Router {
    Router::with_path("services/{service_id}/resolution").get(open_service_resolution)
}
pub(crate) fn service_id_and_did(
    state: &AppState,
) -> Result<(DidCoreId, arkret_wire::Did), AppError> {
    let commitment = state.service_resolution_commitment();
    let core = arkret_wire::project_did_to_core_id(&commitment.did)
        .map_err(|e| AppError::internal(e.to_string()))?;
    Ok((core, commitment.did.clone()))
}
#[salvo::oapi::endpoint(operation_id = "ak.open.service.read.resolution.v1", tags("identity"))]
async fn open_service_resolution(
    service_id: PathParam<String>,
    depot: &mut Depot,
    res: &mut Response,
) -> AppResult<()> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let requested = DidCoreId::new(service_id.into_inner())
        .map_err(|_| AppError::not_found("service resolution not found"))?;
    let (current, _) = service_id_and_did(state)?;
    if requested != current {
        return Err(AppError::not_found("service resolution not found"));
    }
    let authenticated = current_authenticated_service_resolution(state).await?;
    let body = arkret_canonical::canonical_json_string(&authenticated).map_err(|error| {
        AppError::internal(format!(
            "service resolution canonical encoding failed: {error}"
        ))
    })?;
    if body.len() > MAX_AUTHENTICATED_RESOLUTION_BYTES {
        return Err(crate::app_error!(
            LimitExceeded,
            "authenticated service resolution exceeds 1 MiB",
        ));
    }
    res.render(Text::Json(body));
    Ok(())
}

pub(crate) async fn current_authenticated_service_resolution(
    state: &AppState,
) -> Result<AuthenticatedServiceResolution, AppError> {
    let stored = state
        .stored_service_identity()
        .await
        .map_err(|e| crate::app_error!(ServiceIdentityProviderUnavailable, e))?;
    let normalized_document: DidDocument =
        serde_json::from_value(serde_json::to_value(&stored.did_document).map_err(|error| {
            AppError::internal(format!("service DID document encoding failed: {error}"))
        })?)
        .map_err(|error| {
            crate::app_error!(
                ServiceIdentityProviderUnavailable,
                format!("service DID document normalization failed: {error}"),
            )
        })?;
    let mut events = state
        .dids()
        .log_events(stored.identity.did.as_str())
        .await
        .map_err(|error| {
            crate::app_error!(
                ServiceIdentityProviderUnavailable,
                format!("durable service WebVH history unavailable: {error}"),
            )
        })?;
    events.sort_by(|left, right| {
        (left.seq, left.event_digest.as_str()).cmp(&(right.seq, right.event_digest.as_str()))
    });
    let terminal = events
        .iter()
        .position(|event| {
            event.event_digest == stored.registration_receipt.log_head_digest
                && event
                    .operation
                    .get("versionId")
                    .and_then(serde_json::Value::as_str)
                    == Some(stored.identity.version_id.as_str())
        })
        .ok_or_else(|| {
            crate::app_error!(
                ServiceIdentityProviderUnavailable,
                "durable service WebVH history does not contain the current DID head",
            )
        })?;
    let log_entries = events
        .into_iter()
        .take(terminal + 1)
        .map(|event| event.operation)
        .collect::<Vec<_>>();
    let now = chrono::DateTime::<Utc>::from_timestamp_millis(Utc::now().timestamp_millis())
        .ok_or_else(|| AppError::internal("current service resolution timestamp is invalid"))?;
    arkret_identity::build_authenticated_webvh_service_resolution(
        stored.identity.service_id.clone(),
        "station".to_owned(),
        normalized_document,
        log_entries,
        Vec::new(),
        now,
    )
    .map_err(|error| {
        let detail = error.to_string();
        if detail.contains("exceeds 1 MiB") {
            crate::app_error!(LimitExceeded, detail)
        } else {
            crate::app_error!(ServiceIdentityProviderUnavailable, detail)
        }
    })
}
