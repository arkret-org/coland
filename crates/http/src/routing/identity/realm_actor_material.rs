//! Exact private Realm actor material; callers cannot select another identity.
use arkret_models_integration::RealmActorMaterialRequest;
use coland_http::error::AppError;
use salvo::prelude::*;

use crate::state::AppState;

pub(crate) fn router() -> Router {
    Router::with_path("realm-actors/material").post(read)
}

#[handler]
async fn read(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    if !req.headers().contains_key("source-service-id")
        && depot
            .get_typed::<super::realm_actor_control::VerifiedRealmActorControl>()
            .is_err()
        && depot
            .get_typed::<super::applet_managed_device::VerifiedAppletManagedDevice>()
            .is_err()
    {
        return Box::pin(super::realm_actor_account_material::read_account(
            req, depot, res,
        ))
        .await;
    }
    let state = depot.get_typed::<AppState>().expect("state injected");
    let result = read_material(state, req, depot).await;
    match result {
        Ok(outcome) => {
            res.headers_mut().insert(
                salvo::http::header::CACHE_CONTROL,
                salvo::http::HeaderValue::from_static("no-store"),
            );
            res.render(Json(outcome));
        }
        Err(error) => error.write(req, depot, res).await,
    }
}

async fn read_material(
    state: &AppState,
    req: &mut Request,
    depot: &Depot,
) -> Result<arkret_models_integration::RealmActorMaterialOutcome, AppError> {
    let operation = arkret_wire::ServiceOperationId::SelfRealmActorReadMaterialV1;
    if req.headers().get_all("arkret-operation").iter().count() != 1
        || req
            .headers()
            .get("arkret-operation")
            .and_then(|value| value.to_str().ok())
            != Some(operation.as_str())
    {
        return Err(AppError::not_found("Realm actor material not found"));
    }
    let caller = if let Ok(control) =
        depot.get_typed::<super::realm_actor_control::VerifiedRealmActorControl>()
    {
        if control.operation != operation {
            return Err(AppError::not_found("Realm actor material not found"));
        }
        coland_storage::RealmActorMaterialCaller::Control {
            authority: control.carrier.clone(),
            expires_at: control.expires_at,
        }
    } else if let Ok(device) =
        depot.get_typed::<super::applet_managed_device::VerifiedAppletManagedDevice>()
    {
        if device.operation != operation {
            return Err(AppError::not_found("Realm actor material not found"));
        }
        coland_storage::RealmActorMaterialCaller::Device {
            guard: Box::new(super::applet_managed_device::scope_guard(state, device).await?),
            expires_at: device.transport_expires_at,
        }
    } else if req.headers().contains_key("source-service-id") {
        let service =
            crate::routing::extensions::applet_bridge::verify_self_control_service(state, req)
                .await?;
        coland_storage::RealmActorMaterialCaller::Service {
            service_id: service.service_id,
            verification_method: service.verification_method,
            public_key: service.public_key,
            authenticated_document: service.authenticated_document,
            expires_at: service.expires_at,
        }
    } else {
        return Err(AppError::not_found("Realm actor material not found"));
    };
    let bytes = req
        .payload()
        .await
        .map_err(|_| AppError::json_invalid("invalid Realm material body"))?;
    if bytes.len() > 4_194_304 {
        return Err(AppError::schema_violation(
            "Realm material body exceeds 4 MiB",
        ));
    }
    arkret_canonical::canonical::validate_canonical_bytes(bytes)
        .map_err(|_| AppError::json_invalid("Realm material body is not canonical"))?;
    let request: RealmActorMaterialRequest = serde_json::from_slice(bytes)
        .map_err(|_| AppError::schema_violation("invalid Realm material selector"))?;
    request
        .validate()
        .map_err(|_| AppError::schema_violation("invalid Realm material selector"))?;
    supply(state, &request, &caller).await
}

pub(super) async fn supply(
    state: &AppState,
    request: &RealmActorMaterialRequest,
    caller: &coland_storage::RealmActorMaterialCaller,
) -> Result<arkret_models_integration::RealmActorMaterialOutcome, AppError> {
    let method = arkret_wire::DidUrl::new(
        crate::routing::federation::federation_service_signature_key_id(
            state.service_did().as_str(),
        ),
    )
    .map_err(|_| AppError::internal("invalid material signing method"))?;
    state
        .authority_commits()
        .read_realm_actor_material(
            request,
            caller,
            &state.service_core_id(),
            &method,
            state.notary_signing_key().as_ref(),
        )
        .await
        .map_err(|error| match error {
            coland_services::ServiceError::NotFound(_) => {
                AppError::not_found("Realm actor material not found")
            }
            _ => {
                tracing::warn!(error = ?error, "private Realm material supply failed");
                crate::app_error!(
                    TemporarilyUnavailable,
                    "Realm actor material is unavailable"
                )
            }
        })
}
