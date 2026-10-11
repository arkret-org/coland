//! Service-owned dependency material; this read grants no business authority.
use arkret_models_collaboration::applet_installation_authority::{
    AppletAuthorityMaterialOutcome, AppletAuthorityMaterialRequestBody,
};
use coland_http::error::AppError;
use coland_http::result::{JsonResult, json_ok};
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;

use crate::state::AppState;

#[salvo::oapi::endpoint(
    operation_id = "ak.self.applet.authority.read.material",
    tags("extensions")
)]
pub(super) async fn read(
    body: JsonBody<AppletAuthorityMaterialRequestBody>,
    depot: &mut Depot,
) -> JsonResult<AppletAuthorityMaterialOutcome> {
    let verified = depot
        .remove_typed::<super::signature::VerifiedAppletAuthorityService>()
        .map_err(|_| AppError::unauthenticated("Applet Service signature missing"))?;
    let state = depot.get_typed::<AppState>().expect("state injected");
    let request = body.into_inner();
    request
        .validate()
        .map_err(|e| AppError::param_invalid(e.to_string()))?;
    if request.effective_scope != verified.effective_scope {
        return Err(AppError::capability_denied(
            "authenticated Applet scope differs",
        ));
    }
    let outcome = state
        .persistence()
        .applet_authority_material(
            &verified.applet_id,
            &verified.service_id,
            &state.service_core_id(),
            &request,
        )
        .await
        .map_err(|error| match error {
            coland_storage::PersistenceError::Conflict(_) => {
                AppError::not_found("requested authority material unavailable")
            }
            _ => {
                tracing::error!(%error,"Applet authority material read failed");
                AppError::internal("unable to read Applet authority material")
            }
        })?;
    json_ok(outcome)
}
