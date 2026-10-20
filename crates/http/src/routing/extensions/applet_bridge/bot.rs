//! Service-authenticated preview for independent Realm Bot creation.
use arkret_models_collaboration::events_payloads::CapabilityGrantPayload;
use arkret_models_integration::{
    AppletBotAuthoringRequestBasis, AppletBotPreviewOutcome, AppletBotPreviewRequestBody,
    AppletManagedActorAuthoringRequest, AppletManagedActorPurpose,
};
use arkret_wire::CapabilityActionId;
use coland_http::error::AppError;
use coland_http::result::{JsonResult, json_ok};
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;

use super::endpoints::issue_applet_authoring_preview;
use super::install::registration_epoch_evidence_from_event;
use super::record::{applet_id_param, applet_record, ensure_not_revoked};
use super::signature::VerifiedAppletServiceSignature;
use crate::state::AppState;

fn authorization(record: &super::types::AppletRecord) -> Result<arkret_wire::GrantId, AppError> {
    for event in &record.capability_grant_events {
        let payload: CapabilityGrantPayload = serde_json::from_value(
            serde_json::to_value(&event.payload).map_err(|e| AppError::internal(e.to_string()))?,
        )
        .map_err(|e| AppError::internal(e.to_string()))?;
        if payload
            .grant
            .actions
            .iter()
            .any(|a| a == CapabilityActionId::APPLET_BOT_PROVISION)
        {
            return Ok(arkret_wire::GrantId::from_event_id(&event.event_id));
        }
    }
    Err(AppError::capability_denied(
        "installation does not grant Bot creation",
    ))
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.applet.bot.command.preview",
    tags("extensions")
)]
pub(super) async fn preview(
    body: JsonBody<AppletBotPreviewRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AppletBotPreviewOutcome> {
    let verified = depot
        .remove_typed::<VerifiedAppletServiceSignature>()
        .map_err(|_| AppError::unauthenticated("Applet Service signature missing"))?;
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = body.into_inner();
    if body.request_id.is_empty() || body.request_id.len() > 128 {
        return Err(AppError::param_invalid(
            "Bot request_id must contain 1..128 bytes",
        ));
    }
    let path = applet_id_param(req)?;
    let record = applet_record(state, &path, &body.effective_scope)
        .await?
        .ok_or_else(|| AppError::not_found("Applet installation absent"))?;
    ensure_not_revoked(&record)?;
    if verified.install.effective_scope != record.effective_scope
        || verified.install.package.service_id != record.package.service_id
    {
        return Err(AppError::capability_denied(
            "Service installation binding differs",
        ));
    }
    let basis = AppletBotAuthoringRequestBasis {
        schema: AppletBotAuthoringRequestBasis::SCHEMA.to_owned(),
        purpose: AppletManagedActorPurpose::ProvisionBot,
        target_station_id: state.service_core_id(),
        applet_id: record.applet_id.clone(),
        service_id: record.package.service_id.clone(),
        display_name: body.display_name,
        registration_event_ref: record.registration_event.event_id.clone(),
        authorization_ref: authorization(&record)?,
        registration_epoch_evidence: registration_epoch_evidence_from_event(
            &record.registration_event,
        )?,
        package_digest: record
            .package
            .package_digest
            .clone()
            .ok_or_else(|| AppError::internal("package digest absent"))?,
        effective_scope: body.effective_scope,
        request_id: body.request_id,
    };
    let issued_at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let signer = arkret_signatures::Ed25519PayloadSigner::new(
        state.notary_signing_key().as_ref().clone(),
        state.service_did(),
        state
            .service_verification_method("notary-key")
            .map_err(AppError::internal)?,
    );
    let authoring_request = AppletManagedActorAuthoringRequest::sign_bot(
        basis,
        state.service_core_id(),
        issued_at,
        issued_at + chrono::Duration::minutes(5),
        &signer,
    )
    .map_err(|e| AppError::internal(e.to_string()))?;
    let authoring_request = issue_applet_authoring_preview(state, authoring_request).await?;
    json_ok(AppletBotPreviewOutcome { authoring_request })
}
