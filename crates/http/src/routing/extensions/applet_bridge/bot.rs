//! Independent, Service-authenticated Bot authoring and four-Event admission.
use arkret_models_collaboration::events_payloads::CapabilityGrantPayload;
use arkret_models_integration::{
    AppletBotAuthoringRequestBasis, AppletBotPreviewOutcome, AppletBotPreviewRequestBody,
    AppletBotProvisionOutcome, AppletBotProvisionRequestBody, AppletManagedActorAuthoringRequest,
    AppletManagedActorCommittedRequest, AppletManagedActorProvisionPayload,
    AppletManagedActorPurpose, AppletManagedActorRole,
};
use arkret_wire::{ActorId, CapabilityActionId, Hash, RealmId};
use coland_http::error::AppError;
use coland_http::result::{JsonResult, json_ok};
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;

use super::endpoints::{applet_authoring_preview_subject_key, issue_applet_authoring_preview};
use super::install::{
    package_controller_document, registration_epoch_evidence_from_event,
    validate_managed_actor_current_method_evidence,
};
use super::record::{
    applet_id_param, applet_record, encode_applet_identity, encode_applet_record,
    ensure_not_revoked, idempotency_key,
};
use super::signature::VerifiedAppletServiceSignature;
use super::types::BotActorRecord;
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

#[salvo::oapi::endpoint(
    operation_id = "ak.self.applet.bot.command.provision",
    tags("extensions")
)]
pub(super) async fn provision(
    body: JsonBody<AppletBotProvisionRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> JsonResult<AppletBotProvisionOutcome> {
    let verified = depot
        .remove_typed::<VerifiedAppletServiceSignature>()
        .map_err(|_| AppError::unauthenticated("Applet Service signature missing"))?;
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = body.into_inner();
    let basis = body
        .authoring_request
        .basis
        .bot()
        .ok_or_else(|| AppError::param_invalid("Bot authoring purpose required"))?;
    let path = applet_id_param(req)?;
    if basis.applet_id.as_str() != path
        || basis.target_station_id != state.service_core_id()
        || basis.service_id != verified.install.package.service_id
        || basis.effective_scope != verified.install.effective_scope
    {
        return Err(AppError::capability_denied("Bot authoring binding differs"));
    }

    body.authoring_request
        .validate_bindings()
        .map_err(|e| AppError::param_invalid(e.to_string()))?;
    body.managed_actor_bundle
        .validate_bindings(&body.authoring_request)
        .map_err(|e| AppError::param_invalid(e.to_string()))?;
    let hash = Hash::new(
        arkret_canonical::canonical_sha256(&body)
            .map_err(|e| AppError::param_invalid(e.to_string()))?,
    )
    .map_err(|e| AppError::param_invalid(e.to_string()))?;
    let mut record = applet_record(state, &path, &basis.effective_scope)
        .await?
        .ok_or_else(|| AppError::not_found("Applet installation absent"))?;
    let key =
        idempotency_key(req).ok_or_else(|| AppError::param_missing("Idempotency-Key required"))?;
    if let Some(existing) = record
        .bots
        .iter()
        .find(|bot| bot.request_id == basis.request_id)
    {
        if existing.request_digest != hash {
            return Err(
                AppError::conflict("Bot request_id already binds another candidate")
                    .with_wire_code("duplicate_conflict"),
            );
        }
        let p: AppletManagedActorProvisionPayload = serde_json::from_value(
            serde_json::to_value(&existing.managed_actor_provision_event.payload)
                .map_err(|e| AppError::internal(e.to_string()))?,
        )
        .map_err(|e| AppError::internal(e.to_string()))?;
        return json_ok(AppletBotProvisionOutcome {
            bot_actor_id: existing.bot_actor_id.clone(),
            managed_actor_provision_ref: existing.managed_actor_provision_event.event_id.clone(),
            principal_control_realm_id: RealmId::from_event_id(
                &existing.pcr_genesis_event.event_id,
            ),
            profile_event_ref: existing.profile_event.event_id.clone(),
            accountability_grant_ref: existing.accountability_grant_event.event_id.clone(),
            authorization_ref: p.applet_authority_ref,
            display_name: basis.display_name.clone(),
        });
    }
    ensure_not_revoked(&record)?;
    if basis.registration_event_ref != record.registration_event.event_id
        || basis.authorization_ref != authorization(&record)?
    {
        return Err(AppError::capability_denied(
            "Bot creation authority changed",
        ));
    }
    let p: AppletManagedActorProvisionPayload = serde_json::from_value(
        serde_json::to_value(
            &body
                .managed_actor_bundle
                .managed_actor_provision_event
                .payload,
        )
        .map_err(|e| AppError::param_invalid(e.to_string()))?,
    )
    .map_err(|e| AppError::param_invalid(e.to_string()))?;
    if p.actor_role != AppletManagedActorRole::Bot || p.external_ref.is_some() {
        return Err(AppError::param_invalid(
            "native Bot cannot carry Ghost identity",
        ));
    }
    validate_managed_actor_current_method_evidence(state, &p).await?;
    let now = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let expected = encode_applet_record(&record)?;
    let identity = encode_applet_identity(&record.identity)?;
    let bundle = &body.managed_actor_bundle;
    record.bots.push(BotActorRecord {
        bot_actor_id: p.actor_id.clone(),
        request_id: basis.request_id.clone(),
        request_digest: hash.clone(),
        managed_actor_provision_event: bundle.managed_actor_provision_event.clone(),
        pcr_genesis_event: bundle.pcr_genesis_event.clone(),
        accountability_grant_event: bundle.accountability_grant_event.clone(),
        profile_event: bundle.profile_event.clone(),
        created_at: now,
    });
    let replacement = encode_applet_record(&record)?;
    let epoch = registration_epoch_evidence_from_event(&record.registration_event)?;
    let mut input = coland_storage::AppletAuthoringUnitWrite {
        candidate: coland_storage::AppletAuthoringCandidate {
            request: coland_storage::AppletAdmissionRequest::Managed(
                AppletManagedActorCommittedRequest::Bot(Box::new(body.clone())),
            ),
            package: record.package.clone(),
            recomputed_install_plan: None,
            service_did_document: crate::jws_verify::resolve_did_document(state, &epoch.did)
                .map_err(AppError::param_invalid)?,
            controller_did_document: package_controller_document(state, &record.package)?,
            station_verification_method: state
                .service_verification_method("notary-key")
                .map_err(AppError::internal)?,
            station_public_key: *state.notary_verifying_key().as_bytes(),
            admin_actor_id: ActorId::service(basis.service_id.clone()),
            admin_producer_guards: vec![],
            request_digest: body
                .authoring_request
                .canonical_digest()
                .map_err(|e| AppError::param_invalid(e.to_string()))?,
            canonical_request_hash: hash.clone(),
            prior_managed_refs: vec![],
            prior_service_signer_evidence: None,
            accepted_at: now,
        },
        creation_service_resolution: Some(
            super::install::managed_creation_service_resolution(state, &epoch).await?,
        ),
        expected_identity: Some(identity.clone()),
        expected_installation: Some(expected.clone()),
        preview_subject_key: applet_authoring_preview_subject_key(&body.authoring_request)?,
        operation_id: "ak.self.applet.bot.command.provision".to_owned(),
        idempotency_key: key.clone(),
        operation_approvals: None,
    };
    input.operation_approvals =
        super::management_review::prepare_creation_approvals(state, &input.candidate).await?;
    let station = state.service_core_id();
    let service = ActorId::service(basis.service_id.clone());
    let display = basis.display_name.clone();
    let actor = p.actor_id;
    let auth = p.applet_authority_ref;
    let finalizer: coland_storage::AppletUnitFinalizer = std::sync::Arc::new(move |refs| {
        let bundle = &body.managed_actor_bundle;
        let outcome = AppletBotProvisionOutcome {
            bot_actor_id: actor.clone(),
            managed_actor_provision_ref: crate::routing::events::event_log::applet_committed_ref(
                refs,
                &bundle.managed_actor_provision_event,
            )?
            .event_id,
            principal_control_realm_id: RealmId::from_event_id(&bundle.pcr_genesis_event.event_id),
            profile_event_ref: crate::routing::events::event_log::applet_committed_ref(
                refs,
                &bundle.profile_event,
            )?
            .event_id,
            accountability_grant_ref: crate::routing::events::event_log::applet_committed_ref(
                refs,
                &bundle.accountability_grant_event,
            )?
            .event_id,
            authorization_ref: auth.clone(),
            display_name: display.clone(),
        };
        let response_body =
            serde_json::to_value(&outcome).map_err(coland_storage::PersistenceError::database)?;
        Ok(coland_storage::AppletUnitFinalization {
            applet_record: coland_storage::AppletRecordCommit {
                applet_id: record.applet_id.clone(),
                identity: coland_storage::AppletIdentityCommit {
                    target_station_id: station.clone(),
                    expected_record: Some(identity.clone()),
                    record: identity.clone(),
                },
                expected_record: Some(expected.clone()),
                record: replacement.clone(),
            },
            idempotency_record: coland_storage::IdempotencyRecord {
                authenticated_actor: service.clone(),
                operation_id: "ak.self.applet.bot.command.provision".to_owned(),
                idempotency_key: key.clone(),
                request_hash: hash.to_string(),
                response_status: 201,
                response_body: response_body.clone(),
                created_at: now,
                expires_at: now + chrono::Duration::days(1),
            },
            response_body,
        })
    });
    let outcome =
        crate::routing::events::event_log::submit_applet_authoring_unit(state, input, finalizer)
            .await
            .map_err(|e| {
                crate::routing::events::event_log::submit_one_error_to_app_error(
                    "Bot admission",
                    e.status(),
                    e.code(),
                    &e.message(),
                )
            })?;
    res.status_code(if outcome.replayed {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    });
    json_ok(
        serde_json::from_value(outcome.response_body)
            .map_err(|e| AppError::internal(e.to_string()))?,
    )
}
