//! Receiver-derived creation material shared by private review and admission.
use arkret_models_integration::management_review::ManagementReviewTarget;
use arkret_models_integration::{
    AppletManagedActorCommittedRequest, AppletManagedActorProvisionPayload,
};
use arkret_wire::ActorId;
use coland_http::error::AppError;
use coland_storage::{AppletAdmissionRequest, AppletAuthoringCandidate};

use crate::state::AppState;

pub(crate) async fn prepare_management_candidate(
    state: &AppState,
    target: &ManagementReviewTarget,
) -> Result<Option<Box<AppletAuthoringCandidate>>, AppError> {
    let (applet, authoring, request, provision, existing) = match target {
        ManagementReviewTarget::BotCreation {
            applet_id,
            request_body,
        } => (
            applet_id,
            &request_body.authoring_request,
            AppletManagedActorCommittedRequest::Bot(request_body.clone()),
            Some(
                &request_body
                    .managed_actor_bundle
                    .managed_actor_provision_event,
            ),
            None,
        ),
        ManagementReviewTarget::GhostCreation {
            applet_id,
            request_body,
        } => (
            applet_id,
            &request_body.authoring_request,
            AppletManagedActorCommittedRequest::Ghost(request_body.clone()),
            request_body
                .managed_actor_bundle
                .as_ref()
                .map(|bundle| &bundle.managed_actor_provision_event),
            request_body.existing_managed_actor.as_ref(),
        ),
        ManagementReviewTarget::Event { .. } => return Ok(None),
    };
    authoring
        .validate_bindings()
        .map_err(|e| AppError::schema_violation(e.to_string()))?;
    let scope = authoring
        .basis
        .bot()
        .map(|b| &b.effective_scope)
        .or_else(|| authoring.basis.ghost().map(|b| &b.effective_scope))
        .ok_or_else(|| AppError::schema_violation("creation basis absent"))?;
    let record = super::record::applet_record(state, applet.as_str(), scope)
        .await?
        .ok_or_else(|| AppError::not_found("Applet installation absent"))?;
    let mut prior = Vec::new();
    if let Some(event) = provision {
        let provision: AppletManagedActorProvisionPayload =
            serde_json::from_value(serde_json::json!(&event.payload))
                .map_err(|e| AppError::schema_violation(e.to_string()))?;
        super::install::validate_managed_actor_current_method_evidence(state, &provision).await?;
    } else {
        let basis = authoring
            .basis
            .ghost()
            .ok_or_else(|| AppError::schema_violation("Ghost reuse basis absent"))?;
        let ghost = super::ghost_reuse::find_existing(state, &record, &basis.external_ref)
            .await?
            .ok_or_else(|| AppError::not_found("Ghost provenance absent"))?;
        if existing != Some(&super::ghost_reuse::anchors(&ghost)) {
            return Err(AppError::capability_denied("Ghost reuse anchors differ"));
        }
        for event in [
            &ghost.managed_actor_provision_event,
            &ghost.pcr_genesis_event,
            &ghost.accountability_grant_event,
            &ghost.profile_event,
        ] {
            prior.push(super::endpoints::durable_ghost_event_ref(state, event).await?);
        }
    }
    let epoch = super::install::registration_epoch_evidence_from_event(&record.registration_event)?;
    let request = AppletAdmissionRequest::Managed(request);
    Ok(Some(Box::new(AppletAuthoringCandidate {
        canonical_request_hash: arkret_wire::Hash::new(
            arkret_canonical::canonical_sha256(&request)
                .map_err(|e| AppError::schema_violation(e.to_string()))?,
        )
        .map_err(|e| AppError::schema_violation(e.to_string()))?,
        request,
        package: record.package.clone(),
        recomputed_install_plan: None,
        service_did_document: crate::jws_verify::resolve_did_document(state, &epoch.did)
            .map_err(AppError::param_invalid)?,
        controller_did_document: super::install::package_controller_document(
            state,
            &record.package,
        )?,
        station_verification_method: state
            .service_verification_method("notary-key")
            .map_err(AppError::internal)?,
        station_public_key: *state.notary_verifying_key().as_bytes(),
        admin_actor_id: ActorId::service(record.package.service_id),
        admin_producer_guards: Vec::new(),
        request_digest: authoring
            .canonical_digest()
            .map_err(|e| AppError::schema_violation(e.to_string()))?,
        prior_managed_refs: prior,
        prior_service_signer_evidence: None,
        accepted_at: arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
    })))
}

pub(super) async fn prepare_creation_approvals(
    state: &AppState,
    input: &AppletAuthoringCandidate,
) -> Result<Option<coland_storage::OperationApprovalCommit>, AppError> {
    let (target, signatures, operation) = match &input.request {
        AppletAdmissionRequest::Managed(AppletManagedActorCommittedRequest::Bot(body)) => (
            ManagementReviewTarget::BotCreation {
                applet_id: input.package.applet_id.clone(),
                request_body: body.clone(),
            },
            &body.approval_signatures,
            arkret_wire::ServiceOperationId::SelfAppletBotCommandProvisionV1,
        ),
        AppletAdmissionRequest::Managed(AppletManagedActorCommittedRequest::Ghost(body)) => (
            ManagementReviewTarget::GhostCreation {
                applet_id: input.package.applet_id.clone(),
                request_body: body.clone(),
            },
            &body.approval_signatures,
            arkret_wire::ServiceOperationId::SelfAppletGhostCommandProvisionV1,
        ),
        _ => return Ok(None),
    };
    if signatures.is_empty() {
        return Ok(None);
    }
    let result: coland_services::ServiceResult<_> = async {
        let methods = crate::approval_admission::prepare_approval_methods(
            state,
            signatures,
            chrono::Utc::now(),
        )
        .await?;
        let mut accounts = std::collections::BTreeSet::new();
        let mut ids = std::collections::BTreeSet::new();
        let mut management_votes = Vec::new();
        let mut has_action_votes = false;
        for signature in signatures {
            match &signature.input.approval_context {
                arkret_wire::ApprovalContext::Management { request_id, .. } => {
                    ids.insert(request_id.clone());
                    management_votes.push(signature.clone());
                }
                arkret_wire::ApprovalContext::Grant { .. }
                | arkret_wire::ApprovalContext::RealmGovernance { .. } => has_action_votes = true,
                _ => {
                    return Err(coland_services::ServiceError::protocol(
                        arkret_wire::ErrorCode::SignatureInvalid,
                        "creation contains an unrelated approval context",
                    ));
                }
            }
        }
        if ids.len() > 1 {
            return Err(coland_services::ServiceError::protocol(
                arkret_wire::ErrorCode::SignatureInvalid,
                "creation combines different management requests",
            ));
        }
        for id in ids {
            accounts.extend(
                state
                    .persistence()
                    .management_review_material(&input.admin_actor_id, &id, &management_votes)
                    .await
                    .map_err(coland_services::ServiceError::from)?
                    .accounts,
            );
        }
        if has_action_votes {
            accounts.extend(
                state
                    .persistence()
                    .applet_creation_approval_accounts(input)
                    .await
                    .map_err(coland_services::ServiceError::from)?,
            );
        }
        let mut current =
            crate::approval_admission::observe_management_accounts(state, accounts).await?;
        current.applet_candidate = Some(Box::new(input.clone()));
        Ok((current, methods))
    }
    .await;
    let (current, methods) = result.map_err(|error| {
        let code = error
            .conflict_code()
            .and_then(|code| arkret_wire::ErrorCode::from_wire(code.as_str()))
            .unwrap_or(match error.kind() {
                coland_services::ServiceErrorKind::NotFound => arkret_wire::ErrorCode::NotFound,
                coland_services::ServiceErrorKind::SchemaViolation => {
                    arkret_wire::ErrorCode::SchemaViolation
                }
                coland_services::ServiceErrorKind::Database
                | coland_services::ServiceErrorKind::Internal => {
                    arkret_wire::ErrorCode::TemporarilyUnavailable
                }
                _ => arkret_wire::ErrorCode::FailedPrecondition,
            });
        AppError::from_rejection(code, error.to_string())
    })?;
    Ok(Some(coland_storage::OperationApprovalCommit {
        target_digest: target
            .canonical_target_digest()
            .map_err(|e| AppError::schema_violation(e.to_string()))?,
        operation,
        methods,
        current,
    }))
}

/// Resolver material for a real Device Event; no acceptance or current allow.
pub(crate) async fn prepare_event_current(
    state: &AppState,
    target: &ManagementReviewTarget,
) -> coland_services::ServiceResult<Option<Box<coland_storage::AppletEventReviewCurrent>>> {
    let ManagementReviewTarget::Event { event } = target else {
        return Ok(None);
    };
    let Some(applet) = &event.applet_id else {
        return Ok(None);
    };
    let account = event.actor_id.as_account_id().ok_or_else(|| {
        coland_services::ServiceError::Conflict(
            "capability_denied: native management target is not an Account".into(),
        )
    })?;
    let record = super::record::applet_record(state, applet.as_str(), &event.scope_ref)
        .await
        .map_err(|e| {
            coland_services::ServiceError::Conflict(format!("temporarily_unavailable: {e}"))
        })?
        .ok_or_else(|| {
            coland_services::ServiceError::NotFound("Applet installation not found".into())
        })?;
    let resolution = state
        .persistence()
        .principal_resolution_by_account_id(account)
        .await?
        .ok_or_else(|| {
            coland_services::ServiceError::NotFound("native PCR resolution not found".into())
        })?;
    let epoch = super::types::registration_epoch_evidence_from_event(&record.registration_event)
        .map_err(|e| coland_services::ServiceError::SchemaViolation(e.to_string()))?;
    let service_did_document =
        crate::jws_verify::resolve_did_document(state, &epoch.did).map_err(|_| {
            coland_services::ServiceError::Conflict(
                "temporarily_unavailable: Service DID current is unavailable".into(),
            )
        })?;
    Ok(Some(Box::new(coland_storage::AppletEventReviewCurrent {
        pcr_realm_id: resolution.pcr_realm_id,
        service_did_document,
    })))
}
