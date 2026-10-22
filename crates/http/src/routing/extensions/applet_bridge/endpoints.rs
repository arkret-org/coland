//! HTTP endpoint handlers and router assembly for the applet bridge.

use arkret_models_collaboration::governance::grant_constraint::{
    CapabilityGrantStatus, CapabilitySubject,
};
use arkret_models_discovery::ServiceDescribe;
use arkret_models_integration::{
    AppletActorView, AppletCapabilityRevokeIntent, AppletGhostAuthoringRequestBasis,
    AppletInstallOutcome, AppletInstallPreviewOutcome, AppletInstallPreviewRequestBody,
    AppletInstallRequestBody, AppletManagedActorAuthoringRequest, AppletManagedActorPurpose,
    AppletManagedMembershipRemoval, AppletMembershipRemoveIntent, AppletNamespaceDomain,
    AppletPingOutcome, AppletProtocolMetadata, AppletRealmView, AppletRevokeCommittedEventStatus,
    AppletRevokeCommittedEventStep, AppletRevokeEffectRef, AppletRevokeEventEffectKind,
    AppletRevokeLocalEffectKind, AppletRevokeLocalEffectRef, AppletRevokeLocalEffectStatus,
    AppletRevokeLocalEffectStep, AppletRevokeOutcome, AppletRevokePlan, AppletRevokePreviewOutcome,
    AppletRevokePreviewRequestBody, AppletRevokeRequestBody, AppletRevokeSagaStatus,
    AppletRevokeStep, AppletRevokeSubmittedEventStatus, AppletRevokeSubmittedEventStep,
    AppletTransactionOutcome, AppletTransactionRequestBody, ExternalRef, FieldDefinition,
    GhostPreviewOutcome, GhostPreviewRequestBody, ProtocolInstance, namespace_pattern_matches,
};
use arkret_wire::{
    AppletRevokeMode, CommittedEventRef, CurrentRevision, EventId, EventKind, ProtocolOperationId,
};
use coland_http::error::AppError;
use coland_http::result::{JsonResult, json_ok};
use salvo::http::StatusCode;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::{Value, json};

use super::ghost::{ghost_provision_authorization_ref, revoke_applet_record_after_admin_gate};
use super::install::{
    approved_scope_grants, approved_scopes_from_formal_install_events, build_install_plan,
    effective_scope_realm_id, register_package_install, registration_epoch_evidence_from_event,
    require_realm_admin, validate_admin_install_events, validate_applet_package,
};
use super::record::{
    applet_id_param, applet_record, applet_records, ensure_not_revoked, idempotency_key,
    persist_applet_record, query_value,
};
use super::signature::{
    VerifiedAppletProvisionService, VerifiedAppletServiceSignature,
    require_inbound_transaction_signature, require_provision_preview_signature,
};
use super::transaction::process_verified_transaction;
use super::types::{AppletRecord, COLAND_EDGE_APPLET_ID};
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;

pub(in crate::routing::extensions) fn protocol_router() -> Router {
    Router::new()
        .push(
            Router::with_path("peer/applets/{applet_id}/configuration")
                .post(super::configuration::peer_submit),
        )
        .push(
            Router::with_path("edge").push(
                Router::with_path("applet")
                    .push(Router::with_path("ping").get(protocol_ping_endpoint))
                    .push(Router::with_path("describe").get(protocol_describe_endpoint))
                    .push(
                        Router::with_path("transactions")
                            .hoop(require_inbound_transaction_signature)
                            .post(transaction_endpoint),
                    )
                    .push(
                        Router::with_path("realms/{realm_id_or_alias}").get(resolve_realm_endpoint),
                    )
                    .push(Router::with_path("protocols/{protocol}").get(protocol_metadata_endpoint))
                    .push(
                        Router::with_path("third_party")
                            .push(Router::with_path("users").get(third_party_users_endpoint))
                            .push(
                                Router::with_path("locations").get(third_party_locations_endpoint),
                            ),
                    ),
            ),
        )
        .push(
            Router::with_path("self").push(
                Router::with_path("applets")
                    .push(
                        Router::with_path("install")
                            .push(Router::with_path("preview").post(install_preview_endpoint))
                            .post(install_endpoint),
                    )
                    .push(
                        Router::with_path("{applet_id}")
                            .push(
                                Router::with_path("configuration")
                                    .post(super::configuration::self_submit),
                            )
                            .push(
                                Router::with_path("authority/material")
                                    .hoop(super::signature::require_authority_material_signature)
                                    .post(super::authority_material::read),
                            )
                            .push(
                                Router::with_path("bots/provision")
                                    .hoop(require_provision_preview_signature)
                                    .push(Router::with_path("preview").post(super::bot::preview)),
                            )
                            .push(
                                Router::with_path("ghosts/provision")
                                    .hoop(require_provision_preview_signature)
                                    .push(
                                        Router::with_path("preview")
                                            .post(preview_ghost_actor_endpoint),
                                    ),
                            )
                            .push(
                                Router::with_path("revoke")
                                    .push(
                                        Router::with_path("preview").post(revoke_preview_endpoint),
                                    )
                                    .post(revoke_install_endpoint),
                            ),
                    ),
            ),
        )
}

#[salvo::oapi::endpoint(operation_id = "ak.edge.applet.read.ping", tags("extensions"))]
#[tracing::instrument(skip_all, fields(op = "ak.edge.applet.read.ping.v1"))]
async fn protocol_ping_endpoint(depot: &mut Depot) -> JsonResult<AppletPingOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let service_id =
        arkret_identifiers::DidCoreId::new(state.service_id().clone()).map_err(|error| {
            AppError::internal(format!("configured service_id is invalid: {error}"))
        })?;
    json_ok(AppletPingOutcome {
        applet_id: arkret_identifiers::AppletId::new(COLAND_EDGE_APPLET_ID.to_owned()).map_err(
            |error| AppError::internal(format!("configured applet_id is invalid: {error}")),
        )?,
        service_id,
        protocol_version: "1.0".to_owned(),
    })
}

#[salvo::oapi::endpoint(operation_id = "ak.edge.applet.read.describe", tags("extensions"))]
#[tracing::instrument(skip_all, fields(op = "ak.edge.applet.read.describe.v1"))]
async fn protocol_describe_endpoint(depot: &mut Depot) -> JsonResult<ServiceDescribe> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    json_ok(crate::routing::system::describe::build_server_description(
        state,
    ))
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.applet.install.command.preview",
    tags("extensions")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.applet.install.command.preview.v1"))]
async fn install_preview_endpoint(
    aa: AuthArgs,
    body: JsonBody<AppletInstallPreviewRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AppletInstallPreviewOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let preview = body.into_inner();
    let session_actor =
        crate::routing::identity::session_actor::validated_session_actor(state, &session).await?;
    let basis = &preview.authoring_request_basis;
    if basis.target_station_id.as_str() != state.service_id()
        || basis.install_actor_id != session_actor
        || basis.applet_id != preview.applet_package.applet_id
        || basis.service_id != preview.applet_package.service_id
        || preview.applet_package.package_digest.as_ref() != Some(&basis.package_digest)
    {
        return Err(AppError::conflict("install authoring request basis does not match the authenticated actor, target Station, or Applet package")
            .with_wire_code("applet_install_plan_mismatch"));
    }
    for event in
        std::iter::once(&basis.registration_event).chain(basis.capability_grant_events.iter())
    {
        crate::state::verify_self_event_producer(state, &session, event)
            .await
            .map_err(|error| {
                crate::app_error!(
                    SignatureInvalid,
                    "install admin Event producer is invalid: {error}"
                )
            })?;
    }
    let validated_admin =
        validate_admin_install_events(&preview.applet_package, basis, &session_actor)?;
    let registration_epoch_evidence =
        registration_epoch_evidence_from_event(&basis.registration_event)?;
    validate_applet_package(state, &preview.applet_package, &registration_epoch_evidence)?;
    let approved_scopes =
        approved_scope_grants(&basis.effective_scope, validated_admin.approved_actions)?;
    let plan = build_install_plan(
        state,
        &preview.applet_package,
        &registration_epoch_evidence,
        &basis.effective_scope,
        approved_scopes,
        super::install::registration_revision_from_event(&basis.registration_event)?,
    )
    .await?;
    require_realm_admin(state, &session, &basis.effective_scope).await?;
    json_ok(AppletInstallPreviewOutcome { plan })
}

#[salvo::oapi::endpoint(operation_id = "ak.self.applet.command.install", tags("extensions"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.applet.command.install.v1"))]
async fn install_endpoint(
    aa: AuthArgs,
    body: JsonBody<AppletInstallRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> JsonResult<AppletInstallOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let idempotency_key = idempotency_key(req)
        .ok_or_else(|| AppError::param_missing("Idempotency-Key header is required"))?;
    if idempotency_key.len() > 128 {
        return Err(AppError::param_invalid(
            "Idempotency-Key length exceeds 128 bytes",
        ));
    }
    let commit = body.into_inner();
    let body = serde_json::to_value(&commit)
        .map_err(|error| AppError::internal(format!("install commit serialize: {error}")))?;
    let body_digest = crate::util::canonical_digest(&body)?;
    let basis = &commit.authoring_request_basis;
    if let Some(existing) = applet_record(
        state,
        commit.applet_package.applet_id.as_str(),
        commit.applet_package.service_id.as_str(),
        &basis.effective_scope,
    )
    .await?
    {
        if existing.idempotency_key == idempotency_key {
            require_exact_successful_install_replay(
                &existing.idempotency_key,
                existing.install_body_digest.as_str(),
                &idempotency_key,
                &body_digest,
            )?;
            res.status_code(StatusCode::OK);
            return json_ok(existing.install_response);
        }
    }
    let registration_epoch_evidence =
        registration_epoch_evidence_from_event(&basis.registration_event)?;
    validate_applet_package(state, &commit.applet_package, &registration_epoch_evidence)?;
    super::install::registration_epoch_producer_signing_key(
        state,
        &commit.applet_package,
        &registration_epoch_evidence,
    )?;
    let session_actor =
        crate::routing::identity::session_actor::session_actor_from_credential(state, &session)?;
    let approved_scopes = approved_scopes_from_formal_install_events(
        state,
        &commit,
        &session_actor,
        state.service_id(),
    )?;
    let recomputed_plan = build_install_plan(
        state,
        &commit.applet_package,
        &registration_epoch_evidence,
        &basis.effective_scope,
        approved_scopes,
        super::install::registration_revision_from_event(&basis.registration_event)?,
    )
    .await?;
    if commit.plan_digest != recomputed_plan.plan_digest {
        return Err(
            AppError::conflict("install plan digest does not match recomputed plan")
                .with_wire_code("applet_install_plan_mismatch"),
        );
    }

    // Governance gate: the canonical install write projects a
    // `ak.realm.admin`-scoped registration onto the effective_scope realm.
    // Authentication alone is insufficient: the actor MUST hold realm admin
    // over that realm in the durable authorization cut. fail-closed.
    require_realm_admin(state, &session, &basis.effective_scope).await?;

    let response = register_package_install(
        state,
        &session,
        commit,
        recomputed_plan,
        idempotency_key,
        body_digest,
        res,
    )
    .await?;
    json_ok(response)
}

fn require_exact_successful_install_replay(
    stored_key: &str,
    stored_digest: &str,
    requested_key: &str,
    requested_digest: &str,
) -> Result<(), AppError> {
    if stored_key != requested_key {
        return Err(
            AppError::conflict("applet package is already installed in this scope")
                .with_wire_code("duplicate_conflict"),
        );
    }
    if stored_digest == requested_digest {
        return Ok(());
    }
    Err(
        AppError::conflict("Idempotency-Key was already used with a different applet install body")
            .with_wire_code("duplicate_conflict"),
    )
}

pub(super) fn applet_authoring_preview_subject_key(
    request: &AppletManagedActorAuthoringRequest,
) -> Result<String, AppError> {
    let subject = if let Some(basis) = request.basis.bot() {
        json!({
            "purpose": "provision_bot",
            "request_id": basis.request_id,
            "effective_scope": basis.effective_scope,
            "applet_id": basis.applet_id,
            "target_station_id": basis.target_station_id,
        })
    } else if let Some(basis) = request.basis.ghost() {
        json!({
            "purpose": "provision_ghost",
            "applet_id": basis.applet_id,
            "target_station_id": basis.target_station_id,
            "external_ref": basis.external_ref,
            "effective_scope": basis.effective_scope,
        })
    } else {
        return Err(AppError::internal(
            "managed actor authoring request has no closed branch subject",
        ));
    };
    crate::util::canonical_digest(&subject)
}

fn applet_authoring_preview_basis_digest(
    request: &AppletManagedActorAuthoringRequest,
) -> Result<String, AppError> {
    crate::util::canonical_digest(&json!({
        "schema": request.schema,
        "purpose": request.purpose,
        "basis": request.basis,
        "governance_station_id": request.governance_station_id,
    }))
}

pub(super) async fn issue_applet_authoring_preview(
    state: &AppState,
    request: AppletManagedActorAuthoringRequest,
) -> Result<AppletManagedActorAuthoringRequest, AppError> {
    let subject_key = applet_authoring_preview_subject_key(&request)?;
    let basis_digest = applet_authoring_preview_basis_digest(&request)?;
    let request_digest = request
        .canonical_digest()
        .map_err(|error| AppError::internal(format!("authoring request digest failed: {error}")))?
        .to_string();
    let signed_request = serde_json::to_value(&request).map_err(|error| {
        AppError::internal(format!("authoring request serialize failed: {error}"))
    })?;
    let stored = state
        .event_queries()
        .issue_applet_authoring_preview(coland_services::events::AppletAuthoringPreviewState {
            subject_key,
            basis_digest,
            request_digest,
            signed_request,
            issued_at: request.issued_at,
            expires_at: request.expires_at,
        })
        .await
        .map_err(|error| {
            tracing::error!(%error, "failed to persist Applet authoring preview winner");
            AppError::internal("failed to persist Applet authoring preview winner")
        })?;
    let stored_request: AppletManagedActorAuthoringRequest =
        serde_json::from_value(stored.signed_request.clone()).map_err(|error| {
            AppError::internal(format!(
                "stored Applet authoring preview winner is invalid: {error}"
            ))
        })?;
    stored_request.validate_bindings().map_err(|error| {
        AppError::internal(format!(
            "stored Applet authoring preview winner bindings are invalid: {error}"
        ))
    })?;
    let stored_request_digest = stored_request
        .canonical_digest()
        .map_err(|error| AppError::internal(format!("stored request digest failed: {error}")))?
        .to_string();
    if applet_authoring_preview_subject_key(&stored_request)? != stored.subject_key
        || applet_authoring_preview_basis_digest(&stored_request)? != stored.basis_digest
        || stored_request_digest != stored.request_digest
    {
        return Err(AppError::internal(
            "stored Applet authoring preview winner metadata does not match its exact request",
        ));
    }
    Ok(stored_request)
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.applet.revoke.command.preview",
    tags("extensions")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.applet.revoke.command.preview.v1"))]
async fn revoke_preview_endpoint(
    aa: AuthArgs,
    body: JsonBody<AppletRevokePreviewRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AppletRevokePreviewOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let applet_id = applet_id_param(req)?;
    let preview = body.into_inner();
    let record = applet_record(
        state,
        &applet_id,
        preview.service_id.as_str(),
        &preview.effective_scope,
    )
    .await?
    .ok_or_else(|| AppError::not_found("applet is not registered"))?;
    validate_revoke_scope(&record, &preview.effective_scope)?;
    require_realm_admin(state, &session, &preview.effective_scope).await?;
    json_ok(build_revoke_plan(state, &record, &preview).await?)
}

#[salvo::oapi::endpoint(operation_id = "ak.self.applet.command.revoke", tags("extensions"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.applet.command.revoke.v1"))]
async fn revoke_install_endpoint(
    aa: AuthArgs,
    body: JsonBody<AppletRevokeRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AppletRevokeOutcome> {
    revoke_install_future(aa, body, depot, req).await
}

fn revoke_install_future<'a>(
    aa: AuthArgs,
    body: JsonBody<AppletRevokeRequestBody>,
    depot: &'a mut Depot,
    req: &'a mut Request,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = JsonResult<AppletRevokeOutcome>> + Send + 'a>>
{
    Box::pin(revoke_install_inner(aa, body, depot, req))
}

async fn revoke_install_inner(
    aa: AuthArgs,
    body: JsonBody<AppletRevokeRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AppletRevokeOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = crate::boxed_future(|| aa.authenticated_session(state, req)).await?;
    let applet_id = applet_id_param(req)?;
    let idempotency_key = idempotency_key(req)
        .ok_or_else(|| AppError::param_missing("Idempotency-Key header is required"))?;
    if idempotency_key.len() > 128 {
        return Err(AppError::param_invalid(
            "Idempotency-Key length exceeds 128 bytes",
        ));
    }
    let revoke = body.into_inner();
    let request_value = serde_json::to_value(&revoke)
        .map_err(|error| AppError::param_invalid(format!("revoke request invalid: {error}")))?;
    let request_digest = arkret_canonical::canonical_sha256(&request_value)
        .map_err(|error| AppError::param_invalid(format!("revoke request invalid: {error}")))?;
    let mut record = crate::boxed_future(|| {
        applet_record(
            state,
            &applet_id,
            revoke.service_id.as_str(),
            &revoke.effective_scope,
        )
    })
    .await?
    .ok_or_else(|| AppError::not_found("applet is not registered"))?;
    validate_revoke_scope(&record, &revoke.effective_scope)?;
    crate::boxed_future(|| require_realm_admin(state, &session, &revoke.effective_scope)).await?;
    let admin_actor =
        crate::routing::identity::session_actor::session_actor_from_credential(state, &session)?;
    let admin_actor_key = admin_actor.to_string();

    // A durable execution owns the idempotency decision. Exact replay resumes
    // its persisted submissions even when the live projection has moved since
    // preview; conflicting bytes fail before any plan rebuild or side effect.
    let stored_outcome = load_stored_revoke_outcome(
        record.revoke_execution.as_ref(),
        state.service_id(),
        &admin_actor_key,
        &idempotency_key,
        &request_digest,
    )?;
    let mut revoke_plan = None;

    if stored_outcome.is_none() {
        let preview = AppletRevokePreviewRequestBody {
            service_id: revoke.service_id.clone(),
            effective_scope: revoke.effective_scope.clone(),
            reason_code: revoke.reason_code.clone(),
            revoke_mode: revoke.revoke_mode,
        };
        let recomputed =
            crate::boxed_future(|| build_revoke_plan(state, &record, &preview)).await?;
        let recomputed_digest = arkret_canonical::canonical_sha256(&recomputed.revoke_plan)
            .map_err(|error| AppError::internal(format!("revoke plan digest failed: {error}")))?;
        if recomputed_digest != revoke.revoke_plan_digest.as_str() {
            return Err(AppError::conflict("revoke plan changed; preview again")
                .with_wire_code("failed_precondition"));
        }
        validate_revoke_submissions(&admin_actor, &recomputed.revoke_plan, &revoke)?;
        revoke_plan = Some(recomputed.revoke_plan);
    } else if let Some(execution) = record.revoke_execution.as_ref() {
        revoke_plan = execution
            .get("revoke_plan")
            .filter(|value| !value.is_null())
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| {
                AppError::internal(format!("stored revoke plan is invalid: {error}"))
            })?;
        if let Some(plan) = revoke_plan.as_ref() {
            let digest = arkret_canonical::canonical_sha256(plan).map_err(|error| {
                AppError::internal(format!("stored revoke plan digest failed: {error}"))
            })?;
            if digest != revoke.revoke_plan_digest.as_str() {
                return Err(AppError::internal(
                    "stored revoke plan disagrees with the exact request digest",
                ));
            }
        }
    }

    let mut outcome = if let Some(stored_outcome) = stored_outcome {
        stored_outcome
    } else {
        let operation_id =
            ProtocolOperationId::new(format!("ak:operation:{}", uuid::Uuid::now_v7()))
                .map_err(AppError::internal)?;
        let mut steps = revoke
            .capability_revoke_events
            .iter()
            .map(|submission| {
                pending_revoke_event_step(
                    AppletRevokeEventEffectKind::CapabilityRevokeEvent,
                    submission.event.event_id.clone(),
                )
            })
            .chain(revoke.membership_state_events.iter().map(|submission| {
                pending_revoke_event_step(
                    AppletRevokeEventEffectKind::MembershipStateEvent,
                    submission.event.event_id.clone(),
                )
            }))
            .collect::<Vec<_>>();
        if let Some(plan) = revoke_plan.as_ref() {
            for token_ref in &plan.widget_token_refs {
                steps.push(AppletRevokeStep::LocalEffect(AppletRevokeLocalEffectStep {
                    effect_kind: AppletRevokeLocalEffectKind::WidgetTokenInvalidation,
                    effect_ref: arkret_models_integration::AppletRevokeLocalEffectRef::new(
                        token_ref.clone(),
                    )
                    .map_err(|error| AppError::internal(error.to_string()))?,
                    status: AppletRevokeLocalEffectStatus::Pending,
                    reason_code: None,
                }));
            }
        }
        if revoke_mode_fences_runtime(revoke.revoke_mode) {
            steps.push(AppletRevokeStep::LocalEffect(AppletRevokeLocalEffectStep {
                effect_kind: AppletRevokeLocalEffectKind::LocalAppletFence,
                effect_ref: applet_revoke_local_ref(applet_id.clone())?,
                status: AppletRevokeLocalEffectStatus::Pending,
                reason_code: None,
            }));
        }
        let mut outcome = AppletRevokeOutcome {
            operation_id,
            revoke_plan_digest: revoke.revoke_plan_digest.clone(),
            status: AppletRevokeSagaStatus::InProgress,
            steps,
            revoked_refs: Vec::new(),
            rejections: Vec::new(),
        };
        crate::boxed_future(|| {
            persist_revoke_execution(
                state,
                &mut record,
                &admin_actor_key,
                &idempotency_key,
                &request_digest,
                &request_value,
                revoke_plan.as_ref(),
                &mut outcome,
            )
        })
        .await?;
        outcome
    };

    if outcome.status == AppletRevokeSagaStatus::Complete {
        return json_ok(outcome);
    }

    let submissions = revoke
        .capability_revoke_events
        .iter()
        .cloned()
        .chain(revoke.membership_state_events.iter().cloned())
        .collect::<Vec<_>>();
    for (index, submission) in submissions.into_iter().enumerate() {
        if matches!(outcome.steps[index], AppletRevokeStep::CommittedEvent(_)) {
            continue;
        }
        let submitted_event_id = submission.event.event_id.clone();
        let effect_kind = revoke_event_effect_kind(&submission.event.kind)?;
        outcome
            .rejections
            .retain(|item| item.requested_scope.as_deref() != Some(submitted_event_id.as_str()));
        outcome.steps[index] = pending_revoke_event_step(effect_kind, submitted_event_id.clone());
        // A retry of a rejected step is made durable as pending before the
        // exact signed bytes are submitted again. The first attempt already
        // persisted the same pending identity with the initial ledger.
        crate::boxed_future(|| {
            persist_revoke_execution(
                state,
                &mut record,
                &admin_actor_key,
                &idempotency_key,
                &request_digest,
                &request_value,
                revoke_plan.as_ref(),
                &mut outcome,
            )
        })
        .await?;
        if outcome.status == AppletRevokeSagaStatus::Complete {
            return json_ok(outcome);
        }
        if matches!(outcome.steps[index], AppletRevokeStep::CommittedEvent(_)) {
            continue;
        }
        if let Some(committed_event_ref) =
            crate::boxed_future(|| durable_revoke_event_ref(state, &submitted_event_id)).await?
        {
            outcome.steps[index] =
                AppletRevokeStep::CommittedEvent(AppletRevokeCommittedEventStep {
                    effect_kind,
                    committed_event_ref: committed_event_ref.clone(),
                    status: AppletRevokeCommittedEventStatus::Duplicate,
                    reason_code: None,
                });
            outcome
                .revoked_refs
                .push(AppletRevokeEffectRef::CommittedEvent(committed_event_ref));
            crate::boxed_future(|| {
                persist_revoke_execution(
                    state,
                    &mut record,
                    &admin_actor_key,
                    &idempotency_key,
                    &request_digest,
                    &request_value,
                    revoke_plan.as_ref(),
                    &mut outcome,
                )
            })
            .await?;
            continue;
        }
        match crate::boxed_future(|| {
            crate::routing::events::event_log::submit_applet_revoke_event_submission(
                state, &session, submission,
            )
        })
        .await
        {
            Ok(accepted) => {
                let committed_event_ref = crate::boxed_future(|| {
                    committed_revoke_event_ref(
                        state,
                        &submitted_event_id,
                        accepted.event_id.as_str(),
                    )
                })
                .await?;
                let status = if accepted.duplicate {
                    AppletRevokeCommittedEventStatus::Duplicate
                } else {
                    AppletRevokeCommittedEventStatus::Accepted
                };
                outcome.steps[index] =
                    AppletRevokeStep::CommittedEvent(AppletRevokeCommittedEventStep {
                        effect_kind,
                        committed_event_ref: committed_event_ref.clone(),
                        status,
                        reason_code: None,
                    });
                outcome
                    .revoked_refs
                    .push(AppletRevokeEffectRef::CommittedEvent(committed_event_ref));
            }
            Err(error) => {
                let reason_code = arkret_wire::ReasonCode::from_wire(&error.code());
                outcome.steps[index] =
                    AppletRevokeStep::SubmittedEvent(AppletRevokeSubmittedEventStep {
                        effect_kind,
                        submitted_event_id: submitted_event_id.clone(),
                        status: AppletRevokeSubmittedEventStatus::Rejected,
                        reason_code: Some(reason_code.clone()),
                    });
                outcome
                    .rejections
                    .push(arkret_models_integration::AppletScopeRejection {
                        requested_scope: Some(submitted_event_id.to_string()),
                        reason_code,
                    });
                outcome.status = AppletRevokeSagaStatus::PartiallyCompleted;
                crate::boxed_future(|| {
                    persist_revoke_execution(
                        state,
                        &mut record,
                        &admin_actor_key,
                        &idempotency_key,
                        &request_digest,
                        &request_value,
                        revoke_plan.as_ref(),
                        &mut outcome,
                    )
                })
                .await?;
                return json_ok(outcome);
            }
        }
        crate::boxed_future(|| {
            persist_revoke_execution(
                state,
                &mut record,
                &admin_actor_key,
                &idempotency_key,
                &request_digest,
                &request_value,
                revoke_plan.as_ref(),
                &mut outcome,
            )
        })
        .await?;
        if outcome.status == AppletRevokeSagaStatus::Complete {
            return json_ok(outcome);
        }
    }

    for index in 0..outcome.steps.len() {
        let AppletRevokeStep::LocalEffect(local) = &outcome.steps[index] else {
            continue;
        };
        if local.effect_kind != AppletRevokeLocalEffectKind::WidgetTokenInvalidation
            || local.status == AppletRevokeLocalEffectStatus::Accepted
        {
            continue;
        }
        if outcome
            .steps
            .iter()
            .any(|step| matches!(step, AppletRevokeStep::SubmittedEvent(_)))
        {
            return Err(AppError::internal(
                "widget invalidation requires every Event effect committed",
            ));
        }
        let token_ref = local.effect_ref.clone();
        state
            .event_queries()
            .invalidate_widget_token(
                &widget_install_selector(&record),
                token_ref.as_str(),
                chrono::Utc::now(),
            )
            .await
            .map_err(|error| {
                AppError::internal(format!("cannot invalidate widget token: {error}"))
            })?;
        let AppletRevokeStep::LocalEffect(local) = &mut outcome.steps[index] else {
            unreachable!()
        };
        local.status = AppletRevokeLocalEffectStatus::Accepted;
        outcome
            .revoked_refs
            .push(AppletRevokeEffectRef::TypedResource(token_ref));
        crate::boxed_future(|| {
            persist_revoke_execution(
                state,
                &mut record,
                &admin_actor_key,
                &idempotency_key,
                &request_digest,
                &request_value,
                revoke_plan.as_ref(),
                &mut outcome,
            )
        })
        .await?;
    }

    if revoke_mode_fences_runtime(revoke.revoke_mode) {
        if !revoke_outcome_ready_for_local_effect(&outcome) {
            return Err(AppError::internal(
                "Applet revoke cannot apply its local fence before every Event step is committed",
            ));
        }
        let local_outcome = crate::boxed_future(|| {
            revoke_applet_record_after_admin_gate(
                state,
                &session.actor,
                &applet_id,
                revoke.service_id.as_str(),
                &revoke.effective_scope,
            )
        })
        .await?;
        for bot_actor_id in local_outcome.bot_actor_ids {
            outcome
                .revoked_refs
                .push(AppletRevokeEffectRef::TypedResource(
                    applet_revoke_local_ref(bot_actor_id)?,
                ));
        }
        for ghost_actor_id in local_outcome.ghost_actor_ids {
            outcome
                .revoked_refs
                .push(AppletRevokeEffectRef::TypedResource(
                    applet_revoke_local_ref(ghost_actor_id)?,
                ));
        }
        let step = outcome
            .steps
            .iter_mut()
            .find(|step| {
                matches!(
                    step,
                    AppletRevokeStep::LocalEffect(local)
                        if local.effect_kind == AppletRevokeLocalEffectKind::LocalAppletFence
                )
            })
            .ok_or_else(|| AppError::internal("Applet revoke local fence step disappeared"))?;
        let AppletRevokeStep::LocalEffect(step) = step else {
            unreachable!("matched local Applet fence")
        };
        step.status = AppletRevokeLocalEffectStatus::Accepted;
        outcome
            .revoked_refs
            .push(AppletRevokeEffectRef::TypedResource(
                step.effect_ref.clone(),
            ));
    }
    deduplicate_revoke_effect_refs(&mut outcome.revoked_refs)?;
    outcome.status = AppletRevokeSagaStatus::Complete;
    record = crate::boxed_future(|| {
        applet_record(
            state,
            &applet_id,
            revoke.service_id.as_str(),
            &revoke.effective_scope,
        )
    })
    .await?
    .ok_or_else(|| AppError::not_found("applet disappeared during revoke"))?;
    crate::boxed_future(|| {
        persist_revoke_execution(
            state,
            &mut record,
            &admin_actor_key,
            &idempotency_key,
            &request_digest,
            &request_value,
            revoke_plan.as_ref(),
            &mut outcome,
        )
    })
    .await?;
    crate::boxed_future(|| {
        crate::routing::append_audit_log(
            state,
            Some(&session.actor),
            "applet.revoke",
            json!({
                "applet_id": applet_id,
                "operation_id": outcome.operation_id,
                "revoke_plan_digest": outcome.revoke_plan_digest,
                "status": outcome.status,
                "revoked_refs": outcome.revoked_refs,
            }),
            "accepted",
        )
    })
    .await;
    json_ok(outcome)
}

fn validate_revoke_scope(
    record: &AppletRecord,
    effective_scope: &arkret_wire::ScopeRef,
) -> Result<(), AppError> {
    let scope_realm = effective_scope_realm_id(effective_scope);
    if record.portal_realm_id.as_str() != scope_realm || &record.effective_scope != effective_scope
    {
        return Err(
            AppError::conflict("effective_scope does not match active applet install")
                .with_internal_reason("applet_effective_scope_mismatch"),
        );
    }
    Ok(())
}

fn load_stored_revoke_outcome(
    execution: Option<&Value>,
    principal_id: &str,
    admin_actor_id: &str,
    idempotency_key: &str,
    request_digest: &str,
) -> Result<Option<AppletRevokeOutcome>, AppError> {
    let Some(execution) = execution else {
        return Ok(None);
    };
    let binding_matches = execution.get("principal_id").and_then(Value::as_str)
        == Some(principal_id)
        && execution.get("admin_actor_id").and_then(Value::as_str) == Some(admin_actor_id)
        && execution.get("idempotency_key").and_then(Value::as_str) == Some(idempotency_key)
        && execution.get("request_digest").and_then(Value::as_str) == Some(request_digest);
    if !binding_matches {
        return Err(AppError::conflict(
            "revoke idempotency key is already bound to a different service, actor, or canonical body",
        )
        .with_wire_code("duplicate_conflict"));
    }
    serde_json::from_value::<AppletRevokeOutcome>(
        execution.get("outcome").cloned().unwrap_or(Value::Null),
    )
    .map(Some)
    .map_err(|error| AppError::internal(format!("stored revoke saga is invalid: {error}")))
}

fn revoke_mode_fences_runtime(mode: AppletRevokeMode) -> bool {
    matches!(
        mode,
        AppletRevokeMode::RevokeAll | AppletRevokeMode::RevokeRuntimeOnly
    )
}

fn pending_revoke_event_step(
    effect_kind: AppletRevokeEventEffectKind,
    submitted_event_id: EventId,
) -> AppletRevokeStep {
    AppletRevokeStep::SubmittedEvent(AppletRevokeSubmittedEventStep {
        effect_kind,
        submitted_event_id,
        status: AppletRevokeSubmittedEventStatus::Pending,
        reason_code: None,
    })
}

fn revoke_event_effect_kind(kind: &EventKind) -> Result<AppletRevokeEventEffectKind, AppError> {
    match kind {
        EventKind::CapabilityRevoke => Ok(AppletRevokeEventEffectKind::CapabilityRevokeEvent),
        EventKind::MemberState => Ok(AppletRevokeEventEffectKind::MembershipStateEvent),
        _ => Err(AppError::internal(
            "stored Applet revoke submission has an unsupported Event kind",
        )),
    }
}

fn applet_revoke_local_ref(
    value: impl Into<String>,
) -> Result<AppletRevokeLocalEffectRef, AppError> {
    AppletRevokeLocalEffectRef::new(value).map_err(|error| {
        AppError::internal(format!(
            "Applet revoke local effect identity is invalid: {error}"
        ))
    })
}

async fn committed_revoke_event_ref(
    state: &AppState,
    submitted_event_id: &EventId,
    accepted_event_id: &str,
) -> Result<CommittedEventRef, AppError> {
    if accepted_event_id != submitted_event_id.as_str() {
        return Err(AppError::internal(
            "Event admission returned an identity different from the submitted Event",
        ));
    }
    durable_revoke_event_ref(state, submitted_event_id)
        .await?
        .ok_or_else(|| {
            AppError::internal(
                "Event admission succeeded without a durable governing-Station commit",
            )
        })
}

async fn durable_revoke_event_ref(
    state: &AppState,
    submitted_event_id: &EventId,
) -> Result<Option<CommittedEventRef>, AppError> {
    let Some(record) = state
        .persistence()
        .committed_event(submitted_event_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
    else {
        return Ok(None);
    };
    if record.event.event_id != *submitted_event_id {
        return Err(AppError::internal(
            "durable committed Event record disagrees with the submitted Event identity",
        ));
    }
    Ok(Some(CommittedEventRef {
        event_id: submitted_event_id.clone(),
        commit_id: record.commit.commit_id,
        stream_ref: record.commit.stream_ref,
        stream_position: record.commit.stream_position,
    }))
}

fn deduplicate_revoke_effect_refs(refs: &mut Vec<AppletRevokeEffectRef>) -> Result<(), AppError> {
    let mut keyed = refs
        .drain(..)
        .map(|effect_ref| {
            serde_json::to_string(&effect_ref)
                .map(|key| (key, effect_ref))
                .map_err(|error| {
                    AppError::internal(format!(
                        "Applet revoke effect ref serialization failed: {error}"
                    ))
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    keyed.dedup_by(|left, right| left.0 == right.0);
    refs.extend(keyed.into_iter().map(|(_, effect_ref)| effect_ref));
    Ok(())
}

fn widget_install_selector(record: &AppletRecord) -> coland_storage::AppletWidgetInstallSelector {
    coland_storage::AppletWidgetInstallSelector {
        applet_id: record.applet_id.clone(),
        effective_scope: record.effective_scope.clone(),
        registration_event_ref: record.install_response.registration_event_ref.clone(),
        registration_epoch: record.package.registration_epoch.clone(),
    }
}

async fn build_revoke_plan(
    state: &AppState,
    record: &AppletRecord,
    preview: &AppletRevokePreviewRequestBody,
) -> Result<AppletRevokePreviewOutcome, AppError> {
    ensure_not_revoked(record)?;
    let response = &record.install_response;
    let widget_token_refs = if matches!(
        preview.revoke_mode,
        AppletRevokeMode::RevokeAll | AppletRevokeMode::RevokeWidgetOnly
    ) {
        state
            .event_queries()
            .widget_tokens(&widget_install_selector(record), chrono::Utc::now())
            .await
            .map_err(|error| {
                AppError::internal(format!("cannot read widget token inventory: {error}"))
            })?
            .into_iter()
            .map(|token| token.token_ref)
            .collect()
    } else {
        Vec::new()
    };
    let package = &record.package;
    let mut capability_revocations = Vec::new();
    let mut membership_removals = Vec::new();
    if revoke_mode_fences_runtime(preview.revoke_mode) {
        let scope_realm_id = arkret_wire::RealmId::new(effective_scope_realm_id(
            &preview.effective_scope,
        ))
        .map_err(|error| AppError::internal(format!("effective Realm id is invalid: {error}")))?;
        let grant_snapshot = state
            .persistence()
            .capability_grant_current_results(&scope_realm_id)
            .await
            .map_err(|error| {
                AppError::internal(format!(
                    "cannot read governing-Station Capability Grant current snapshot: {error}"
                ))
            })?;
        let active_grant_revisions = active_applet_grant_revisions(
            grant_snapshot,
            &scope_realm_id,
            &package.service_id,
            &record.target_station_id,
            &response.capability_grant_refs,
        )?;
        for grant_id in &response.capability_grant_refs {
            if let Some(expected_revision) = active_grant_revisions.get(grant_id) {
                capability_revocations.push(AppletCapabilityRevokeIntent {
                    event_kind: EventKind::CapabilityRevoke.as_str().to_owned(),
                    grant_id: grant_id.clone(),
                    expected_revision: expected_revision.clone(),
                    registration_epoch: package.registration_epoch.clone(),
                    reason_code: preview.reason_code.clone(),
                });
            }
        }
        membership_removals =
            exact_managed_membership_removals(state, record, &preview.reason_code).await?;
    }
    capability_revocations
        .sort_by(|left, right| left.grant_id.as_str().cmp(right.grant_id.as_str()));
    membership_removals.sort_by(|left, right| left.member_id.cmp(&right.member_id));
    let plan = AppletRevokePlan {
        applet_id: record.applet_id.clone(),
        service_id: record.package.service_id.clone(),
        effective_scope: preview.effective_scope.clone(),
        registration_epoch: package.registration_epoch.clone(),
        reason_code: preview.reason_code.clone(),
        revoke_mode: preview.revoke_mode,
        capability_revocations,
        membership_removals,
        widget_token_refs,
    };
    Ok(AppletRevokePreviewOutcome { revoke_plan: plan })
}

fn active_applet_grant_revisions(
    snapshot: Vec<coland_storage::CapabilityGrantCurrentResultRecord>,
    realm_id: &arkret_wire::RealmId,
    applet_service_id: &arkret_wire::DidCoreId,
    target_station_id: &arkret_wire::DidCoreId,
    installed_grant_refs: &[arkret_wire::GrantId],
) -> Result<std::collections::BTreeMap<arkret_wire::GrantId, CurrentRevision>, AppError> {
    let installed = installed_grant_refs
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let expected_subject = arkret_wire::ActorId::service(applet_service_id.clone());
    let _ = target_station_id;
    let mut active = std::collections::BTreeMap::new();
    for row in snapshot {
        if !installed.contains(&row.grant_id)
            || row.status != coland_storage::CapabilityGrantCurrentStatus::Active
        {
            continue;
        }
        let grant = row.value;
        let subject_matches = matches!(
            &grant.subject,
            CapabilitySubject::Actor(subject) if subject == &expected_subject
        );
        if grant.id != row.grant_id
            || grant.realm_id.as_ref() != Some(realm_id)
            || grant.status != CapabilityGrantStatus::Active
            || !subject_matches
        {
            return Err(AppError::internal(
                "active Applet Capability Grant current row disagrees with its canonical value",
            ));
        }
        if active.insert(row.grant_id, row.revision).is_some() {
            return Err(AppError::internal(
                "governing-Station Capability Grant snapshot contains a duplicate Grant id",
            ));
        }
    }
    Ok(active)
}

fn incomplete_managed_membership_projection(detail: impl std::fmt::Display) -> AppError {
    AppError::conflict(format!(
        "Applet managed membership projection is incomplete: {detail}"
    ))
    .with_internal_reason("applet_install_projection_incomplete")
}

async fn exact_managed_membership_removals(
    state: &AppState,
    record: &AppletRecord,
    reason_code: &arkret_wire::ReasonCode,
) -> Result<Vec<AppletMembershipRemoveIntent>, AppError> {
    let realm_id = record.effective_scope.realm_id().as_str().to_owned();
    let managed_actor_ids = std::collections::BTreeSet::from_iter(
        record
            .bots
            .iter()
            .map(|bot| bot.bot_actor_id.clone())
            .chain(
                record
                    .ghosts
                    .iter()
                    .map(|ghost| ghost.ghost_actor_id.clone()),
            ),
    );
    let current_members = {
        let projection = state.projections().snapshot();
        projection
            .members_of_realm(&realm_id)
            .into_iter()
            .filter(|membership| {
                serde_json::from_str::<arkret_wire::ActorId>(&membership.member)
                    .is_ok_and(|member| managed_actor_ids.contains(&member))
            })
            .map(|membership| {
                (
                    membership.member.clone(),
                    membership.membership_event_ref.clone(),
                )
            })
            .collect::<Vec<_>>()
    };
    let mut removals = Vec::new();
    for (projected_member, membership_event_ref) in current_members {
        let membership_event_ref = membership_event_ref.ok_or_else(|| {
            incomplete_managed_membership_projection(format!(
                "current joined member {projected_member} has no winning Event ref"
            ))
        })?;
        let accepted = state
            .event_queries()
            .accepted_event(&membership_event_ref)
            .await
            .map_err(|error| {
                incomplete_managed_membership_projection(format!(
                    "cannot load winning membership Event {membership_event_ref}: {error}"
                ))
            })?
            .ok_or_else(|| {
                incomplete_managed_membership_projection(format!(
                    "winning membership Event {membership_event_ref} is not durably accepted"
                ))
            })?;
        if accepted.event_id != membership_event_ref {
            return Err(incomplete_managed_membership_projection(format!(
                "accepted membership lookup returned {} for winning Event {membership_event_ref}",
                accepted.event_id
            )));
        }
        let event =
            serde_json::from_value::<arkret_wire::Event>(accepted.envelope).map_err(|error| {
                incomplete_managed_membership_projection(format!(
                    "winning membership Event {membership_event_ref} is invalid: {error}"
                ))
            })?;
        if let Some(intent) = classify_current_managed_membership(
            record.applet_id.as_str(),
            &record.effective_scope,
            &managed_actor_ids,
            &projected_member,
            &membership_event_ref,
            &event,
            reason_code,
        )? {
            removals.push(intent);
        }
    }
    removals.sort_by(|left, right| left.member_id.cmp(&right.member_id));
    Ok(removals)
}

#[allow(clippy::too_many_arguments)]
fn classify_current_managed_membership(
    applet_id: &str,
    effective_scope: &arkret_wire::ScopeRef,
    managed_actor_ids: &std::collections::BTreeSet<arkret_wire::ActorId>,
    projected_member: &str,
    membership_event_ref: &str,
    event: &arkret_wire::Event,
    reason_code: &arkret_wire::ReasonCode,
) -> Result<Option<AppletMembershipRemoveIntent>, AppError> {
    // common-fields.md section 4.5: `leave -> join` is either the member's own
    // `ak.member.state{join}` or the exact target's `ak.invite.accept`. An
    // accepted invite joins its own author, so the Event actor is the member.
    let (member_id, joins) = match event.kind {
        EventKind::MemberState => {
            let member_id = event
                .payload
                .get("member_id")
                .cloned()
                .and_then(|value| serde_json::from_value::<arkret_wire::ActorId>(value).ok())
                .ok_or_else(|| {
                    incomplete_managed_membership_projection(format!(
                        "winning membership Event {membership_event_ref} has no complete member_id"
                    ))
                })?;
            let joins = event.payload.get("membership").and_then(Value::as_str) == Some("join");
            (member_id, joins)
        }
        EventKind::InviteAccept => {
            let invitee_matches = match event.payload.get("invitee_account_id") {
                None => true,
                Some(value) => serde_json::from_value::<arkret_wire::AccountId>(value.clone())
                    .ok()
                    .is_some_and(|invitee| event.actor_id.as_account_id() == Some(&invitee)),
            };
            (event.actor_id.clone(), invitee_matches)
        }
        _ => {
            return Err(incomplete_managed_membership_projection(format!(
                "winning membership Event {membership_event_ref} is not a membership join"
            )));
        }
    };
    let current_generation_matches = event.event_id.as_str() == membership_event_ref
        && joins
        && event.realm_id == *effective_scope.realm_id()
        && member_id.to_string() == projected_member;
    if !current_generation_matches {
        return Err(incomplete_managed_membership_projection(format!(
            "current membership cell and winning Event {membership_event_ref} disagree"
        )));
    }

    let applet_matches =
        event.applet_id.as_ref().map(ToString::to_string).as_deref() == Some(applet_id);
    let scope_matches = event.scope_ref == *effective_scope;

    if !scope_matches {
        return Ok(None);
    }
    if !applet_matches {
        return Ok(None);
    }
    if !managed_actor_ids.contains(&member_id) {
        return Err(incomplete_managed_membership_projection(format!(
            "membership Event {membership_event_ref} targets an actor absent from the durable Bot/Ghost projection"
        )));
    }

    Ok(Some(AppletMembershipRemoveIntent {
        event_kind: EventKind::MemberState.as_str().to_owned(),
        member_id,
        membership: AppletManagedMembershipRemoval::Leave,
        reason_code: reason_code.clone(),
    }))
}

fn validate_revoke_submissions(
    admin_actor: &arkret_wire::ActorId,
    plan: &AppletRevokePlan,
    revoke: &AppletRevokeRequestBody,
) -> Result<(), AppError> {
    let expected_grants = plan
        .capability_revocations
        .iter()
        .map(|intent| (intent.grant_id.clone(), intent))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut submitted_grants = std::collections::BTreeSet::new();
    for submission in &revoke.capability_revoke_events {
        let event = &submission.event;
        if event.kind != EventKind::CapabilityRevoke
            || &event.actor_id != admin_actor
            || event.scope_ref != plan.effective_scope
        {
            return Err(AppError::param_invalid(
                "capability revoke Event kind, actor, or scope does not match the plan",
            ));
        }
        let payload = &event.payload;
        let grant_id = payload
            .get("grant_id")
            .cloned()
            .and_then(|value| serde_json::from_value::<arkret_wire::GrantId>(value).ok())
            .ok_or_else(|| AppError::param_invalid("capability revoke payload lacks grant_id"))?;
        let expected = expected_grants.get(&grant_id).ok_or_else(|| {
            AppError::conflict("capability revoke Event target is absent from the current plan")
                .with_wire_code("failed_precondition")
        })?;
        let submitted_revision = payload
            .get("expected_revision")
            .cloned()
            .and_then(|value| serde_json::from_value::<CurrentRevision>(value).ok())
            .ok_or_else(|| {
                AppError::param_invalid("capability revoke payload lacks expected_revision")
            })?;
        if submitted_revision != expected.expected_revision {
            return Err(AppError::conflict(
                "capability revoke expected_revision does not match the current plan",
            )
            .with_wire_code("failed_precondition"));
        }
        if payload.get("reason").and_then(Value::as_str) != Some(expected.reason_code.as_str()) {
            return Err(AppError::param_invalid(
                "capability revoke reason does not match the plan",
            ));
        }
        if !submitted_grants.insert(grant_id) {
            return Err(AppError::param_invalid(
                "duplicate capability revoke target",
            ));
        }
    }
    if submitted_grants != expected_grants.keys().cloned().collect() {
        return Err(AppError::conflict(
            "capability revoke Event set does not exactly match the current plan",
        )
        .with_wire_code("failed_precondition"));
    }

    let expected_members = plan
        .membership_removals
        .iter()
        .map(|intent| {
            (
                intent.member_id.clone(),
                match intent.membership {
                    AppletManagedMembershipRemoval::Leave => "leave",
                }
                .to_owned(),
            )
        })
        .collect::<std::collections::BTreeSet<_>>();
    let mut submitted_members = std::collections::BTreeSet::new();
    for submission in &revoke.membership_state_events {
        let event = &submission.event;
        if event.kind != EventKind::MemberState
            || &event.actor_id != admin_actor
            || event.scope_ref != plan.effective_scope
        {
            return Err(AppError::param_invalid(
                "membership Event kind, actor, or scope does not match the plan",
            ));
        }
        let payload = &event.payload;
        let member_id = payload
            .get("member_id")
            .cloned()
            .and_then(|value| serde_json::from_value::<arkret_wire::ActorId>(value).ok())
            .ok_or_else(|| {
                AppError::param_invalid("membership payload lacks a complete member_id Actor")
            })?;
        let membership = payload
            .get("membership")
            .and_then(Value::as_str)
            .ok_or_else(|| AppError::param_invalid("membership payload lacks membership"))?;
        if membership != "leave"
            || payload.get("reason").and_then(Value::as_str) != Some(plan.reason_code.as_str())
        {
            return Err(AppError::param_invalid(
                "membership transition or reason does not match the plan",
            ));
        }
        if !submitted_members.insert((member_id, membership.to_owned())) {
            return Err(AppError::param_invalid(
                "duplicate membership revoke target",
            ));
        }
    }
    if submitted_members != expected_members {
        return Err(AppError::conflict(
            "membership Event set does not exactly match the current plan",
        )
        .with_wire_code("failed_precondition"));
    }
    Ok(())
}

async fn persist_revoke_execution(
    state: &AppState,
    record: &mut AppletRecord,
    admin_actor_id: &str,
    idempotency_key: &str,
    request_digest: &str,
    request: &Value,
    revoke_plan: Option<&AppletRevokePlan>,
    outcome: &mut AppletRevokeOutcome,
) -> Result<(), AppError> {
    let execution = json!({
        "principal_id": state.service_id(),
        "admin_actor_id": admin_actor_id,
        "idempotency_key": idempotency_key,
        "request_digest": request_digest,
        "request": request,
        "revoke_plan": revoke_plan,
        "outcome": outcome,
    });
    for _ in 0..8 {
        let current = record.clone();
        let mut replacement = current.clone();
        replacement.revoke_execution = Some(execution.clone());
        if persist_applet_record(state, &current, &replacement).await? {
            *record = replacement;
            return Ok(());
        }
        let applet_id = record.applet_id.clone();
        let effective_scope = record.effective_scope.clone();
        *record = applet_record(
            state,
            applet_id.as_str(),
            current.package.service_id.as_str(),
            &effective_scope,
        )
        .await?
        .ok_or_else(|| AppError::not_found("applet disappeared during revoke"))?;
        if let Some(stored) = load_stored_revoke_outcome(
            record.revoke_execution.as_ref(),
            state.service_id(),
            admin_actor_id,
            idempotency_key,
            request_digest,
        )? && revoke_outcome_progress(&stored) >= revoke_outcome_progress(outcome)
        {
            // A concurrent request has already persisted the same or a later
            // prefix of this deterministic saga. Its record is the winner;
            // never overwrite it with this request's stale outcome.
            *outcome = stored;
            return Ok(());
        }
    }
    Err(
        AppError::conflict("Applet record changed repeatedly during revoke progress persistence")
            .with_wire_code("cas_conflict"),
    )
}

fn revoke_outcome_progress(outcome: &AppletRevokeOutcome) -> (bool, usize, usize, u8) {
    let completed_prefix = outcome
        .steps
        .iter()
        .take_while(|step| !revoke_step_is_pending(step))
        .count();
    let accepted = outcome
        .steps
        .iter()
        .filter(|step| revoke_step_is_successful(step))
        .count();
    let status_rank = match outcome.status {
        AppletRevokeSagaStatus::InProgress => 0,
        AppletRevokeSagaStatus::PartiallyCompleted => 1,
        AppletRevokeSagaStatus::Complete => 2,
    };
    (
        outcome.status == AppletRevokeSagaStatus::Complete,
        completed_prefix,
        accepted,
        status_rank,
    )
}

fn revoke_step_is_pending(step: &AppletRevokeStep) -> bool {
    matches!(
        step,
        AppletRevokeStep::SubmittedEvent(AppletRevokeSubmittedEventStep {
            status: AppletRevokeSubmittedEventStatus::Pending,
            ..
        }) | AppletRevokeStep::LocalEffect(AppletRevokeLocalEffectStep {
            status: AppletRevokeLocalEffectStatus::Pending,
            ..
        })
    )
}

fn revoke_step_is_successful(step: &AppletRevokeStep) -> bool {
    matches!(
        step,
        AppletRevokeStep::CommittedEvent(_)
            | AppletRevokeStep::LocalEffect(AppletRevokeLocalEffectStep {
                status: AppletRevokeLocalEffectStatus::Accepted
                    | AppletRevokeLocalEffectStatus::Duplicate,
                ..
            })
    )
}

fn revoke_outcome_ready_for_local_effect(outcome: &AppletRevokeOutcome) -> bool {
    let mut local_fence_pending = false;
    for step in &outcome.steps {
        match step {
            AppletRevokeStep::CommittedEvent(_) => {}
            AppletRevokeStep::SubmittedEvent(_) => return false,
            AppletRevokeStep::LocalEffect(local)
                if local.effect_kind == AppletRevokeLocalEffectKind::LocalAppletFence
                    && local.status == AppletRevokeLocalEffectStatus::Pending =>
            {
                if local_fence_pending {
                    return false;
                }
                local_fence_pending = true;
            }
            AppletRevokeStep::LocalEffect(local)
                if local.effect_kind == AppletRevokeLocalEffectKind::WidgetTokenInvalidation
                    && local.status == AppletRevokeLocalEffectStatus::Accepted => {}
            AppletRevokeStep::LocalEffect(_) => return false,
        }
    }
    local_fence_pending
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.applet.ghost.command.preview",
    tags("extensions")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.applet.ghost.command.preview.v1"))]
async fn preview_ghost_actor_endpoint(
    body: JsonBody<GhostPreviewRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<GhostPreviewOutcome> {
    let verified = depot
        .remove_typed::<VerifiedAppletProvisionService>()
        .map_err(|_| AppError::unauthenticated("Applet service signature verification missing"))?;
    let state = depot.get_typed::<AppState>().expect("state injected");
    let path_applet_id = applet_id_param(req)?;
    let preview = body.into_inner();
    let record = applet_record(
        state,
        &path_applet_id,
        verified.install.package.service_id.as_str(),
        &preview.effective_scope,
    )
    .await?
    .ok_or_else(|| AppError::not_found("applet is not installed"))?;
    ensure_not_revoked(&record)?;
    if verified.install.applet_id.as_str() != path_applet_id
        || verified.install.package.service_id != record.package.service_id
        || preview.effective_scope != record.effective_scope
    {
        return Err(AppError::capability_denied(
            "authenticated Applet service or realm does not match the installed Applet",
        )
        .with_wire_code("applet_registration_unauthorized"));
    }
    for (field, value) in [
        (
            "external_ref.protocol",
            preview.external_ref.protocol.as_str(),
        ),
        (
            "external_ref.instance_id",
            preview.external_ref.instance_id.as_str(),
        ),
        (
            "external_ref.external_id",
            preview.external_ref.external_id.as_str(),
        ),
    ] {
        if value.trim().is_empty() {
            return Err(AppError::param_missing(format!("{field} is required")));
        }
    }
    if preview
        .display_name
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return Err(AppError::param_invalid(
            "display_name must be omitted or non-empty",
        ));
    }
    let registration_epoch_evidence =
        registration_epoch_evidence_from_event(&record.registration_event)?;
    let package_digest = record.package.package_digest.clone().ok_or_else(|| {
        AppError::internal("installed Applet package has no canonical package_digest")
    })?;
    let authorization_ref = arkret_wire::GrantId::new(ghost_provision_authorization_ref(&record)?)
        .map_err(|error| {
            AppError::internal(format!("stored Ghost grant id is invalid: {error}"))
        })?;
    let existing_managed_actor =
        super::ghost_reuse::find_existing(state, &record, &preview.external_ref)
            .await?
            .map(|ghost| super::ghost_reuse::anchors(&ghost));
    let basis = AppletGhostAuthoringRequestBasis {
        schema: AppletGhostAuthoringRequestBasis::SCHEMA.to_owned(),
        purpose: AppletManagedActorPurpose::ProvisionGhost,
        target_station_id: arkret_wire::DidCoreId::new(state.service_id().clone()).map_err(
            |error| AppError::internal(format!("configured service_id is invalid: {error}")),
        )?,
        applet_id: record.applet_id.clone(),
        service_id: record.package.service_id,
        effective_scope: preview.effective_scope,
        external_ref: preview.external_ref,
        display_name: preview.display_name,
        registration_event_ref: record.registration_event.event_id,
        authorization_ref,
        registration_epoch_evidence,
        package_digest,
        existing_managed_actor: existing_managed_actor.clone(),
    };
    let issued_at = arkret_canonical::canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let signer = arkret_signatures::Ed25519PayloadSigner::new(
        state.notary_signing_key().as_ref().clone(),
        state.service_did(),
        state
            .service_verification_method("notary-key")
            .map_err(AppError::internal)?,
    );
    let authoring_request = AppletManagedActorAuthoringRequest::sign_ghost(
        basis,
        state.service_core_id(),
        issued_at,
        issued_at + chrono::Duration::minutes(5),
        &signer,
    )
    .map_err(|error| AppError::internal(format!("Ghost authoring request sign failed: {error}")))?;
    let authoring_request = issue_applet_authoring_preview(state, authoring_request).await?;
    json_ok(GhostPreviewOutcome {
        authoring_request,
        existing_managed_actor,
    })
}

#[salvo::oapi::endpoint(
    operation_id = "ak.edge.applet.command.transaction",
    tags("extensions")
)]
#[tracing::instrument(skip_all, fields(op = "ak.edge.applet.command.transaction.v1"))]
async fn transaction_endpoint(
    body: JsonBody<AppletTransactionRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AppletTransactionOutcome> {
    let state = depot
        .get_typed::<AppState>()
        .expect("state injected")
        .clone();
    let idempotency_key = idempotency_key(req)
        .ok_or_else(|| AppError::param_missing("Idempotency-Key header is required"))?;
    if idempotency_key.len() > 128 {
        return Err(AppError::param_invalid(
            "Idempotency-Key length exceeds 128 bytes",
        ));
    }
    let AppletTransactionRequestBody::Events(transaction) = body.into_inner() else {
        return Err(AppError::schema_violation(
            "managed Actor authoring completion is allowed only from Station to Applet",
        ));
    };
    if transaction.events.is_empty() {
        return Err(AppError::param_invalid(
            "events must contain at least one event",
        ));
    }
    // The route hoop verifies the per-delivery RFC 9421 source signature
    // against the raw canonical body before this typed extractor or any event
    // processing runs. A successful verification is consumed exactly once.
    let verified = depot
        .remove_typed::<VerifiedAppletServiceSignature>()
        .map_err(|_| AppError::internal("verified applet transaction signature is unavailable"))?;
    let outcome =
        process_verified_transaction(&state, transaction, &idempotency_key, verified).await?;
    json_ok(outcome)
}

#[salvo::oapi::endpoint(operation_id = "ak.edge.applet.realm.read.resolve", tags("extensions"))]
#[tracing::instrument(skip_all, fields(op = "ak.edge.applet.realm.read.resolve.v1"))]
async fn resolve_realm_endpoint(
    req: &mut Request,
    depot: &mut Depot,
) -> JsonResult<AppletRealmView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let realm_id_or_alias = req
        .param::<String>("realm_id_or_alias")
        .ok_or_else(|| AppError::param_missing("realm_id_or_alias path segment required"))?;
    let record = applet_records(state).await?.into_iter().find(|record| {
        record.portal_realm_id.as_str() == realm_id_or_alias
            || record.package.namespaces.realms.iter().any(|claim| {
                namespace_pattern_matches(
                    AppletNamespaceDomain::Realms,
                    &claim.pattern,
                    &realm_id_or_alias,
                )
            })
            || record.applet_id.as_str() == realm_id_or_alias
    });
    if let Some(record) = record {
        let realm_id = record.portal_realm_id.clone();
        return json_ok(AppletRealmView {
            exists: true,
            realm_id: Some(realm_id),
            title: Some(record.package.package_id.clone()),
            external_ref: Some(ExternalRef {
                protocol: record
                    .package
                    .protocols
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "applet".to_owned()),
                external_id: record.applet_id.to_string(),
                instance_id: Some(record.install_id),
                display_name: None,
                url: None,
            }),
        });
    }
    json_ok(AppletRealmView {
        exists: false,
        realm_id: None,
        title: None,
        external_ref: None,
    })
}

#[salvo::oapi::endpoint(
    operation_id = "ak.edge.applet.read.protocol_metadata",
    tags("extensions")
)]
#[tracing::instrument(skip_all, fields(op = "ak.edge.applet.read.protocol_metadata.v1"))]
async fn protocol_metadata_endpoint(
    req: &mut Request,
    depot: &mut Depot,
) -> JsonResult<AppletProtocolMetadata> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let protocol = req
        .param::<String>("protocol")
        .ok_or_else(|| AppError::param_missing("protocol path segment required"))?;
    let instances = applet_records(state)
        .await?
        .into_iter()
        .filter(|record| {
            record
                .package
                .protocols
                .iter()
                .any(|item| item == &protocol)
        })
        .map(|record| ProtocolInstance {
            instance_id: record.applet_id.to_string(),
            display_name: record.package.package_id.clone(),
            external_ref: Some(ExternalRef {
                protocol: protocol.clone(),
                external_id: record.applet_id.to_string(),
                instance_id: Some(record.install_id),
                display_name: None,
                url: None,
            }),
        })
        .collect::<Vec<_>>();
    json_ok(AppletProtocolMetadata {
        protocol: protocol.clone(),
        display_name: format!("{protocol} applet protocol"),
        icon_blob_ref: None,
        field_definitions: [
            ("applet_id", true),
            ("service_id", false),
            ("status", false),
        ]
        .into_iter()
        .map(|(name, required)| {
            (
                name.to_owned(),
                FieldDefinition {
                    value_kind: "string".to_owned(),
                    required: required.then_some(true),
                    enum_values: None,
                    description: None,
                },
            )
        })
        .collect(),
        instances,
    })
}

#[salvo::oapi::endpoint(
    operation_id = "ak.edge.applet.third_party_users.read.list",
    tags("extensions")
)]
#[tracing::instrument(skip_all, fields(op = "ak.edge.applet.third_party_users.read.list.v1"))]
async fn third_party_users_endpoint(
    req: &mut Request,
    depot: &mut Depot,
) -> JsonResult<AppletActorView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let protocol = query_value(req, "protocol")
        .ok_or_else(|| AppError::param_missing("protocol is required"))?;
    let instance_id = query_value(req, "instance_id")
        .ok_or_else(|| AppError::param_missing("instance_id is required"))?;
    let external_id = query_value(req, "user")
        .or_else(|| query_value(req, "user_id"))
        .or_else(|| query_value(req, "external_id"))
        .ok_or_else(|| AppError::param_missing("external_id is required"))?;
    for record in applet_records(state).await? {
        if let Some(ghost) = record.ghosts.iter().find(|ghost| {
            ghost.external_ref.protocol == protocol
                && ghost.external_ref.instance_id == instance_id
                && ghost.external_ref.external_id == external_id
        }) {
            let actor_id = ghost.ghost_actor_id.clone();
            return json_ok(AppletActorView {
                exists: true,
                actor_id: Some(actor_id),
                display_name: ghost.display_name.clone(),
                external_ref: Some(ExternalRef {
                    protocol: ghost.external_ref.protocol.clone(),
                    external_id: ghost.external_ref.external_id.clone(),
                    instance_id: Some(ghost.external_ref.instance_id.clone()),
                    display_name: ghost.display_name.clone(),
                    url: None,
                }),
            });
        }
    }
    json_ok(AppletActorView {
        exists: false,
        actor_id: None,
        display_name: None,
        external_ref: None,
    })
}

#[salvo::oapi::endpoint(
    operation_id = "ak.edge.applet.third_party_locations.read.list",
    tags("extensions")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ak.edge.applet.third_party_locations.read.list.v1")
)]
async fn third_party_locations_endpoint(
    req: &mut Request,
    depot: &mut Depot,
) -> JsonResult<AppletRealmView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let location = query_value(req, "location")
        .or_else(|| query_value(req, "channel"))
        .or_else(|| query_value(req, "realm"));
    if let Some(location) = location
        && let Some(record) = applet_records(state).await?.into_iter().find(|record| {
            record.portal_realm_id.as_str() == location
                || record.package.namespaces.realms.iter().any(|claim| {
                    namespace_pattern_matches(
                        AppletNamespaceDomain::Realms,
                        &claim.pattern,
                        &location,
                    )
                })
        })
    {
        let realm_id = record.portal_realm_id.clone();
        return json_ok(AppletRealmView {
            exists: true,
            realm_id: Some(realm_id),
            title: Some(record.package.package_id.clone()),
            external_ref: Some(ExternalRef {
                protocol: record
                    .package
                    .protocols
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "applet".to_owned()),
                external_id: location,
                instance_id: Some(record.install_id),
                display_name: None,
                url: None,
            }),
        });
    }
    json_ok(AppletRealmView {
        exists: false,
        realm_id: None,
        title: None,
        external_ref: None,
    })
}

#[cfg(test)]
mod revoke_saga_tests {
    use arkret_wire::Hash;

    use super::*;

    const APPLET_ID: &str = "ak:applet:01904100-0000-7000-8000-000000000001";
    const REALM_ID: &str = "ak:realm:AXqIXbu56hFXteZXtkBsqJxy_puV4mhSv1U0ZkUldxAL";
    const TARGET_GRANT: &str = "ak:grant:AXqIXbu56hFXteZXtkBsqJxy_puV4mhSv1U0ZkUldxAL";

    fn admin_actor(station: &str) -> arkret_wire::ActorId {
        arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:admin-a.example").unwrap(),
            arkret_wire::DidCoreId::new(station).unwrap(),
        ))
    }

    fn realm_scope() -> arkret_wire::ScopeRef {
        arkret_wire::ScopeRef::Realm {
            realm_id: arkret_wire::RealmId::new(REALM_ID).unwrap(),
        }
    }

    fn managed_actor(principal: &str) -> arkret_wire::ActorId {
        arkret_wire::ActorId::realm(arkret_wire::RealmActorId::new(
            arkret_wire::RealmId::new(REALM_ID).unwrap(),
            arkret_wire::DidCoreId::new(principal).unwrap(),
        ))
    }

    fn current_join_event(
        scope: arkret_wire::ScopeRef,
        member: &arkret_wire::ActorId,
        grant: &str,
    ) -> arkret_wire::Event {
        let mut event = arkret_wire::test_support::raw_event_for_actor_at(
            EventKind::MemberState.as_str(),
            scope,
            member.clone(),
            json!({"member_id": member, "membership": "join"}),
            "2026-10-21T00:00:00.000Z".parse().unwrap(),
        )
        .unwrap();
        event.applet_id = Some(arkret_wire::AppletId::new(APPLET_ID).unwrap());
        event.authorization_ref = Some(arkret_wire::AuthorizationRef::new(grant).unwrap());
        event
    }

    #[test]
    fn exact_current_membership_generation_is_removed_but_another_scope_is_not() {
        let target_scope = realm_scope();
        let member = managed_actor("ak:did_core:webvh:z6mkfixtureBot");
        let managed = std::collections::BTreeSet::from([member.clone()]);
        let reason = arkret_wire::ReasonCode::from_wire("requested_by_admin");
        let event = current_join_event(target_scope.clone(), &member, TARGET_GRANT);
        let intent = classify_current_managed_membership(
            APPLET_ID,
            &target_scope,
            &managed,
            &member.to_string(),
            event.event_id.as_str(),
            &event,
            &reason,
        )
        .unwrap()
        .unwrap();
        assert_eq!(intent.member_id, member);
        assert_eq!(intent.membership, AppletManagedMembershipRemoval::Leave);

        let other_scope = arkret_wire::ScopeRef::Circle {
            realm_id: arkret_wire::RealmId::new(REALM_ID).unwrap(),
            circle_id: arkret_wire::CircleId::new(
                "ak:circle:AXqIXbu56hFXteZXtkBsqJxy_puV4mhSv1U0ZkUldxAL",
            )
            .unwrap(),
        };
        let other = current_join_event(other_scope, &member, TARGET_GRANT);
        assert!(
            classify_current_managed_membership(
                APPLET_ID,
                &target_scope,
                &managed,
                &member.to_string(),
                other.event_id.as_str(),
                &other,
                &reason,
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn managed_actor_invite_acceptance_is_a_current_join_generation() {
        let scope = realm_scope();
        let member = managed_actor("ak:did_core:webvh:z6mkfixtureBot");
        let reason = arkret_wire::ReasonCode::from_wire("requested_by_admin");
        let mut accept = arkret_wire::test_support::raw_event_for_actor_at(
            EventKind::InviteAccept.as_str(),
            scope.clone(),
            member.clone(),
            json!({
                "invite_id": "ak:invite:AXqIXbu56hFXteZXtkBsqJxy_puV4mhSv1U0ZkUldxAL",
                "previous_state": "pending",
            }),
            "2026-10-21T00:00:00.000Z".parse().unwrap(),
        )
        .unwrap();
        accept.applet_id = Some(arkret_wire::AppletId::new(APPLET_ID).unwrap());
        accept.authorization_ref = Some(arkret_wire::AuthorizationRef::new(TARGET_GRANT).unwrap());
        let managed = std::collections::BTreeSet::from([member.clone()]);
        let intent = classify_current_managed_membership(
            APPLET_ID,
            &scope,
            &managed,
            &member.to_string(),
            accept.event_id.as_str(),
            &accept,
            &reason,
        )
        .unwrap()
        .unwrap();
        assert_eq!(intent.member_id, member);
        assert_eq!(intent.membership, AppletManagedMembershipRemoval::Leave);

        let mut foreign_invitee = accept.clone();
        foreign_invitee.payload.insert(
            "invitee_account_id".to_owned(),
            json!(arkret_wire::AccountId::new(
                arkret_wire::DidCoreId::new("ak:did_core:web:other.example").unwrap(),
                arkret_wire::DidCoreId::new("ak:did_core:web:service-a.example").unwrap(),
            )),
        );
        assert!(
            classify_current_managed_membership(
                APPLET_ID,
                &scope,
                &managed,
                &member.to_string(),
                foreign_invitee.event_id.as_str(),
                &foreign_invitee,
                &reason,
            )
            .is_err()
        );
    }

    #[test]
    fn exact_install_membership_rejects_missing_ghost_projection_and_ignores_other_applet() {
        let scope = realm_scope();
        let ghost = managed_actor("ak:did_core:webvh:z6mkfixtureGhost");
        let reason = arkret_wire::ReasonCode::from_wire("requested_by_admin");
        let event = current_join_event(scope.clone(), &ghost, TARGET_GRANT);
        assert!(
            classify_current_managed_membership(
                APPLET_ID,
                &scope,
                &std::collections::BTreeSet::new(),
                &ghost.to_string(),
                event.event_id.as_str(),
                &event,
                &reason,
            )
            .is_err()
        );

        let mut other_applet = current_join_event(scope.clone(), &ghost, TARGET_GRANT);
        other_applet.applet_id = Some(
            arkret_wire::AppletId::new("ak:applet:01904100-0000-7000-8000-000000000002".to_owned())
                .unwrap(),
        );
        assert!(
            classify_current_managed_membership(
                APPLET_ID,
                &scope,
                &std::collections::BTreeSet::from([ghost.clone()]),
                &ghost.to_string(),
                other_applet.event_id.as_str(),
                &other_applet,
                &reason,
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn revoke_submissions_bind_the_full_admin_and_member_actors() {
        let actor = admin_actor("ak:did_core:web:service-a.example");
        let member = managed_actor("ak:did_core:webvh:z6mkfixtureBot");
        let scope = arkret_wire::ScopeRef::Realm {
            realm_id: arkret_wire::RealmId::new(
                "ak:realm:AXqIXbu56hFXteZXtkBsqJxy_puV4mhSv1U0ZkUldxAL",
            )
            .unwrap(),
        };
        let event = arkret_wire::test_support::raw_event(
            EventKind::MemberState.as_str(),
            scope.clone(),
            actor.signing_principal_id().clone(),
            actor.as_account_id().unwrap().station_id.clone(),
            json!({"member_id": member, "membership": "leave", "reason": "requested_by_admin"}),
        )
        .unwrap();
        let plan: AppletRevokePlan = serde_json::from_value(json!({
            "applet_id": "ak:applet:01904100-0000-7000-8000-000000000001",
            "service_id": "ak:did_core:webvh:zservice",
            "effective_scope": scope,
            "registration_epoch": format!("sha256:{}", "a".repeat(64)),
            "reason_code": "requested_by_admin",
            "revoke_mode": "revoke_runtime_only",
            "capability_revocations": [],
            "membership_removals": [{"event_kind": "ak.member.state", "member_id": member, "membership": "leave", "reason_code": "requested_by_admin"}],
            "widget_token_refs": []
        })).unwrap();
        let mut request = AppletRevokeRequestBody {
            service_id: plan.service_id.clone(),
            revoke_plan_digest: Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap(),
            effective_scope: scope,
            reason_code: plan.reason_code.clone(),
            revoke_mode: plan.revoke_mode,
            capability_revoke_events: Vec::new(),
            membership_state_events: vec![arkret_wire::EventAdmissionSubmission::new(event)],
        };
        assert!(validate_revoke_submissions(&actor, &plan, &request).is_ok());
        assert!(
            validate_revoke_submissions(
                &admin_actor("ak:did_core:web:service-b.example"),
                &plan,
                &request,
            )
            .is_err()
        );
        let original = request.membership_state_events[0].event.payload.clone();
        for wrong in [
            json!(member.signing_principal_id()),
            json!(arkret_wire::ActorId::service(
                member.signing_principal_id().clone()
            )),
            json!(arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                member.signing_principal_id().clone(),
                arkret_wire::DidCoreId::new("ak:did_core:web:service-b.example").unwrap(),
            ))),
        ] {
            request.membership_state_events[0]
                .event
                .payload
                .insert("member_id".to_owned(), wrong);
            assert!(validate_revoke_submissions(&actor, &plan, &request).is_err());
        }
        request.membership_state_events[0].event.payload = original;
        request.membership_state_events[0]
            .event
            .payload
            .remove("member_id");
        request.membership_state_events[0]
            .event
            .payload
            .insert("actor_id".to_owned(), json!(member));
        assert!(validate_revoke_submissions(&actor, &plan, &request).is_err());
    }

    #[test]
    fn stale_capability_revision_is_rejected_before_the_saga_can_apply_an_effect() {
        let actor = admin_actor("ak:did_core:web:service-a.example");
        let scope = realm_scope();
        let expected_revision = json!({
            "commit_id": "ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4",
            "stream_position": 41
        });
        let plan: AppletRevokePlan = serde_json::from_value(json!({
            "applet_id": APPLET_ID,
            "effective_scope": scope,
            "registration_epoch": format!("sha256:{}", "a".repeat(64)),
            "reason_code": "requested_by_admin",
            "revoke_mode": "revoke_runtime_only",
            "capability_revocations": [{
                "event_kind": "ak.capability.revoke",
                "grant_id": TARGET_GRANT,
                "expected_revision": expected_revision,
                "registration_epoch": format!("sha256:{}", "a".repeat(64)),
                "reason_code": "requested_by_admin"
            }],
            "membership_removals": [],
            "widget_token_refs": []
        }))
        .unwrap();
        let mut event = arkret_wire::test_support::raw_event(
            EventKind::CapabilityRevoke.as_str(),
            realm_scope(),
            actor.signing_principal_id().clone(),
            actor.as_account_id().unwrap().station_id.clone(),
            json!({
                "grant_id": TARGET_GRANT,
                "expected_revision": expected_revision,
                "reason": "requested_by_admin"
            }),
        )
        .unwrap();
        event.actor_id = actor.clone();
        let mut request = AppletRevokeRequestBody {
            service_id: plan.service_id.clone(),
            revoke_plan_digest: Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap(),
            effective_scope: realm_scope(),
            reason_code: plan.reason_code.clone(),
            revoke_mode: plan.revoke_mode,
            capability_revoke_events: vec![arkret_wire::EventAdmissionSubmission::new(event)],
            membership_state_events: Vec::new(),
        };
        assert!(validate_revoke_submissions(&actor, &plan, &request).is_ok());

        request.capability_revoke_events[0].event.payload.insert(
            "expected_revision".to_owned(),
            json!({
                "commit_id": "ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4",
                "stream_position": 40
            }),
        );
        let error = validate_revoke_submissions(&actor, &plan, &request).unwrap_err();
        assert_eq!(error.wire_code(), "failed_precondition");
    }

    fn completed_execution() -> Value {
        json!({
            "principal_id": "ak:did_core:web:service-a.example",
            "admin_actor_id": admin_actor("ak:did_core:web:service-a.example").to_string(),
            "idempotency_key": "revoke-key",
            "request_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "outcome": {
                "operation_id": "ak:operation:01904100-0000-7000-8000-000000000001",
                "revoke_plan_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "status": "complete",
                "steps": []
            }
        })
    }

    #[test]
    fn completed_replay_loads_the_terminal_outcome() {
        let execution = completed_execution();
        let outcome = load_stored_revoke_outcome(
            Some(&execution),
            "ak:did_core:web:service-a.example",
            &admin_actor("ak:did_core:web:service-a.example").to_string(),
            "revoke-key",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .unwrap()
        .unwrap();
        assert_eq!(outcome.status, AppletRevokeSagaStatus::Complete);
    }

    #[test]
    fn successful_install_replay_rejects_changed_body() {
        let error = require_exact_successful_install_replay(
            "install-key",
            "sha256:first",
            "install-key",
            "sha256:changed",
        )
        .unwrap_err();
        assert_eq!(error.wire_code(), "duplicate_conflict");
    }

    #[test]
    fn installed_applet_rejects_another_idempotency_key_before_reusing_authoring_preview() {
        let error = require_exact_successful_install_replay(
            "install-key",
            "sha256:exact",
            "another-key",
            "sha256:exact",
        )
        .unwrap_err();
        assert_eq!(error.wire_code(), "duplicate_conflict");
        assert_eq!(error.http_status(), StatusCode::CONFLICT);
    }

    #[test]
    fn replay_binding_rejects_another_actor_or_service() {
        let execution = completed_execution();
        for (service, actor) in [
            ("did:web:service-a.example", "did:web:admin-b.example"),
            ("did:web:service-b.example", "did:web:admin-a.example"),
        ] {
            let error = load_stored_revoke_outcome(
                Some(&execution),
                service,
                actor,
                "revoke-key",
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap_err();
            assert_eq!(error.wire_code(), "duplicate_conflict");
        }
    }

    #[test]
    fn widget_only_never_fences_the_runtime() {
        assert!(!revoke_mode_fences_runtime(
            AppletRevokeMode::RevokeWidgetOnly
        ));
        assert!(revoke_mode_fences_runtime(
            AppletRevokeMode::RevokeRuntimeOnly
        ));
    }

    #[test]
    fn concurrent_revoke_progress_never_regresses_from_step_three_to_step_two() {
        let outcome = |statuses: &[&str]| {
            serde_json::from_value::<AppletRevokeOutcome>(json!({
                "operation_id": "ak:operation:01904100-0000-7000-8000-000000000001",
                "revoke_plan_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "status": "in_progress",
                "steps": statuses.iter().map(|status| match *status {
                    "pending" => json!({
                        "effect_kind": "capability_revoke_event",
                        "submitted_event_id": "ak:event:AXKJvMpMFIFTD9GYNEzOeImU-2ytvLCtsCq3Mrq9-Ci8",
                        "status": "pending",
                    }),
                    "accepted" => json!({
                        "effect_kind": "capability_revoke_event",
                        "committed_event_ref": {
                            "event_id": "ak:event:AXKJvMpMFIFTD9GYNEzOeImU-2ytvLCtsCq3Mrq9-Ci8",
                            "commit_id": "ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4",
                            "stream_ref": {"kind": "realm", "realm_id": REALM_ID},
                            "stream_position": 42
                        },
                        "status": "accepted",
                    }),
                    other => panic!("unsupported fixture status {other}"),
                }).collect::<Vec<_>>(),
            }))
            .unwrap()
        };
        let step_two = outcome(&["accepted", "accepted", "pending"]);
        let step_three = outcome(&["accepted", "accepted", "accepted"]);
        assert!(revoke_outcome_progress(&step_three) > revoke_outcome_progress(&step_two));
    }

    #[test]
    fn accepted_then_rejected_events_do_not_open_the_local_fence_gate() {
        let outcome: AppletRevokeOutcome = serde_json::from_value(json!({
            "operation_id": "ak:operation:01904100-0000-7000-8000-000000000001",
            "revoke_plan_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "status": "partially_completed",
            "steps": [
                {
                    "effect_kind": "capability_revoke_event",
                    "committed_event_ref": {
                        "event_id": "ak:event:AXKJvMpMFIFTD9GYNEzOeImU-2ytvLCtsCq3Mrq9-Ci8",
                        "commit_id": "ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4",
                        "stream_ref": {"kind": "realm", "realm_id": REALM_ID},
                        "stream_position": 42
                    },
                    "status": "accepted"
                },
                {
                    "effect_kind": "membership_state_event",
                    "submitted_event_id": "ak:event:AZ0ZCDzYHwYBC27RoU6bQQQgjHBScA-_bYFHyK9m1IQJ",
                    "status": "rejected",
                    "reason_code": "cas_conflict"
                },
                {
                    "effect_kind": "local_applet_fence",
                    "effect_ref": APPLET_ID,
                    "status": "pending"
                }
            ]
        }))
        .unwrap();
        assert!(!revoke_outcome_ready_for_local_effect(&outcome));

        let all_events_committed: AppletRevokeOutcome = serde_json::from_value(json!({
            "operation_id": "ak:operation:01904100-0000-7000-8000-000000000001",
            "revoke_plan_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "status": "in_progress",
            "steps": [
                {
                    "effect_kind": "capability_revoke_event",
                    "committed_event_ref": {
                        "event_id": "ak:event:AXKJvMpMFIFTD9GYNEzOeImU-2ytvLCtsCq3Mrq9-Ci8",
                        "commit_id": "ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4",
                        "stream_ref": {"kind": "realm", "realm_id": REALM_ID},
                        "stream_position": 42
                    },
                    "status": "duplicate"
                },
                {
                    "effect_kind": "local_applet_fence",
                    "effect_ref": APPLET_ID,
                    "status": "pending"
                }
            ]
        }))
        .unwrap();
        assert!(revoke_outcome_ready_for_local_effect(&all_events_committed));
    }
}
