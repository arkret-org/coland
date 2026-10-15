//! Mapping admission reuses accepted Ghost provenance without creating Events.
use arkret_models_integration::{
    AppletManagedActorCommittedRequest, ExistingManagedActor, GhostActorProvisionOutcome,
    GhostActorProvisionRequestBody, GhostExternalTuple,
};
use arkret_wire::{ActorId, Hash};
use coland_http::error::AppError;
use coland_http::result::{JsonResult, json_ok};
use salvo::prelude::*;

use super::record::*;
use super::signature::VerifiedAppletServiceSignature;
use super::types::{AppletRecord, GhostActorRecord};
use crate::state::AppState;

pub(super) fn anchors(ghost: &GhostActorRecord) -> ExistingManagedActor {
    ExistingManagedActor {
        ghost_actor_id: ghost.ghost_actor_id.clone(),
        managed_actor_provision_ref: ghost.managed_actor_provision_event.event_id.clone(),
        principal_control_realm_id: ghost.principal_control_realm_id(),
        profile_event_ref: ghost.profile_event.event_id.clone(),
        accountability_grant_ref: ghost.accountability_grant_event.event_id.clone(),
    }
}

pub(super) async fn find_existing(
    state: &AppState,
    installation: &AppletRecord,
    external: &GhostExternalTuple,
) -> Result<Option<GhostActorRecord>, AppError> {
    let mut winner: Option<GhostActorRecord> = None;
    for record in applet_records(state).await? {
        if record.applet_id != installation.applet_id
            || record.target_station_id != installation.target_station_id
        {
            continue;
        }
        for ghost in record
            .ghosts
            .into_iter()
            .filter(|g| &g.external_ref == external)
        {
            if winner
                .as_ref()
                .is_some_and(|prior| anchors(prior) != anchors(&ghost))
            {
                return Err(AppError::conflict(
                    "Ghost tuple has conflicting accepted identities",
                ));
            }
            winner = Some(ghost);
        }
    }
    Ok(winner)
}

pub(super) async fn provision(
    state: &AppState,
    body: GhostActorProvisionRequestBody,
    verified: VerifiedAppletServiceSignature,
    req: &mut Request,
    res: &mut Response,
) -> JsonResult<GhostActorProvisionOutcome> {
    let basis = body
        .authoring_basis()
        .ok_or_else(|| AppError::param_invalid("Ghost authoring basis absent"))?
        .clone();
    if basis.target_station_id != state.service_core_id()
        || basis.service_id != verified.install.package.service_id
        || basis.effective_scope != verified.install.effective_scope
    {
        return Err(AppError::capability_denied(
            "Ghost mapping Service or scope differs",
        ));
    }

    let path = applet_id_param(req)?;
    let mut record = applet_record(state, &path, &basis.effective_scope)
        .await?
        .ok_or_else(|| AppError::not_found("Applet installation absent"))?;
    ensure_not_revoked(&record)?;
    super::ghost::ensure_formal_ghost_provision_allowed(&record, &body)?;
    let mut ghost = find_existing(state, &record, &basis.external_ref)
        .await?
        .ok_or_else(|| AppError::conflict("Ghost accepted provenance absent"))?;
    let existing = anchors(&ghost);
    if body.existing_managed_actor.as_ref() != Some(&existing)
        || basis.existing_managed_actor.as_ref() != Some(&existing)
    {
        return Err(AppError::conflict(
            "Ghost reuse anchors differ from accepted provenance",
        ));
    }
    let hash = Hash::new(
        arkret_canonical::canonical_sha256(&body)
            .map_err(|e| AppError::param_invalid(e.to_string()))?,
    )
    .map_err(|e| AppError::param_invalid(e.to_string()))?;
    let key =
        idempotency_key(req).ok_or_else(|| AppError::param_missing("Idempotency-Key required"))?;
    if key.len() > 128 {
        return Err(AppError::param_invalid("Idempotency-Key exceeds 128 bytes"));
    }
    let mut prior = vec![];
    for event in [
        &ghost.managed_actor_provision_event,
        &ghost.pcr_genesis_event,
        &ghost.accountability_grant_event,
        &ghost.profile_event,
    ] {
        prior.push(super::endpoints::durable_ghost_event_ref(state, event).await?);
    }
    let expected = encode_applet_record(&record)?;
    let identity = encode_applet_identity(&record.identity)?;
    ghost.request_digest = hash.clone();
    if !record
        .ghosts
        .iter()
        .any(|g| g.external_ref == ghost.external_ref)
    {
        record.ghosts.push(ghost.clone());
    }
    let replacement = encode_applet_record(&record)?;
    let epoch = super::install::registration_epoch_evidence_from_event(&record.registration_event)?;
    let now = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let mut input = coland_storage::AppletAuthoringUnitWrite {
        candidate: coland_storage::AppletAuthoringCandidate {
            request: coland_storage::AppletAdmissionRequest::Managed(
                AppletManagedActorCommittedRequest::Ghost(Box::new(body.clone())),
            ),
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
            admin_actor_id: ActorId::service(basis.service_id.clone()),
            admin_producer_guards: vec![],
            request_digest: body
                .authoring_request
                .canonical_digest()
                .map_err(|e| AppError::param_invalid(e.to_string()))?,
            canonical_request_hash: hash.clone(),
            prior_managed_refs: prior,
            prior_service_signer_evidence: None,
            accepted_at: now,
        },
        expected_identity: Some(identity.clone()),
        expected_installation: Some(expected.clone()),
        preview_subject_key: super::endpoints::applet_authoring_preview_subject_key(
            &body.authoring_request,
        )?,
        operation_id: "ak.self.applet.ghost.command.provision".to_owned(),
        idempotency_key: key.clone(),
        management_approval: None,
    };
    input.management_approval =
        super::management_review::prepare_creation_approvals(state, &input.candidate).await?;
    let finalizer: coland_storage::AppletUnitFinalizer = std::sync::Arc::new(move |refs| {
        // These are reopened accepted tuples, never freshly authored Events.
        for event in [
            &ghost.managed_actor_provision_event,
            &ghost.pcr_genesis_event,
            &ghost.accountability_grant_event,
            &ghost.profile_event,
        ] {
            crate::routing::events::event_log::applet_committed_ref(refs, event)?;
        }
        let outcome = GhostActorProvisionOutcome {
            ghost_actor_id: existing.ghost_actor_id.clone(),
            managed_actor_provision_ref: existing.managed_actor_provision_ref.clone(),
            principal_control_realm_id: existing.principal_control_realm_id.clone(),
            profile_event_ref: existing.profile_event_ref.clone(),
            accountability_grant_ref: existing.accountability_grant_ref.clone(),
            authorization_ref: basis.authorization_ref.clone(),
            display_name: ghost.display_name.clone(),
        };
        let response_body =
            serde_json::to_value(outcome).map_err(coland_storage::PersistenceError::database)?;
        Ok(coland_storage::AppletUnitFinalization {
            applet_record: coland_storage::AppletRecordCommit {
                applet_id: record.applet_id.clone(),
                identity: coland_storage::AppletIdentityCommit {
                    target_station_id: record.target_station_id.clone(),
                    expected_record: Some(identity.clone()),
                    record: identity.clone(),
                },
                expected_record: Some(expected.clone()),
                record: replacement.clone(),
            },
            idempotency_record: coland_storage::IdempotencyRecord {
                authenticated_actor: ActorId::service(basis.service_id.clone()),
                operation_id: "ak.self.applet.ghost.command.provision".to_owned(),
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
    let accepted =
        crate::routing::events::event_log::submit_applet_authoring_unit(state, input, finalizer)
            .await
            .map_err(|e| {
                crate::routing::events::event_log::submit_one_error_to_app_error(
                    "Ghost mapping admission",
                    e.status(),
                    e.code(),
                    &e.message(),
                )
            })?;
    res.status_code(if accepted.replayed {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    });
    json_ok(
        serde_json::from_value(accepted.response_body)
            .map_err(|e| AppError::internal(e.to_string()))?,
    )
}
