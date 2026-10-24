//! Canonical applet install: package validation, plan building, registration
//! projection, portal message ingress, and the realm-admin governance gate.

use std::collections::BTreeSet;

use arkret_identifiers::{GrantId, Hash, RealmId};
use arkret_identity::DidDocument;
use arkret_models_collaboration::governance::grant_constraint::{
    CapabilitySubject, GrantConstraintKind, GrantConstraintSubkind,
};
use arkret_models_integration::{
    AppletGhostActorMode, AppletInstallAuthoringRequestBasis, AppletInstallEffectiveStatus,
    AppletInstallPlan, AppletInstallRequestBody, AppletInstallResponseBody, AppletPackage,
    AppletRegistrationEpochEvidence, AppletScopeRejection, AppletWireNamespaces, DeniedScope,
    E2eeEffect, NamespaceConflict, PlannedEvent, ScopeGrant, WidgetEffect,
};
use arkret_wire::{
    ActorId, CapabilityActionId, Event, ResourceMatchScope, ScopeRef, WireResourceSelector,
};
use coland_http::error::AppError;
use coland_services::identity::SessionIdentityState as SessionRecord;
use salvo::http::StatusCode;
use salvo::prelude::*;
use serde_json::{Value, json};

use super::record::{
    applet_identity, applet_record, applet_records, encode_applet_identity, encode_applet_record,
};
use super::types::{AppletIdentityRecord, AppletRecord};
use crate::ids;
use crate::state::AppState;

pub(super) struct ValidatedAdminInstallEvents {
    pub approved_actions: Vec<String>,
    pub grant_ids: Vec<GrantId>,
    pub approved_scopes: Vec<ScopeGrant>,
}

pub(super) fn approved_scopes_from_formal_install_events(
    state: &AppState,
    commit: &AppletInstallRequestBody,
    install_actor: &ActorId,
    station_id: &str,
) -> Result<Vec<ScopeGrant>, AppError> {
    let validated = validate_formal_install_events(state, commit, install_actor, station_id)?;
    Ok(validated.approved_scopes)
}

fn validate_formal_install_events(
    _state: &AppState,
    commit: &AppletInstallRequestBody,
    install_actor: &ActorId,
    _station_id: &str,
) -> Result<ValidatedAdminInstallEvents, AppError> {
    let package = &commit.applet_package;
    let basis = &commit.authoring_request_basis;
    validate_admin_install_events(package, basis, install_actor)
}

pub(super) fn validate_admin_install_events(
    package: &AppletPackage,
    basis: &AppletInstallAuthoringRequestBasis,
    install_actor: &ActorId,
) -> Result<ValidatedAdminInstallEvents, AppError> {
    validate_applet_controller_principal(package)?;
    let realm_id = basis.effective_scope.realm_id();
    let registration = &basis.registration_event;
    if &basis.install_actor_id != install_actor
        || registration.kind != arkret_wire::EventKind::AppletRegistration
        || &registration.actor_id != install_actor
        || registration.actor_id.as_account_id().map(|a| &a.station_id)
            != Some(&basis.target_station_id)
        || &registration.realm_id != realm_id
        || registration.scope_ref != ScopeRef::realm(realm_id.clone())
        || registration.producer_proof.is_none()
    {
        return Err(crate::app_error!(
            AppletInstallPlanMismatch,
            "registration_event must be a caller-signed Applet registration in the exact effective scope",
        ));
    }
    let registration_epoch_evidence = registration_epoch_evidence_from_event(registration)?;
    let expected_registration = registration_payload_from_package(
        package,
        &registration_epoch_evidence,
        registration_revision_from_event(registration)?,
    )?;
    let submitted_registration = serde_json::to_value(&registration.payload).map_err(|error| {
        AppError::internal(format!(
            "registration_event payload cannot be canonicalized: {error}"
        ))
    })?;
    if submitted_registration != expected_registration {
        return Err(AppError::conflict(
            "registration_event payload does not match the Applet package",
        )
        .with_wire_code("applet_install_plan_mismatch"));
    }
    if basis.capability_grant_events.is_empty() {
        return Err(crate::app_error!(
            AppletInstallPlanMismatch,
            "capability_grant_events must contain at least one caller-signed Event",
        ));
    }

    let expected_resource = match &basis.effective_scope {
        ScopeRef::Realm { realm_id } => WireResourceSelector::realm(realm_id.clone()),
        ScopeRef::Circle {
            realm_id,
            circle_id,
        } => {
            let mut selector = WireResourceSelector::circle(realm_id.clone(), circle_id.clone());
            selector.match_scope = Some(ResourceMatchScope::Exact);
            selector
        }
        _ => {
            return Err(AppError::param_invalid(
                "unsupported applet effective scope",
            ));
        }
    };
    let expected_applet_id = package.applet_id.clone();
    let requested = package
        .requested_scopes
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut approved_actions = BTreeSet::new();
    let mut grant_ids = Vec::with_capacity(basis.capability_grant_events.len());
    let mut approved_scopes = Vec::with_capacity(basis.capability_grant_events.len());
    let mut event_ids = BTreeSet::new();

    for event in &basis.capability_grant_events {
        if event.kind != arkret_wire::EventKind::CapabilityGrant
            || &event.actor_id != install_actor
            || event.actor_id.as_account_id().map(|a| &a.station_id)
                != Some(&basis.target_station_id)
            || &event.realm_id != realm_id
            || event.scope_ref != basis.effective_scope
            || event.producer_proof.is_none()
            || !event_ids.insert(event.event_id.clone())
        {
            return Err(crate::app_error!(
                AppletInstallPlanMismatch,
                "every capability_grant_event must be unique, caller-signed, and use the exact effective scope",
            ));
        }
        let payload: arkret_models_collaboration::events_payloads::CapabilityGrantPayload =
            serde_json::from_value(serde_json::to_value(&event.payload).map_err(|error| {
                AppError::internal(format!(
                    "capability_grant_event payload cannot be canonicalized: {error}"
                ))
            })?)
            .map_err(|error| {
                crate::app_error!(
                    AppletInstallPlanMismatch,
                    format!("capability_grant_event payload is invalid: {error}")
                )
            })?;
        let grant = payload.grant;
        if grant.issuer_id != event.actor_id
            || grant.realm_id.as_ref() != Some(realm_id)
            || !matches!(
                &grant.subject,
                CapabilitySubject::Actor(subject)
                    if subject == &ActorId::service(package.service_id.clone())
            )
            || grant.resources.len() != 1
            || grant.resources[0] != expected_resource
        {
            return Err(crate::app_error!(
                AppletInstallPlanMismatch,
                "capability grant issuer, subject authority pair, resource, or id does not match the install",
            ));
        }
        let binding_count = grant
            .constraints
            .iter()
            .filter(|constraint| {
                constraint.constraint_kind == GrantConstraintKind::AuthorityControl
                    && constraint.constraint_subkind
                        == Some(GrantConstraintSubkind::AppletAuthority)
                    && constraint.applet_id.as_ref() == Some(&expected_applet_id)
                    && constraint.executed_by.as_ref()
                        == Some(&arkret_wire::ActorId::service(package.service_id.clone()))
                    && constraint.registration_epoch.as_ref() == Some(&package.registration_epoch)
            })
            .count();
        if binding_count != 1 || grant.actions.is_empty() {
            return Err(crate::app_error!(
                AppletInstallPlanMismatch,
                "capability grant must carry one exact applet_authority binding and at least one action",
            ));
        }
        for action in &grant.actions {
            if !requested.contains(action) || !approved_actions.insert(action.clone()) {
                return Err(crate::app_error!(
                    AppletInstallPlanMismatch,
                    "capability grant actions must be unique and requested by the Applet package",
                ));
            }
        }
        grant_ids.push(arkret_identifiers::GrantId::from_event_id(&event.event_id));
        approved_scopes.push(ScopeGrant {
            actions: grant.actions.clone(),
            realm_ids: vec![realm_id.clone()],
            circle_ids: match &basis.effective_scope {
                ScopeRef::Circle { circle_id, .. } => Some(vec![circle_id.clone()]),
                _ => None,
            },
            constraints: grant.constraints.clone(),
        });
    }

    Ok(ValidatedAdminInstallEvents {
        approved_actions: approved_actions.into_iter().collect(),
        grant_ids,
        approved_scopes,
    })
}

pub(super) async fn register_package_install(
    state: &AppState,
    session: &SessionRecord,
    commit: AppletInstallRequestBody,
    recomputed_install_plan: AppletInstallPlan,
    idempotency_key: String,
    body_digest: String,
    res: &mut Response,
) -> Result<AppletInstallResponseBody, AppError> {
    let owner_actor =
        crate::routing::identity::session_actor::session_actor_from_credential(state, session)?;
    let owner_actor_key = owner_actor.to_string();
    let owner_actor_id = owner_actor_key.as_str();
    let validated_events =
        validate_formal_install_events(state, &commit, &owner_actor, state.service_id())?;
    let approved_actions = validated_events.approved_actions;
    let capability_grant_refs = validated_events.grant_ids;
    let basis = &commit.authoring_request_basis;
    let registration_event = basis.registration_event.clone();
    let capability_grant_events = basis.capability_grant_events.clone();
    let committed_request =
        coland_storage::AppletAdmissionRequest::Install(Box::new(commit.clone()));
    let mut admin_producer_guards = Vec::with_capacity(1 + capability_grant_events.len());
    for event in std::iter::once(&registration_event).chain(capability_grant_events.iter()) {
        admin_producer_guards.push(
            crate::state::verify_self_event_producer(state, session, event)
                .await
                .map_err(|error| AppError::capability_denied(error.to_string()))?,
        );
    }
    let epoch = registration_epoch_evidence_from_event(&registration_event)?;
    let service_did_document = crate::jws_verify::resolve_did_document(state, &epoch.did)
        .map_err(AppError::param_invalid)?;
    let submitted_plan_digest = commit.plan_digest.to_string();
    let effective_scope = basis.effective_scope.clone();
    let actor_policy = basis.actor_policy.clone();
    let package = commit.applet_package.clone();
    let typed_applet_id = package.applet_id.clone();
    let applet_id = package.applet_id.to_string();
    let target_station_id = basis.target_station_id.clone();
    let realm_id = effective_scope_realm_id(&effective_scope).to_owned();
    let ghost_actors_allowed =
        ghost_actors_allowed_for_install(&package, &approved_actions, actor_policy.as_ref());

    let existing_installation = applet_record(
        state,
        &applet_id,
        package.service_id.as_str(),
        &effective_scope,
    )
    .await?;
    if let Some(existing) = &existing_installation
        && existing.idempotency_key == idempotency_key
    {
        if existing.install_body_digest.as_str() == body_digest {
            res.status_code(StatusCode::OK);
            return Ok(existing.install_response.clone());
        }
        return Err(AppError::conflict(
            "Idempotency-Key was already used with a different applet install body",
        )
        .with_wire_code("duplicate_conflict"));
    }
    let expected_installation = existing_installation
        .as_ref()
        .map(encode_applet_record)
        .transpose()?;

    let existing_identity = applet_identity(state, &applet_id, target_station_id.as_str()).await?;
    let (identity, expected_identity) = if let Some(mut existing) = existing_identity {
        if package.applet_id != existing.initial_package.applet_id
            || package.controller_principal_id != existing.initial_package.controller_principal_id
        {
            return Err(AppError::conflict(
                "Applet Service identity differs from its original installation",
            ));
        }
        let expected = encode_applet_identity(&existing)?;
        existing.globally_fenced_at = None;
        (existing, Some(expected))
    } else {
        (
            AppletIdentityRecord {
                applet_id: package.applet_id.clone(),
                registry_id: package.controller_principal_id.clone(),
                target_station_id: target_station_id.clone(),
                initial_package: package.clone(),
                initial_owner_actor_id: registration_event.actor_id.clone(),
                initial_effective_scope: effective_scope.clone(),
                initial_registration_event: registration_event.clone(),
                initial_capability_grant_refs: capability_grant_refs.clone(),
                globally_fenced_at: None,
            },
            None,
        )
    };
    let identity_value = encode_applet_identity(&identity)?;

    let now = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let e2ee_authorization_refs = commit.e2ee_join_authorization_refs().map_err(|error| {
        AppError::capability_denied(error.to_string())
            .with_wire_code("applet_e2ee_join_unauthorized")
    })?;
    debug_assert!(!approved_actions.is_empty());
    let effective_status = if approved_actions.len() < package.requested_scopes.len() {
        AppletInstallEffectiveStatus::PartiallyInstalled
    } else {
        AppletInstallEffectiveStatus::Installed
    };
    let effective_status_wire = match effective_status {
        AppletInstallEffectiveStatus::Installed => "installed",
        AppletInstallEffectiveStatus::PartiallyInstalled => "partially_installed",
    };
    let install_id = ids::generate_install_id();
    let station_verification_method = state
        .service_verification_method("notary-key")
        .map_err(AppError::internal)?;
    let input = coland_storage::AppletAuthoringUnitWrite {
        candidate: coland_storage::AppletAuthoringCandidate {
            request: committed_request,
            package: package.clone(),
            recomputed_install_plan: Some(recomputed_install_plan),
            service_did_document,
            controller_did_document: package_controller_document(state, &package)?,
            station_verification_method,
            station_public_key: *state.notary_verifying_key().as_bytes(),
            admin_actor_id: owner_actor.clone(),
            admin_producer_guards,
            request_digest: Hash::new(body_digest.clone())
                .map_err(|error| AppError::param_invalid(error.to_string()))?,
            canonical_request_hash: Hash::new(body_digest.clone())
                .map_err(|error| AppError::param_invalid(error.to_string()))?,
            prior_managed_refs: Vec::new(),
            prior_service_signer_evidence: None,
            accepted_at: now,
        },
        creation_service_resolution: None,
        expected_identity: expected_identity.clone(),
        expected_installation: expected_installation.clone(),
        preview_subject_key: String::new(),
        operation_id: "ak.self.applet.command.install".to_owned(),
        idempotency_key: idempotency_key.clone(),
        operation_approvals: None,
    };
    let audit_package = package.clone();
    let admin_actor = owner_actor.clone();
    let station_id = state.service_id().to_owned();
    let finalizer: coland_storage::AppletUnitFinalizer = std::sync::Arc::new(move |references| {
        let registration_event_ref = crate::routing::events::event_log::applet_committed_ref(
            references,
            &registration_event,
        )?
        .event_id;
        let response = AppletInstallResponseBody {
            install_id: install_id.clone(),
            applet_id: package.applet_id.clone(),
            service_id: package.service_id.clone(),
            registration_event_ref,
            registration_epoch: package.registration_epoch.clone(),
            capability_grant_refs: capability_grant_refs.clone(),
            e2ee_authorization_refs: e2ee_authorization_refs.clone(),
            widget_policy_ref: None,
            effective_status,
            rejections: denied_scope_values(&package, &approved_actions)
                .into_iter()
                .map(|scope| AppletScopeRejection {
                    requested_scope: Some(scope.requested_scope),
                    reason_code: scope.reason_code,
                })
                .collect(),
        };
        let mut record = AppletRecord {
            identity: identity.clone(),
            applet_id: typed_applet_id.clone(),
            owner_actor_id: registration_event.actor_id.clone(),
            portal_realm_id: RealmId::new(realm_id.clone()).map_err(|error| {
                coland_storage::PersistenceError::Internal(format!(
                    "validated portal realm id is invalid: {error}"
                ))
            })?,
            effective_scope: effective_scope.clone(),
            capabilities: approved_actions.clone(),
            package: package.clone(),
            ghost_actors_allowed,
            status: effective_status_wire.to_owned(),
            registered_at: now,
            revoked_at: None,
            idempotency_key: idempotency_key.clone(),
            install_body_digest: Hash::new(body_digest.clone()).map_err(|error| {
                coland_storage::PersistenceError::Internal(format!(
                    "validated install body digest is invalid: {error}"
                ))
            })?,
            install_id: response.install_id.clone(),
            install_response: response.clone(),
            registration_event: registration_event.clone(),
            capability_grant_events: capability_grant_events.clone(),
            install_execution: Value::Null,
            revoke_execution: None,
            bots: Vec::new(),
            ghosts: Vec::new(),
        };
        record.install_execution = build_install_execution_record(
            &station_id,
            &admin_actor.to_string(),
            &record.idempotency_key,
            record.install_body_digest.as_str(),
            &submitted_plan_digest,
            &record,
            &response,
            true,
        )
        .map_err(|error| coland_storage::PersistenceError::Internal(error.to_string()))?;
        let response_body = serde_json::to_value(&response)
            .map_err(|error| coland_storage::PersistenceError::Internal(error.to_string()))?;
        Ok(coland_storage::AppletUnitFinalization {
            applet_record: coland_storage::AppletRecordCommit {
                applet_id: typed_applet_id.clone(),
                identity: coland_storage::AppletIdentityCommit {
                    target_station_id: target_station_id.clone(),
                    expected_record: expected_identity.clone(),
                    record: identity_value.clone(),
                },
                expected_record: expected_installation.clone(),
                record: encode_applet_record(&record).map_err(|error| {
                    coland_storage::PersistenceError::Internal(error.to_string())
                })?,
            },
            idempotency_record: coland_storage::IdempotencyRecord {
                authenticated_actor: admin_actor.clone(),
                operation_id: "ak.self.applet.command.install".to_owned(),
                idempotency_key: idempotency_key.clone(),
                request_hash: body_digest.clone(),
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
            .map_err(|error| {
                crate::routing::events::event_log::submit_one_error_to_app_error(
                    "Applet admission",
                    error.status(),
                    error.code(),
                    &error.message(),
                )
            })?;
    let response: AppletInstallResponseBody = serde_json::from_value(accepted.response_body)
        .map_err(|error| {
            AppError::internal(format!("stored Applet outcome is invalid: {error}"))
        })?;
    crate::routing::append_audit_log(
        state,
        Some(owner_actor_id),
        "applet.install",
        json!({
            "applet_id": audit_package.applet_id,
            "namespaces": &audit_package.namespaces,
            "service_id": audit_package.service_id,
            "registration_event_ref": response.registration_event_ref,
            "registration_epoch": audit_package.registration_epoch,
        }),
        "accepted",
    )
    .await;
    res.status_code(if accepted.replayed {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    });
    Ok(response)
}

fn build_install_execution_record(
    principal_id: &str,
    admin_actor_id: &str,
    idempotency_key: &str,
    body_digest: &str,
    submitted_plan_digest: &str,
    record: &AppletRecord,
    response: &AppletInstallResponseBody,
    accepted: bool,
) -> Result<Value, AppError> {
    let status = if accepted { "completed" } else { "pending" };
    let produced_event_refs = if accepted {
        install_produced_event_refs(record, response)
    } else {
        Vec::new()
    };
    Ok(json!({
        "principal_id": principal_id,
        "admin_actor_id": admin_actor_id,
        "idempotency_key": idempotency_key,
        "body_hash": body_digest,
        "submitted_plan_digest": submitted_plan_digest,
        "status": status,
        "effective_status": record.status.as_str(),
        "produced_event_refs": produced_event_refs,
        "steps": install_execution_steps(record, response, accepted)?,
    }))
}

fn install_produced_event_refs(
    record: &AppletRecord,
    response: &AppletInstallResponseBody,
) -> Vec<String> {
    let mut refs = Vec::with_capacity(
        5 + response.capability_grant_refs.len()
            + usize::from(response.widget_policy_ref.is_some()),
    );
    refs.push(response.registration_event_ref.to_string());
    refs.extend(
        record
            .capability_grant_events
            .iter()
            .map(|event| event.event_id.to_string()),
    );
    if let Some(widget_policy_ref) = &response.widget_policy_ref {
        refs.push(widget_policy_ref.to_string());
    }
    refs
}

fn install_execution_steps(
    record: &AppletRecord,
    response: &AppletInstallResponseBody,
    accepted: bool,
) -> Result<Vec<Value>, AppError> {
    let package = &record.package;
    let mut steps = Vec::with_capacity(5 + response.capability_grant_refs.len());
    let event = &record.registration_event;
    steps.push(install_execution_step(
        0,
        arkret_wire::EventKind::AppletRegistration.as_str(),
        event.event_id.as_str(),
        crate::util::canonical_digest(&serde_json::to_value(event).map_err(|error| {
            AppError::internal(format!("registration Event serialization failed: {error}"))
        })?)?,
        accepted,
        None,
    ));
    for (offset, event) in record.capability_grant_events.iter().enumerate() {
        let grant_id = arkret_identifiers::GrantId::from_event_id(&event.event_id);
        steps.push(install_execution_step(
            offset + 1,
            arkret_wire::EventKind::CapabilityGrant.as_str(),
            event.event_id.as_str(),
            crate::util::canonical_digest(&serde_json::to_value(event).map_err(|error| {
                AppError::internal(format!(
                    "capability grant Event serialization failed: {error}"
                ))
            })?)?,
            accepted,
            Some(json!({
                "applet_id": record.applet_id.as_str(),
                "grant_id": grant_id.as_str(),
                "executed_by": arkret_wire::ActorId::service(package.service_id.clone()),
                "registration_epoch": package.registration_epoch.to_string(),
            })),
        ));
    }
    Ok(steps)
}

fn install_execution_step(
    step_index: usize,
    target_event_kind: &str,
    planned_event_ref: &str,
    canonical_event_body_hash: String,
    accepted: bool,
    grant_binding: Option<Value>,
) -> Value {
    let status = if accepted { "accepted" } else { "pending" };
    let event_ref = if accepted {
        Value::String(planned_event_ref.to_owned())
    } else {
        Value::Null
    };
    let mut step = json!({
        "step_index": step_index,
        "target_event_kind": target_event_kind,
        "canonical_event_body_hash": canonical_event_body_hash,
        "status": status,
        "planned_event_ref": planned_event_ref,
        "event_ref": event_ref,
    });
    if let Some(grant_binding) = grant_binding
        && let Some(object) = step.as_object_mut()
    {
        object.insert("grant_binding".to_owned(), grant_binding);
    }
    step
}

pub(super) fn validate_applet_package(
    state: &AppState,
    package: &AppletPackage,
    registration_epoch_evidence: &AppletRegistrationEpochEvidence,
) -> Result<(), AppError> {
    validate_applet_controller_principal(package)?;
    validate_requested_capability_actions(package)?;
    validated_registration_epoch_evidence(state, package, registration_epoch_evidence)?;
    package
        .validate_with_epoch_evidence(registration_epoch_evidence)
        .map_err(|error| {
            crate::app_error!(SchemaViolation, format!("applet package invalid: {error}"),)
        })?;
    if let Some(expires_at) = package.expires_at
        && expires_at <= chrono::Utc::now()
    {
        return Err(AppError::conflict("applet package has expired")
            .with_internal_reason("applet_package_expired"));
    }
    let expected_digest = package
        .compute_package_digest()
        .map_err(|error| AppError::internal(format!("package digest failed: {error}")))?;
    if package.package_digest.as_ref() != Some(&expected_digest) {
        return Err(crate::app_error!(
            SchemaViolation,
            "applet package_digest does not match package body",
        ));
    }
    let proof = package
        .proof
        .as_ref()
        .ok_or_else(|| AppError::param_invalid("applet package proof is required"))?;
    proof.validate().map_err(|error| {
        AppError::param_invalid(format!("applet package proof invalid: {error}"))
    })?;
    let mut unsigned = package.clone();
    unsigned.proof = None;
    let unsigned_canonical_bytes =
        arkret_canonical::canonical_json_bytes(&unsigned).map_err(|error| {
            AppError::internal(format!("package proof canonical bytes failed: {error}"))
        })?;
    let expected_payload_digest =
        arkret_identifiers::Hash::new(arkret_canonical::sha256_digest(&unsigned_canonical_bytes))
            .map_err(|error| AppError::internal(format!("package proof digest invalid: {error}")))?;
    if proof.payload_digest != expected_payload_digest {
        return Err(
            AppError::param_invalid("applet package proof payload_digest mismatch")
                .with_reason_code("proof_invalid"),
        );
    }
    // applet-integration.md §4.1 line 193/199 + §4b line 229: the controller
    // detached proof MUST be a real signature by `controller_principal_id` covering the
    // canonical package body. Digest equality alone is forgeable — anyone can
    // recompute `payload_digest` over `unsigned` and sign it with an arbitrary
    // key. Anchor the proof's verification_method to `controller_principal_id` and run
    // the same detached-JWS verifier every other coland proof path uses
    // (DID-resolved Ed25519 in every mode). Preview/commit MUST
    // fail closed (`proof_invalid`) when the controller proof is invalid or its
    // key cannot be resolved.
    validate_controller_proof(state, package, &unsigned_canonical_bytes)?;
    Ok(())
}

fn validate_applet_controller_principal(package: &AppletPackage) -> Result<(), AppError> {
    if package.controller_principal_id == package.service_id {
        return Err(crate::app_error!(
            SchemaViolation,
            "applet runtime service_id cannot be used as controller_principal_id",
        ));
    }
    Ok(())
}

pub(super) fn registration_epoch_producer_signing_key(
    state: &AppState,
    package: &AppletPackage,
    evidence: &AppletRegistrationEpochEvidence,
) -> Result<arkret_wire::DidKey, AppError> {
    let document =
        crate::jws_verify::resolve_did_document(state, &evidence.did).map_err(|reason| {
            AppError::param_invalid("applet service DID document could not be resolved")
                .with_reason_detail(format!(
                    "applet_registration_epoch_evidence_mismatch: {reason}"
                ))
        })?;
    registration_epoch_signing_key_from_document(package, evidence, &document)
}

fn registration_epoch_signing_key_from_document(
    package: &AppletPackage,
    evidence: &AppletRegistrationEpochEvidence,
    document: &DidDocument,
) -> Result<arkret_wire::DidKey, AppError> {
    validate_registration_epoch_evidence_for_document(package, evidence, document)?;
    let public_key = arkret_identity::jws::resolve_ed25519_pubkey_from_document(
        document,
        package.webhook_signature_policy.key_ref.as_str(),
    )
    .map_err(|error| {
        AppError::param_invalid(format!(
            "applet registration-epoch producer key is invalid: {error}"
        ))
        .with_internal_reason("applet_registration_epoch_signing_key_mismatch")
    })?;
    let public_key_multibase =
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(public_key.as_bytes());
    arkret_wire::DidKey::new(format!("did:key:{public_key_multibase}")).map_err(|error| {
        AppError::param_invalid(format!(
            "applet registration-epoch producer key is invalid: {error}"
        ))
        .with_internal_reason("applet_registration_epoch_signing_key_mismatch")
    })
}

fn validate_requested_capability_actions(package: &AppletPackage) -> Result<(), AppError> {
    for action in &package.requested_scopes {
        match arkret_schema::capability_action(action) {
            Some(_) => {}
            None => {
                return Err(crate::app_error!(SchemaViolation, format!(
                    "applet package requested_scopes contains unknown capability action: {action}"
                ))
                .with_reason_detail("capability_action_unknown"));
            }
        }
    }
    Ok(())
}

/// Cryptographically verify the controller detached proof on an Applet package.
///
/// Reuses the shared coland detached-JWS verifier boundary
/// (`crate::jws_verify`) in every mode: the controller DID document is
/// resolved and the Ed25519 signature is verified against the verification
/// method's public key.
///
/// `controller_principal_id` is anchored two ways: the proof's `verification_method`
/// MUST be a DID URL under `controller_principal_id`, and the resolved public key MUST
/// come from `controller_principal_id`'s DID document. A proof signed by any
/// other key — even with a correctly recomputed `payload_digest` — fails here.
pub(super) fn package_controller_document(
    state: &AppState,
    package: &AppletPackage,
) -> Result<DidDocument, AppError> {
    let proof = package
        .proof
        .as_ref()
        .ok_or_else(|| AppError::param_invalid("applet package proof is required"))?;
    let controller = proof
        .verification_method
        .split_once('#')
        .map(|(did, _)| did)
        .ok_or_else(|| {
            AppError::param_invalid("applet package verification method has no controller")
        })?;
    let controller = arkret_wire::Did::new(controller)
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    crate::jws_verify::resolve_did_document(state, &controller).map_err(AppError::param_invalid)
}

fn validate_controller_proof(
    state: &AppState,
    package: &AppletPackage,
    unsigned_canonical_bytes: &[u8],
) -> Result<(), AppError> {
    let proof = package
        .proof
        .as_ref()
        .ok_or_else(|| AppError::param_invalid("applet package proof is required"))?;
    let controller_principal_id = package.controller_principal_id.as_str();
    crate::jws_verify::validate_verification_method_controller(
        controller_principal_id,
        &proof.verification_method,
    )
    .map_err(|reason| {
        AppError::param_invalid("applet package proof is not anchored to controller_principal_id")
            .with_reason_code("proof_invalid")
            .with_reason_detail(reason)
    })?;
    crate::jws_verify::verify_did_controlled_jws(
        unsigned_canonical_bytes,
        &proof.jws,
        &proof.verification_method,
        controller_principal_id,
        state,
    )
    .map_err(|reason| {
        AppError::param_invalid("applet package controller proof signature is invalid")
            .with_reason_code("proof_invalid")
            .with_reason_detail(reason)
    })
}

fn validated_registration_epoch_evidence(
    state: &AppState,
    package: &AppletPackage,
    evidence: &AppletRegistrationEpochEvidence,
) -> Result<(), AppError> {
    let document =
        crate::jws_verify::resolve_did_document(state, &evidence.did).map_err(|reason| {
            AppError::param_invalid("applet service DID document could not be resolved")
                .with_reason_detail(format!(
                    "applet_registration_epoch_evidence_mismatch: {reason}"
                ))
        })?;
    validate_registration_epoch_evidence_for_document(package, evidence, &document)
}

fn validate_registration_epoch_evidence_for_document(
    package: &AppletPackage,
    evidence: &AppletRegistrationEpochEvidence,
    document: &DidDocument,
) -> Result<(), AppError> {
    evidence
        .validate_against_did_document(document)
        .map_err(|reason| {
            AppError::param_invalid(
                "applet registration_epoch evidence does not match service DID document",
            )
            .with_reason_detail(format!(
                "applet_registration_epoch_evidence_mismatch: {reason}"
            ))
        })?;
    if !evidence.contains_signing_key(&package.webhook_signature_policy.key_ref) {
        return Err(AppError::param_invalid(
            "applet webhook_signature_policy key_ref is outside registration_epoch evidence",
        )
        .with_internal_reason("applet_registration_epoch_signing_key_mismatch"));
    }
    Ok(())
}

pub(super) async fn build_install_plan(
    state: &AppState,
    package: &AppletPackage,
    registration_epoch_evidence: &AppletRegistrationEpochEvidence,
    scope: &ScopeRef,
    approved_scopes: Vec<ScopeGrant>,
    expected_revision: Option<arkret_wire::CurrentRevision>,
) -> Result<AppletInstallPlan, AppError> {
    let namespace_conflicts =
        namespace_conflicts_for(state, package.applet_id.as_str(), &package.namespaces).await?;
    if !namespace_conflicts.is_empty() {
        return Err(AppError::conflict("applet namespace is already claimed")
            .with_wire_code("applet_namespace_conflict"));
    }
    let approved_actions = actions_from_approved_scopes(&approved_scopes);
    let denied_scopes = denied_scope_values(package, &approved_actions);
    let registration_payload =
        registration_payload_from_package(package, registration_epoch_evidence, expected_revision)?;
    let package_digest = package
        .package_digest
        .clone()
        .ok_or_else(|| AppError::param_missing("applet_package.package_digest is required"))?;
    let event_payload = serde_json::from_value(registration_payload).map_err(|error| {
        AppError::internal(format!(
            "applet registration payload is not an object: {error}"
        ))
    })?;
    let mut plan = AppletInstallPlan {
        schema: arkret_wire::SchemaId::APPLET_INSTALL_PLAN_V1.to_owned(),
        plan_id: arkret_wire::PlanId::new(UNASSIGNED_PLAN_ID)
            .map_err(|error| AppError::internal(error.to_string()))?,
        applet_id: package.applet_id.clone(),
        service_id: package.service_id.clone(),
        package_digest: package_digest.clone(),
        registration_epoch: package.registration_epoch.clone(),
        effective_scope: scope.clone(),
        requested_scopes: package.requested_scopes.clone(),
        approved_scopes,
        denied_scopes,
        planned_events: vec![PlannedEvent {
            event_kind: arkret_wire::EventKind::AppletRegistration
                .as_str()
                .to_owned(),
            payload: event_payload,
            semantic_refs: None,
        }],
        namespace_conflicts: Vec::<NamespaceConflict>::new(),
        e2ee_effect: e2ee_effect_for_package(package),
        widget_effect: widget_effect_for_package(package),
        warnings: Vec::new(),
        plan_digest: package_digest.clone(),
    };
    plan.plan_id = deterministic_plan_id(&plan)?;
    plan.stamp_plan_digest()
        .map_err(|error| AppError::internal(format!("install plan digest failed: {error}")))?;
    Ok(plan)
}

pub(super) fn registration_payload_from_package(
    package: &AppletPackage,
    registration_epoch_evidence: &AppletRegistrationEpochEvidence,
    expected_revision: Option<arkret_wire::CurrentRevision>,
) -> Result<Value, AppError> {
    let registration = package
        .to_registration(registration_epoch_evidence, expected_revision)
        .map_err(|error| AppError::schema_violation(error.to_string()))?;
    serde_json::to_value(registration).map_err(|error| {
        AppError::internal(format!("Applet registration cannot be serialized: {error}"))
    })
}

pub(super) fn registration_epoch_evidence_from_event(
    event: &Event,
) -> Result<AppletRegistrationEpochEvidence, AppError> {
    // An absent or malformed carrier violates the closed
    // `applet-registration-epoch-evidence.schema.json` shape; a schema-valid
    // carrier that disagrees with the resolved DID state is rejected later.
    super::registration_epoch_evidence_from_event(event).map_err(AppError::schema_violation)
}

pub(super) fn e2ee_effect_for_package(package: &AppletPackage) -> E2eeEffect {
    E2eeEffect {
        mls_join_required: package.e2ee_policy.mls_join_requested.unwrap_or(false),
        plaintext_access: "policy_declared".to_owned(),
        authorization_refs: None,
    }
}

pub(super) fn widget_effect_for_package(package: &AppletPackage) -> WidgetEffect {
    WidgetEffect {
        widget_allowed: package.widget.is_some(),
        policy_event_ref: None,
    }
}

/// Placeholder identity carried only until [`deterministic_plan_id`] replaces
/// it; both derived identifiers are excluded from the digest seed.
const UNASSIGNED_PLAN_ID: &str = "ak:plan:unassigned";

/// The plan id is the canonical digest of the plan content with its two
/// derived identifiers (`plan_id` and `plan_digest`) omitted.
pub(super) fn deterministic_plan_id(
    plan: &AppletInstallPlan,
) -> Result<arkret_wire::PlanId, AppError> {
    let mut seed = serde_json::to_value(plan)
        .map_err(|error| AppError::internal(format!("install plan encoding failed: {error}")))?;
    let object = seed
        .as_object_mut()
        .ok_or_else(|| AppError::internal("install plan must encode as an object"))?;
    object.remove("plan_id");
    object.remove("plan_digest");
    let digest = crate::util::canonical_digest(&seed)?;
    arkret_wire::PlanId::new(format!("ak:plan:{}", digest.trim_start_matches("sha256:")))
        .map_err(|error| AppError::internal(error.to_string()))
}

pub(super) fn actions_from_approved_scopes(scopes: &[ScopeGrant]) -> Vec<String> {
    scopes
        .iter()
        .flat_map(|scope| scope.actions.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

pub(super) fn denied_scope_values(
    package: &AppletPackage,
    approved_actions: &[String],
) -> Vec<DeniedScope> {
    let approved = approved_actions.iter().collect::<BTreeSet<_>>();
    package
        .requested_scopes
        .iter()
        .filter(|scope| !approved.contains(scope))
        .map(|scope| DeniedScope {
            requested_scope: scope.clone(),
            reason_code: arkret_wire::ReasonCode::from_wire("not_approved"),
        })
        .collect()
}

pub(super) async fn namespace_conflicts_for(
    state: &AppState,
    applet_id: &str,
    namespaces: &AppletWireNamespaces,
) -> Result<Vec<Value>, AppError> {
    let mut conflicts = Vec::new();
    for record in applet_records(state)
        .await?
        .into_iter()
        .filter(|record| record.revoked_at.is_none() && record.applet_id.as_str() != applet_id)
    {
        let existing = &record.package.namespaces;
        for conflict in namespaces.conflicts_with(existing) {
            conflicts.push(json!({
                "namespace": conflict.pattern,
                "existing_owner": record.applet_id.to_string(),
                "resolution": "deny",
            }));
        }
    }
    Ok(conflicts)
}

pub(super) fn effective_scope_realm_id(scope: &ScopeRef) -> String {
    match scope {
        ScopeRef::Realm { realm_id } | ScopeRef::Circle { realm_id, .. } => realm_id.to_string(),
        _ => unreachable!("unsupported canonical applet effective scope"),
    }
}

/// Governance gate for canonical applet install/revoke.
///
/// An authenticated session is not enough to register or revoke a realm-scoped
/// applet install: the actor MUST hold `ak.realm.admin` over the install's
/// effective_scope realm in the durable authorization cut (a covering grant,
/// or the effective `ak.realm.owner` aggregate). Mirrors the ban gate in
/// `routing/events/operations/policy.rs::validate_member_state_policy`.
/// fail-closed: anything other than an explicit allow is rejected with
/// `applet_registration_unauthorized`.
pub(super) async fn require_realm_admin(
    state: &AppState,
    session: &SessionRecord,
    scope: &ScopeRef,
) -> Result<(), AppError> {
    let realm_id = effective_scope_realm_id(scope);
    let actor =
        crate::routing::identity::session_actor::session_actor_from_credential(state, session)?;
    if crate::authz::authorize(
        state,
        &realm_id,
        &actor,
        &[arkret_wire::CapabilityActionId::REALM_ADMIN],
        &realm_id,
        chrono::Utc::now(),
    )
    .await?
    .allowed()
    {
        return Ok(());
    }
    Err(
        AppError::capability_denied("actor lacks ak.realm.admin over the applet install realm")
            .with_wire_code("applet_registration_unauthorized"),
    )
}

pub(super) fn ghost_actors_allowed_for_install(
    package: &AppletPackage,
    approved_actions: &[String],
    actor_policy: Option<&arkret_models_integration::applet_models::AppletActorPolicy>,
) -> bool {
    let package_allows = package.ghost_policy.enabled;
    let scope_approved = approved_actions
        .iter()
        .any(|action| action == CapabilityActionId::APPLET_GHOST_PROVISION);
    let actor_policy_allows = actor_policy.is_none_or(|policy| {
        matches!(
            policy.ghost_actor_mode,
            Some(AppletGhostActorMode::ControllerApproved | AppletGhostActorMode::PolicyDeclared)
        )
    });
    package_allows && scope_approved && actor_policy_allows
}

#[cfg(test)]
mod tests {
    use arkret_identifiers::{Did, DidCoreId, Hash};
    use arkret_models_integration::{
        AppletEndpointAuth, AppletEndpointEntry, AppletEndpointMethod, AppletNamespaceEntry,
    };
    use arkret_signatures::Ed25519PayloadSigner;

    use super::*;

    /// Applet registration epoch evidence accepts only versioned
    /// `did:webvh` / `did:key` service DIDs
    /// (`applet-registration-epoch-evidence.schema.json`).
    const TEST_APPLET_SERVICE_DID: &str = "did:webvh:z6mktestapplet:test-applet.example";

    fn test_applet_service_did() -> Did {
        Did::new(TEST_APPLET_SERVICE_DID.to_owned()).unwrap()
    }

    fn pinned_service_method_version() -> arkret_models_integration::AppletDidMethodVersionEvidence
    {
        arkret_models_integration::AppletDidMethodVersionEvidence::versioned(
            "did:webvh",
            Some("1-QmTestAppletServiceVersion".to_owned()),
            None,
        )
        .unwrap()
    }

    /// Minimal production-mode (`development_mode == false`) AppState for
    /// exercising the controller-proof verifier against the built-in
    /// `did:key` resolver. Mirrors `routing/events/operations/policy_tests.rs`
    /// but with real-crypto verification enabled.
    fn production_test_state() -> AppState {
        let config = crate::config::AppConfig {
            object_storage: crate::config::ObjectStorageConfig::local(
                std::env::temp_dir().join("coland-applet-proof-test-blobs"),
            ),
            did_resolver_allow_methods: vec!["web".to_owned(), "key".to_owned()],
            notary_signing_key_seed: Some([9u8; 32]),
            ..crate::config::AppConfig::test_default()
        };
        AppState::new(config, coland_storage_postgres::Db { pool: None })
    }

    /// Derive a `did:key` DID + its `#`-fragment verification method for an
    /// Ed25519 seed, using the SDK's canonical multibase encoder so the
    /// built-in `DidKeyResolver` resolves the embedded public key.
    fn did_key_for_seed(seed: [u8; 32]) -> (Did, String) {
        let verifying = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
        let multibase =
            arkret_canonical::ed25519_pubkey_to_did_key_multibase(&verifying.to_bytes());
        let did_str = format!("did:key:{multibase}");
        let vm = format!("{did_str}#{multibase}");
        (Did::new(did_str).unwrap(), vm)
    }

    /// Build a sealed package whose `controller_principal_id` is a `did:key` and whose
    /// `registration_epoch_evidence` is consistent with a non-empty service
    /// DID document, then sign it with the signer/verification_method chosen
    /// by the caller. When the signer key differs from `controller_principal_id`'s key
    /// the resulting controller proof MUST fail verification.
    fn signed_did_key_package(
        controller_seed: [u8; 32],
        signer_seed: [u8; 32],
        verification_method: &str,
    ) -> AppletPackage {
        let (controller_did, _) = did_key_for_seed(controller_seed);
        let controller_principal_id = arkret_wire::project_did_to_core_id(&controller_did).unwrap();
        let service_did = test_applet_service_did();
        let service_id = arkret_wire::project_did_to_core_id(&service_did).unwrap();
        let mut package = AppletPackage::new(
            "package:ak:applet:test".to_owned(),
            arkret_identifiers::AppletId::new("ak:applet:01974100-0000-7000-8000-000000000001")
                .unwrap(),
            service_id.clone(),
            service_did.clone(),
            controller_principal_id.clone(),
            "https://test-applet.example".to_owned(),
            vec!["arkret.portal".to_owned()],
            AppletWireNamespaces {
                handles: vec![AppletNamespaceEntry::exclusive("bridge.test".to_owned())],
                ..Default::default()
            },
        );
        package.requested_scopes = vec!["ak.message.create".to_owned()];
        package.endpoint_policy.endpoints = vec![AppletEndpointEntry {
            method: AppletEndpointMethod::Post,
            path: "/events".to_owned(),
            authentication_kind: Some(AppletEndpointAuth::WebhookSignature),
            description: None,
            extra: Default::default(),
        }];
        let evidence = arkret_models_integration::applet::AppletRegistrationEpochEvidence::new(
            service_did,
            Hash::new(format!("sha256:{}", "22".repeat(32))).unwrap(),
            pinned_service_method_version(),
            vec![
                arkret_models_integration::applet::AppletAcceptedSigningKeyEvidence {
                    key_ref: package.webhook_signature_policy.key_ref.to_string(),
                    public_key_digest: Hash::new(format!("sha256:{}", "33".repeat(32))).unwrap(),
                },
            ],
        );
        package.stamp_registration_epoch(&evidence).unwrap();
        package.stamp_package_digest().unwrap();
        let signer = Ed25519PayloadSigner::from_did_key_seed(
            signer_seed,
            controller_did,
            arkret_wire::DidUrl::new(verification_method).expect("fixture DID URL"),
        );
        package
            .sign(
                &signer,
                &arkret_wire::DidUrl::new(verification_method).expect("fixture DID URL"),
            )
            .unwrap();
        package
    }

    #[test]
    fn registration_payload_preserves_canonical_whole_second_package_timestamp() {
        let seed = [1u8; 32];
        let (controller_did, controller_vm) = did_key_for_seed(seed);
        let mut package = signed_did_key_package(seed, seed, &controller_vm);
        let evidence = AppletRegistrationEpochEvidence::new(
            test_applet_service_did(),
            Hash::new(format!("sha256:{}", "22".repeat(32))).unwrap(),
            pinned_service_method_version(),
            vec![
                arkret_models_integration::applet::AppletAcceptedSigningKeyEvidence {
                    key_ref: package.webhook_signature_policy.key_ref.to_string(),
                    public_key_digest: Hash::new(format!("sha256:{}", "33".repeat(32))).unwrap(),
                },
            ],
        );
        package.created_at =
            arkret_canonical::parse_timestamp_canonical("2026-01-01T00:00:00.000Z").unwrap();
        package.stamp_registration_epoch(&evidence).unwrap();
        package.stamp_package_digest().unwrap();
        let verification_method = arkret_wire::DidUrl::new(controller_vm).unwrap();
        let signer = Ed25519PayloadSigner::from_did_key_seed(
            seed,
            controller_did,
            verification_method.clone(),
        );
        package.sign(&signer, &verification_method).unwrap();

        let payload = registration_payload_from_package(&package, &evidence, None).unwrap();
        assert_eq!(payload["created_at"], "2026-01-01T00:00:00.000Z");
        let registration: arkret_models_integration::AppletRegistrationPayload =
            serde_json::from_value(payload).unwrap();
        assert_eq!(registration.created_at, package.created_at);
        assert_eq!(
            serde_json::to_value(&registration.proof).unwrap(),
            serde_json::to_value(package.proof.as_ref().unwrap()).unwrap()
        );
    }

    #[test]
    fn validate_controller_proof_rejects_wrong_key_signature() {
        let state = production_test_state();
        // controller_principal_id is keyed by `controller_seed`, but the proof is signed
        // with `signer_seed` while still naming controller_principal_id's verification
        // method. The forged proof recomputes the correct payload digest yet
        // the Ed25519 signature is made by the wrong key — verification MUST
        // fail closed with `proof_invalid`.
        let controller_seed = [1u8; 32];
        let signer_seed = [2u8; 32];
        let (_, controller_vm) = did_key_for_seed(controller_seed);
        let package = signed_did_key_package(controller_seed, signer_seed, &controller_vm);

        let mut unsigned = package.clone();
        unsigned.proof = None;
        let bytes = arkret_canonical::canonical_json_bytes(&unsigned).unwrap();
        let error = validate_controller_proof(&state, &package, &bytes)
            .expect_err("wrong-key controller proof must be rejected");
        assert_eq!(error.wire_code(), "param_invalid");
        assert_eq!(
            error.reason_code.as_deref(),
            Some(arkret_wire::ReasonCode::PROOF_INVALID)
        );
    }

    #[test]
    fn requested_capability_actions_accept_registered_applet_actions() {
        let controller_seed = [1u8; 32];
        let (_, controller_vm) = did_key_for_seed(controller_seed);
        let mut package = signed_did_key_package(controller_seed, controller_seed, &controller_vm);
        package.requested_scopes = vec![
            "ak.message.create".to_owned(),
            "ak.applet.ghost.provision".to_owned(),
        ];

        validate_requested_capability_actions(&package)
            .expect("registered capability actions must pass preview validation");
    }

    #[test]
    fn runtime_service_cannot_be_the_applet_controller_principal() {
        let mut package = sample_package();
        package.controller_principal_id = package.service_id.clone();

        let error = validate_applet_controller_principal(&package)
            .expect_err("runtime service must not be accepted as publisher principal");
        assert_eq!(error.wire_code(), "schema_violation");
        assert_eq!(error.http_status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn validate_controller_proof_rejects_unanchored_verification_method() {
        let state = production_test_state();
        // Sign with a verification_method belonging to a *different* DID than
        // controller_principal_id. The anchoring gate MUST reject before any crypto,
        // because the proof is not attributable to controller_principal_id.
        let controller_seed = [1u8; 32];
        let other_seed = [2u8; 32];
        let (_, other_vm) = did_key_for_seed(other_seed);
        let package = signed_did_key_package(controller_seed, other_seed, &other_vm);

        let mut unsigned = package.clone();
        unsigned.proof = None;
        let bytes = arkret_canonical::canonical_json_bytes(&unsigned).unwrap();
        let error = validate_controller_proof(&state, &package, &bytes).expect_err(
            "controller proof not anchored to controller_principal_id must be rejected",
        );
        assert_eq!(error.wire_code(), "param_invalid");
        assert_eq!(
            error.reason_code.as_deref(),
            Some(arkret_wire::ReasonCode::PROOF_INVALID)
        );
    }

    #[test]
    fn validate_controller_proof_accepts_correct_controller_signature() {
        let state = production_test_state();
        // Same key for controller_principal_id and signer: a genuine controller proof
        // verifies against the resolved did:key public key.
        let seed = [1u8; 32];
        let (_, vm) = did_key_for_seed(seed);
        let package = signed_did_key_package(seed, seed, &vm);

        let mut unsigned = package.clone();
        unsigned.proof = None;
        let bytes = arkret_canonical::canonical_json_bytes(&unsigned).unwrap();
        validate_controller_proof(&state, &package, &bytes)
            .expect("genuine controller proof must verify");
    }

    fn sample_package() -> AppletPackage {
        let service_did = test_applet_service_did();
        AppletPackage::new(
            "package:ak:applet:test".to_owned(),
            arkret_identifiers::AppletId::new("ak:applet:01974100-0000-7000-8000-000000000001")
                .unwrap(),
            arkret_wire::project_did_to_core_id(&service_did).unwrap(),
            service_did,
            DidCoreId::new("ak:did_core:web:test-registry.example".to_owned()).unwrap(),
            "https://test-applet.example".to_owned(),
            vec!["arkret.portal".to_owned()],
            AppletWireNamespaces {
                handles: vec![AppletNamespaceEntry::exclusive("bridge.test".to_owned())],
                ..Default::default()
            },
        )
    }

    #[test]
    fn ghost_actors_allowed_uses_package_ghost_policy_enabled() {
        let mut package = sample_package();
        package.ghost_policy = arkret_models_integration::applet::AppletGhostPolicy {
            enabled: true,
            accountability_template: Some("bot_actor_and_applet_registry".to_owned()),
            ..Default::default()
        };
        let actor_policy = arkret_models_integration::applet_models::AppletActorPolicy {
            ghost_actor_mode: Some(
                arkret_models_integration::applet_models::AppletGhostActorMode::PolicyDeclared,
            ),
        };
        assert!(ghost_actors_allowed_for_install(
            &package,
            &[CapabilityActionId::APPLET_GHOST_PROVISION.to_owned()],
            Some(&actor_policy)
        ));

        package.ghost_policy = arkret_models_integration::applet::AppletGhostPolicy {
            enabled: false,
            accountability_template: Some("bot_actor_and_applet_registry".to_owned()),
            ..Default::default()
        };
        assert!(!ghost_actors_allowed_for_install(
            &package,
            &[CapabilityActionId::APPLET_GHOST_PROVISION.to_owned()],
            Some(&actor_policy)
        ));
    }

    #[test]
    fn registration_epoch_signing_key_accepts_jwk_and_multibase_with_pinned_evidence() {
        let package = sample_package();
        let key = ed25519_dalek::SigningKey::from_bytes(&[31; 32]).verifying_key();
        let multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(key.as_bytes());
        let expected = arkret_wire::DidKey::new(format!("did:key:{multibase}")).unwrap();
        let jwk = json!({
            "kty": "OKP", "crv": "Ed25519",
            "x": arkret_canonical::base64url_encode(key.as_bytes()),
        })
        .to_string();
        for material in [multibase, jwk] {
            let document = DidDocument::new(
                test_applet_service_did(),
                package.webhook_signature_policy.key_ref.to_string(),
                material,
            );
            let evidence = AppletRegistrationEpochEvidence::from_did_document(
                &document,
                pinned_service_method_version(),
            )
            .unwrap();
            assert_eq!(
                registration_epoch_signing_key_from_document(&package, &evidence, &document)
                    .unwrap(),
                expected
            );

            let mut rotated = document.clone();
            rotated.verification_methods.insert(
                package.webhook_signature_policy.key_ref.to_string(),
                arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                    ed25519_dalek::SigningKey::from_bytes(&[32; 32])
                        .verifying_key()
                        .as_bytes(),
                ),
            );
            let error = registration_epoch_signing_key_from_document(&package, &evidence, &rotated)
                .unwrap_err();
            assert_eq!(error.wire_code(), "param_invalid");
            assert!(
                error
                    .reason_detail
                    .as_deref()
                    .is_some_and(|detail| detail
                        .starts_with("applet_registration_epoch_evidence_mismatch: ")),
                "{error:?}"
            );
        }
    }

    #[test]
    fn registration_epoch_signing_key_rejects_non_ed25519_material() {
        let package = sample_package();
        let document = DidDocument::new(
            test_applet_service_did(),
            package.webhook_signature_policy.key_ref.to_string(),
            json!({"kty": "OKP", "crv": "X25519", "x": arkret_canonical::base64url_encode(&[31; 32])}).to_string(),
        );
        let evidence = AppletRegistrationEpochEvidence::from_did_document(
            &document,
            pinned_service_method_version(),
        )
        .unwrap();
        let error = registration_epoch_signing_key_from_document(&package, &evidence, &document)
            .unwrap_err();
        assert_eq!(error.wire_code(), "param_invalid");
        assert_eq!(
            error.reason_detail.as_deref(),
            Some("applet_registration_epoch_signing_key_mismatch")
        );
    }

    #[test]
    fn registration_epoch_validation_accepts_pinned_webvh_and_refuses_web_snapshot() {
        let package = sample_package();
        let document = DidDocument::new(
            test_applet_service_did(),
            package.webhook_signature_policy.key_ref.to_string(),
            r#"{"crv":"Ed25519","kty":"OKP","x":"fixture"}"#,
        );
        let evidence =
            arkret_models_integration::AppletRegistrationEpochEvidence::from_did_document(
                &document,
                pinned_service_method_version(),
            )
            .unwrap();
        validate_registration_epoch_evidence_for_document(&package, &evidence, &document).unwrap();

        // A `did:web` current snapshot has no version selector that historical
        // producer verification could pin.
        let web_document = DidDocument::new(
            Did::new("did:web:test-applet.example".to_owned()).unwrap(),
            "did:web:test-applet.example#controller".to_owned(),
            r#"{"crv":"Ed25519","kty":"OKP","x":"fixture"}"#,
        );
        assert!(
            arkret_models_integration::AppletRegistrationEpochEvidence::from_did_document(
                &web_document,
                pinned_service_method_version(),
            )
            .is_err()
        );
        let mut web_evidence = serde_json::to_value(&evidence).unwrap();
        web_evidence["did"] = json!("did:web:test-applet.example");
        web_evidence["method_version_evidence"] =
            json!({"method": "did:web", "unversioned_refetch": true});
        assert!(
            serde_json::from_value::<arkret_models_integration::AppletRegistrationEpochEvidence>(
                web_evidence
            )
            .is_err()
        );
    }

    #[test]
    fn registration_epoch_validation_rejects_rotation_until_new_snapshot_is_used() {
        let package = sample_package();
        let old_document = DidDocument::new(
            test_applet_service_did(),
            package.webhook_signature_policy.key_ref.to_string(),
            r#"{"crv":"Ed25519","kty":"OKP","x":"old"}"#,
        );
        let old_evidence = AppletRegistrationEpochEvidence::from_did_document(
            &old_document,
            pinned_service_method_version(),
        )
        .unwrap();
        validate_registration_epoch_evidence_for_document(&package, &old_evidence, &old_document)
            .unwrap();

        let rotated_document = DidDocument::new(
            test_applet_service_did(),
            package.webhook_signature_policy.key_ref.to_string(),
            r#"{"crv":"Ed25519","kty":"OKP","x":"rotated"}"#,
        );
        assert!(
            validate_registration_epoch_evidence_for_document(
                &package,
                &old_evidence,
                &rotated_document,
            )
            .is_err()
        );

        let rotated_evidence = AppletRegistrationEpochEvidence::from_did_document(
            &rotated_document,
            pinned_service_method_version(),
        )
        .unwrap();
        validate_registration_epoch_evidence_for_document(
            &package,
            &rotated_evidence,
            &rotated_document,
        )
        .unwrap();
        assert_ne!(
            old_evidence.document_digest,
            rotated_evidence.document_digest
        );
    }

    #[test]
    fn registration_epoch_validation_rejects_deactivated_and_empty_key_documents() {
        let package = sample_package();
        let mut deactivated_document = DidDocument::new(
            test_applet_service_did(),
            package.webhook_signature_policy.key_ref.to_string(),
            r#"{"crv":"Ed25519","kty":"OKP","x":"fixture"}"#,
        );
        let active_evidence = AppletRegistrationEpochEvidence::from_did_document(
            &deactivated_document,
            pinned_service_method_version(),
        )
        .unwrap();
        deactivated_document
            .raw_properties
            .insert("deactivated".to_owned(), json!(true));
        assert!(
            validate_registration_epoch_evidence_for_document(
                &package,
                &active_evidence,
                &deactivated_document,
            )
            .is_err()
        );
        assert!(
            AppletRegistrationEpochEvidence::from_did_document(
                &deactivated_document,
                pinned_service_method_version(),
            )
            .is_err()
        );

        let mut keyless_document = deactivated_document.clone();
        keyless_document.raw_properties.remove("deactivated");
        keyless_document.verification_methods.clear();
        assert!(
            AppletRegistrationEpochEvidence::from_did_document(
                &keyless_document,
                pinned_service_method_version(),
            )
            .is_err()
        );
        let mut empty_evidence = active_evidence;
        empty_evidence.accepted_signing_keys.clear();
        assert!(
            validate_registration_epoch_evidence_for_document(
                &package,
                &empty_evidence,
                &keyless_document,
            )
            .is_err()
        );
    }

    #[test]
    fn registration_epoch_validation_rejects_swapped_service_document() {
        let package = sample_package();
        let swapped_document = DidDocument::new(
            Did::new("did:webvh:z6mkotherapplet:other-applet.example".to_owned()).unwrap(),
            "did:webvh:z6mkotherapplet:other-applet.example#controller".to_owned(),
            r#"{"crv":"Ed25519","kty":"OKP","x":"fixture"}"#,
        );
        let swapped_evidence = AppletRegistrationEpochEvidence::from_did_document(
            &swapped_document,
            pinned_service_method_version(),
        )
        .unwrap();
        assert!(
            validate_registration_epoch_evidence_for_document(
                &package,
                &swapped_evidence,
                &swapped_document,
            )
            .is_err()
        );
    }
}

pub(super) fn registration_revision_from_event(
    event: &Event,
) -> Result<Option<arkret_wire::CurrentRevision>, AppError> {
    let payload: arkret_models_integration::AppletRegistrationPayload = serde_json::from_value(
        serde_json::to_value(&event.payload)
            .map_err(|e| AppError::schema_violation(e.to_string()))?,
    )
    .map_err(|e| AppError::schema_violation(e.to_string()))?;
    Ok(payload.expected_revision)
}
