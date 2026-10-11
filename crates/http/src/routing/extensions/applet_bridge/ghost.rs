//! Ghost / bot actor provisioning, revocation, and caller-signed proof checks.

use arkret_models_collaboration::governance::accountability::{
    AccountabilityGrantPayload, AccountabilityScope, AccountabilityScopeKind,
};
use arkret_models_integration::{
    AppletManagedActorProvisionPayload, AppletManagedActorRole, AppletNamespaceDomain,
    GhostActorProvisionRequestBody, namespace_pattern_matches,
};
use arkret_wire::{ActorId, CapabilityActionId, Event};
use coland_http::error::AppError;
use serde_json::{Value, json};

use super::install::registration_epoch_evidence_from_event;
use super::record::{applet_record, fence_applet_record};
use super::types::AppletRecord;
use crate::state::AppState;

pub(super) async fn revoke_applet_record_after_admin_gate(
    state: &AppState,
    actor: &str,
    applet_id: &str,
    effective_scope: &arkret_wire::ScopeRef,
) -> Result<super::types::AppletRevokeRecordOutcome, AppError> {
    revoke_applet_record_inner(state, actor, applet_id, effective_scope).await
}

async fn revoke_applet_record_inner(
    state: &AppState,
    actor: &str,
    applet_id: &str,
    effective_scope: &arkret_wire::ScopeRef,
) -> Result<super::types::AppletRevokeRecordOutcome, AppError> {
    let mut attempts = 0_u8;
    let (record, globally_fenced) = loop {
        let current = applet_record(state, applet_id, effective_scope)
            .await?
            .ok_or_else(|| AppError::not_found("applet is not registered"))?;
        if current.status == "revoked" {
            break (
                current.clone(),
                current.identity.globally_fenced_at.is_some(),
            );
        }
        let mut replacement = current.clone();
        let fenced_at = chrono::Utc::now();
        replacement.status = "revoked".to_owned();
        replacement.revoked_at = Some(fenced_at);
        let outcome = fence_applet_record(state, &current, &replacement, fenced_at).await?;
        if outcome.updated {
            break (replacement, outcome.globally_fenced);
        }
        attempts += 1;
        if attempts >= 8 {
            return Err(
                AppError::conflict("Applet record changed repeatedly during revoke")
                    .with_wire_code("cas_conflict"),
            );
        }
    };
    let now = record
        .revoked_at
        .as_ref()
        .cloned()
        .ok_or_else(|| AppError::internal("revoked Applet has no revoked_at"))?;
    crate::routing::append_audit_log(
        state,
        Some(actor),
        "extensions.applet.revoke",
        json!({
            "applet_id": record.applet_id.clone(),
            "bot_actor_ids": record.bots.iter().map(|bot| &bot.bot_actor_id).collect::<Vec<_>>(),
            "ghost_count": record.ghosts.len(),
            "globally_fenced": globally_fenced,
        }),
        "accepted",
    )
    .await;
    Ok(super::types::AppletRevokeRecordOutcome {
        applet_id: record.applet_id.clone(),
        status: "revoked".to_owned(),
        revoked_at: now,
        bot_actor_ids: record
            .bots
            .iter()
            .map(|bot| bot.bot_actor_id.signing_principal_id().to_string())
            .collect(),
        ghost_actor_ids: record
            .ghosts
            .iter()
            .map(|ghost| ghost.ghost_actor_id.signing_principal_id().to_string())
            .collect(),
    })
}

pub(super) fn validate_ghost_actor_provision_request(
    path_applet_id: &str,
    provision: &GhostActorProvisionRequestBody,
) -> Result<(), AppError> {
    let basis = provision.authoring_basis().ok_or_else(|| {
        AppError::param_invalid("Ghost provision authoring purpose must be provision_ghost")
    })?;
    provision
        .authoring_request
        .validate_bindings()
        .map_err(|error| {
            AppError::param_invalid(format!("Ghost authoring request is invalid: {error}"))
        })?;
    provision
        .validate()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    if basis.existing_managed_actor != provision.existing_managed_actor {
        return Err(AppError::param_invalid(
            "reuse anchors must match the signed preview",
        ));
    }
    if let Some(bundle) = &provision.managed_actor_bundle {
        bundle
            .validate_bindings(&provision.authoring_request)
            .map_err(|error| AppError::param_invalid(error.to_string()))?;
    }
    if basis.applet_id.as_str() != path_applet_id {
        return Err(AppError::param_invalid(
            "authoring basis applet_id must match applet_id path segment",
        ));
    }
    for (field, value) in [
        (
            "external_ref.protocol",
            basis.external_ref.protocol.as_str(),
        ),
        (
            "external_ref.instance_id",
            basis.external_ref.instance_id.as_str(),
        ),
        (
            "external_ref.external_id",
            basis.external_ref.external_id.as_str(),
        ),
    ] {
        if value.trim().is_empty() {
            return Err(AppError::param_missing(format!("{field} is required")));
        }
    }
    if let Some(display_name) = basis.display_name.as_deref()
        && display_name.trim().is_empty()
    {
        return Err(AppError::param_invalid(
            "display_name must be omitted or non-empty",
        ));
    }
    Ok(())
}

pub(super) fn ensure_formal_ghost_provision_allowed(
    record: &AppletRecord,
    provision: &GhostActorProvisionRequestBody,
) -> Result<(), AppError> {
    let package = &record.package;
    let basis = provision.authoring_basis().ok_or_else(|| {
        AppError::param_invalid("Ghost provision authoring purpose must be provision_ghost")
    })?;
    let expected_evidence = registration_epoch_evidence_from_event(&record.registration_event)?;
    let expected_authorization_ref = ghost_provision_authorization_ref(record)?;
    if package.service_id != basis.service_id
        || record.applet_id != basis.applet_id
        || record.install_response.registration_event_ref != basis.registration_event_ref
        || package.package_digest.as_ref() != Some(&basis.package_digest)
        || expected_evidence != basis.registration_epoch_evidence
        || expected_authorization_ref != basis.authorization_ref.as_str()
    {
        return Err(AppError::capability_denied(
            "Ghost authoring basis does not match the installed Applet authority",
        ));
    }
    if record.effective_scope != basis.effective_scope {
        return Err(
            AppError::conflict("realm_id does not match installed applet effective scope")
                .with_internal_reason("applet_effective_scope_mismatch"),
        );
    }
    if !record.ghost_actors_allowed {
        return Err(AppError::capability_denied(
            "applet install does not grant ghost actor provisioning",
        ));
    }
    Ok(())
}

pub(super) fn ghost_provision_authorization_ref(record: &AppletRecord) -> Result<String, AppError> {
    if !record
        .capabilities
        .iter()
        .any(|action| action == CapabilityActionId::APPLET_GHOST_PROVISION)
    {
        return Err(AppError::capability_denied(
            "applet install does not grant ak.applet.ghost.provision",
        ));
    }
    for event in &record.capability_grant_events {
        let payload = serde_json::from_value::<
            arkret_models_collaboration::events_payloads::CapabilityGrantPayload,
        >(serde_json::to_value(&event.payload).map_err(|error| {
            AppError::internal(format!(
                "stored Applet capability grant payload cannot be encoded: {error}"
            ))
        })?)
        .map_err(|error| {
            AppError::internal(format!(
                "stored Applet capability grant payload is invalid: {error}"
            ))
        })?;
        if payload
            .grant
            .actions
            .iter()
            .any(|action| action == CapabilityActionId::APPLET_GHOST_PROVISION)
        {
            return Ok(arkret_identifiers::GrantId::from_event_id(&event.event_id).to_string());
        }
    }
    Err(
        AppError::conflict("applet ghost provisioning grant projection is incomplete")
            .with_internal_reason("applet_install_projection_incomplete"),
    )
}

pub(super) async fn validate_signed_ghost_provision_events(
    state: &AppState,
    record: &AppletRecord,
    provision: &GhostActorProvisionRequestBody,
) -> Result<(String, AppletManagedActorProvisionPayload), AppError> {
    let basis = provision.authoring_basis().ok_or_else(|| {
        AppError::param_invalid("Ghost provision authoring purpose must be provision_ghost")
    })?;
    let accountability = &provision
        .managed_actor_bundle
        .as_ref()
        .ok_or_else(|| AppError::conflict("Ghost reuse does not carry creation Events"))?
        .accountability_grant_event;
    let profile = &provision
        .managed_actor_bundle
        .as_ref()
        .ok_or_else(|| AppError::conflict("Ghost reuse does not carry creation Events"))?
        .profile_event;
    let service_actor_id = ActorId::service(basis.service_id.clone());
    let authorization_ref = ghost_provision_authorization_ref(record)?;
    let managed_provision =
        validate_ghost_managed_actor_unit(state, record, provision, authorization_ref.as_str())
            .await?;
    let ghost_actor_id = managed_provision.actor_id.clone();
    let registration_verification_method =
        super::signature::applet_registration_verification_method(
            record,
            basis.service_id.as_str(),
        )?;
    let applet_matches = |event: &Event| {
        event.applet_id.as_ref() == Some(&basis.applet_id)
            && event.authorization_ref.as_deref() == Some(authorization_ref.as_str())
    };
    if accountability.kind != arkret_wire::EventKind::IdentityAccountabilityGrant
        || &accountability.realm_id != basis.effective_scope.realm_id()
        || accountability.actor_id != service_actor_id
        || accountability.executed_by.is_some()
        || !applet_matches(accountability)
    {
        return Err(AppError::param_invalid(
            "accountability_grant_event envelope does not match the Applet provision binding",
        ));
    }
    // Profile state is principal-scoped: it lives in the Ghost's own principal
    // control Realm, founded by the unit's PCR genesis, never in the portal.
    let principal_control_realm_id = arkret_wire::RealmId::from_event_id(
        &provision
            .managed_actor_bundle
            .as_ref()
            .ok_or_else(|| AppError::conflict("Ghost reuse does not carry creation Events"))?
            .pcr_genesis_event
            .event_id,
    );
    if profile.kind != arkret_wire::EventKind::ProfileCreate
        || profile.realm_id != principal_control_realm_id
        || profile.scope_ref
            != (arkret_wire::ScopeRef::Realm {
                realm_id: principal_control_realm_id.clone(),
            })
        || profile.actor_id != ghost_actor_id
        || profile.executed_by.as_ref() != Some(&service_actor_id)
        || !applet_matches(profile)
    {
        return Err(AppError::param_invalid(
            "profile_event envelope does not match the delegated Ghost provision binding",
        ));
    }
    let accountability_refs = profile
        .semantic_refs
        .iter()
        .filter(|event_ref| event_ref.role == "accountability")
        .collect::<Vec<_>>();
    if accountability_refs.len() != 1
        || accountability_refs[0].id != accountability.event_id.as_str()
        || !accountability_refs[0].critical
    {
        return Err(AppError::param_invalid(
            "profile_event must critically reference accountability_grant_event",
        ));
    }
    if accountability
        .producer_proof
        .iter()
        .chain(profile.producer_proof.iter())
        .any(|proof| proof.verification_method != registration_verification_method)
    {
        return Err(AppError::capability_denied(
            "Ghost provisioning Event proofs must use the installed registration-epoch key",
        )
        .with_reason_code(arkret_wire::ReasonCode::PROOF_INVALID));
    }

    let grant: AccountabilityGrantPayload = serde_json::from_value(
        serde_json::to_value(&accountability.payload).map_err(|error| {
            AppError::param_invalid(format!(
                "accountability_grant_event payload invalid: {error}"
            ))
        })?,
    )
    .map_err(|error| {
        AppError::param_invalid(format!(
            "accountability_grant_event payload invalid: {error}"
        ))
    })?;
    if grant.issuer_id != basis.service_id
        || &grant.subject_id != ghost_actor_id.signing_principal_id()
        || grant.accountability_scope
            != AccountabilityScope::Single(AccountabilityScopeKind::ContractedService)
        || !matches!(
            grant.grant_status,
            arkret_models_collaboration::governance::accountability::AccountabilityGrantStatus::Active
        )
    {
        return Err(AppError::param_invalid(
            "accountability_grant_event payload does not bind the service to the Ghost",
        ));
    }
    grant
        .validate_lifecycle_at(chrono::Utc::now())
        .map_err(|error| {
            AppError::param_invalid(format!(
                "accountability_grant_event payload invalid: {error}"
            ))
        })?;
    if grant.proof.verification_method != registration_verification_method {
        return Err(AppError::capability_denied(
            "accountability payload proof must use the installed registration-epoch key",
        )
        .with_reason_code(arkret_wire::ReasonCode::PROOF_INVALID));
    }
    let proof_binding = grant.canonical_proof_binding_bytes().map_err(|error| {
        AppError::param_invalid(format!(
            "accountability payload proof binding is invalid: {error}"
        ))
    })?;
    verify_registration_epoch_payload_jws(
        state,
        record,
        &proof_binding,
        &grant.proof.jws,
        grant.proof.verification_method.as_str(),
    )
    .map_err(|error| {
        AppError::param_invalid(format!(
            "accountability payload proof JWS verification failed: {error}"
        ))
        .with_reason_code(arkret_wire::ReasonCode::PROOF_INVALID)
    })?;

    let profile_payload: arkret_models_collaboration::events_payloads::ActorProfileCreatePayload =
        serde_json::from_value(serde_json::to_value(&profile.payload).map_err(|error| {
            AppError::param_invalid(format!("profile_event payload invalid: {error}"))
        })?)
        .map_err(|error| {
            AppError::param_invalid(format!("profile_event payload invalid: {error}"))
        })?;
    let actor_profile = profile_payload.object;
    let expected_display_name = basis
        .display_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(basis.external_ref.external_id.as_str());
    let expected_external_ref = serde_json::to_value(&basis.external_ref).map_err(|error| {
        AppError::internal(format!("external_ref serialization failed: {error}"))
    })?;
    let has_exact_accountable_principal = actor_profile.accountable_principal_ids.len() == 1
        && actor_profile.accountable_principal_ids[0].as_str() == basis.service_id.as_str();
    if &actor_profile.principal_id != ghost_actor_id.signing_principal_id()
        || actor_profile.actor_kind != arkret_wire::ActorKind::Integration
        || actor_profile.display_name != expected_display_name
        || actor_profile
            .profile_fields
            .get("managed_by_applet")
            .and_then(Value::as_str)
            != Some(basis.applet_id.as_str())
        || actor_profile.profile_fields.get("external_ref") != Some(&expected_external_ref)
        || !has_exact_accountable_principal
    {
        return Err(AppError::param_invalid(
            "profile_event payload does not exactly match the Ghost provision request",
        ));
    }
    Ok((authorization_ref, managed_provision))
}

async fn validate_ghost_managed_actor_unit(
    state: &AppState,
    record: &AppletRecord,
    request: &GhostActorProvisionRequestBody,
    authorization_ref: &str,
) -> Result<AppletManagedActorProvisionPayload, AppError> {
    let basis = request.authoring_basis().ok_or_else(|| {
        AppError::param_invalid("Ghost provision authoring purpose must be provision_ghost")
    })?;
    let event = &request
        .managed_actor_bundle
        .as_ref()
        .ok_or_else(|| AppError::conflict("Ghost reuse does not carry creation Events"))?
        .managed_actor_provision_event;
    let service_actor_id = ActorId::service(basis.service_id.clone());
    if event.kind.as_str() != "ak.applet.managed_actor.provision"
        || event.actor_id != service_actor_id
        || event.applet_id.as_ref() != Some(&basis.applet_id)
        || &event.realm_id != basis.effective_scope.realm_id()
        || event.producer_proof.is_none()
    {
        return Err(AppError::param_invalid(
            "managed_actor_provision_event does not match the installed Applet service",
        )
        .with_reason_code("applet_managed_actor_provision_invalid"));
    }
    let payload: AppletManagedActorProvisionPayload =
        serde_json::from_value(serde_json::to_value(&event.payload).map_err(|error| {
            AppError::internal(format!(
                "managed actor provision serialization failed: {error}"
            ))
        })?)
        .map_err(|error| {
            AppError::param_invalid(format!("managed actor provision payload invalid: {error}"))
                .with_reason_code("applet_managed_actor_provision_invalid")
        })?;
    payload.validate().map_err(|error| {
        AppError::param_invalid(format!("managed actor provision payload invalid: {error}"))
            .with_reason_code("applet_managed_actor_provision_invalid")
    })?;
    if payload.actor_role != AppletManagedActorRole::Ghost
        || payload.applet_id != basis.applet_id
        || payload.service_id != basis.service_id
        || payload.actor_id.signing_principal_id() == &record.package.controller_principal_id
        || record
            .bots
            .iter()
            .any(|bot| payload.actor_id == bot.bot_actor_id)
        || payload.actor_id.route_service_id().as_str() != state.service_id()
        || record.install_response.registration_event_ref != payload.registration_ref
        || payload.applet_authority_ref.as_str() != authorization_ref
        || payload.external_ref.as_ref() != Some(&basis.external_ref)
    {
        return Err(AppError::param_invalid(
            "Ghost provision authority does not bind the exact authority pair, registration, grant, or external principal",
        )
        .with_reason_code("applet_managed_actor_provision_invalid"));
    }
    super::install::validate_managed_actor_method_evidence(&payload)?;
    super::install::validate_managed_actor_current_method_evidence(state, &payload).await?;
    if !record.package.namespaces.actors.is_empty()
        && !record.package.namespaces.actors.iter().any(|entry| {
            namespace_pattern_matches(
                AppletNamespaceDomain::Actors,
                &entry.pattern,
                payload.initial_resolution.did.as_str(),
            )
        })
    {
        return Err(AppError::capability_denied(
            "Ghost did is outside the installed Applet actor namespace",
        )
        .with_reason_code("applet_namespace_mismatch"));
    }

    let genesis = &request
        .managed_actor_bundle
        .as_ref()
        .ok_or_else(|| AppError::conflict("Ghost reuse does not carry creation Events"))?
        .pcr_genesis_event;
    let expected_realm_id = arkret_wire::RealmId::from_event_id(&genesis.event_id);
    let genesis_object: arkret_models_collaboration::events_payloads::RealmGenesis =
        serde_json::from_value(
            genesis
                .payload
                .get("object")
                .cloned()
                .ok_or_else(|| AppError::param_missing("Ghost PCR genesis object is required"))?,
        )
        .map_err(|error| {
            AppError::param_invalid(format!("Ghost PCR genesis object is invalid: {error}"))
                .with_reason_code("applet_managed_pcr_genesis_invalid")
        })?;
    super::install::validate_hosted_applet_pcr_governance_station(
        &genesis_object.governance_station_id,
        &state.service_core_id(),
    )?;
    let provision_ref_count = genesis
        .semantic_refs
        .iter()
        .filter(|reference| {
            reference.role == "applet_managed_actor_provision"
                && reference.critical
                && reference.id == event.event_id.as_str()
        })
        .count();
    let provision_role_count = genesis
        .semantic_refs
        .iter()
        .filter(|reference| reference.role == "applet_managed_actor_provision")
        .count();
    if genesis.kind != arkret_wire::EventKind::RealmCreate
        || genesis.actor_id != payload.actor_id
        || genesis.executed_by.as_ref() != Some(&service_actor_id)
        || genesis.applet_id.as_ref() != Some(&basis.applet_id)
        || genesis.realm_id != expected_realm_id
        || genesis.authorization_ref.as_deref() != Some(authorization_ref)
        || provision_role_count != 1
        || provision_ref_count != 1
        || genesis_object.purpose
            != arkret_models_collaboration::events_payloads::RealmPurpose::AppletManagedControl
        || genesis_object.initial_resolution.as_ref() != Some(&payload.initial_resolution)
    {
        return Err(AppError::param_invalid(
            "Ghost PCR genesis does not exactly cross-bind its immutable provision authority",
        )
        .with_reason_code("applet_managed_pcr_genesis_invalid"));
    }
    Ok(payload)
}

fn verify_registration_epoch_payload_jws(
    state: &AppState,
    record: &AppletRecord,
    canonical_bytes: &[u8],
    jws: &str,
    verification_method: &str,
) -> Result<(), String> {
    let evidence = registration_epoch_evidence_from_event(&record.registration_event)
        .map_err(|error| error.to_string())?;
    if !evidence.contains_signing_key(verification_method) {
        return Err("payload proof key is outside the installed registration epoch".to_owned());
    }
    let document = crate::jws_verify::resolve_did_document(state, &evidence.did)?;
    evidence
        .validate_against_did_document(&document)
        .map_err(|error| format!("registration-epoch DID evidence mismatch: {error}"))?;
    let verification_method = arkret_wire::DidUrl::new(verification_method.to_owned())
        .map_err(|error| format!("payload proof verification method is invalid: {error}"))?;
    arkret_identity::verify_jws_with_document(
        canonical_bytes,
        jws,
        &verification_method,
        &evidence.did,
        &document,
    )
    .map_err(|error| error.to_string())
}
