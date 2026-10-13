//! Agent aggregate Event fan-out.
//!
//! Provisioning accepts only the closed controller-signed Event pair carried
//! by the SDK request type. Older aggregate operations that do not yet carry a
//! signed Event fail closed instead of asking Coland to impersonate a
//! controller or writing a development-only proof shape into durable history.

use arkret_wire::Event;
#[cfg(test)]
use chrono::Utc;
use coland_http::error::AppError;
use serde_json::Value;

use super::SessionRecord;
use crate::state::AppState;

/// Resolve the authenticated controller's own Principal Control Realm. Agent
/// provisioning may write controller-owned facts there, but it must never
/// create an ordinary Realm and reuse it as an Agent PCR.
pub(super) async fn require_controller_principal_control_realm(
    state: &AppState,
    session: &SessionRecord,
    authority: &arkret_wire::AccountId,
) -> Result<String, AppError> {
    let controller_principal_id = arkret_wire::DidCoreId::new(session.actor.clone())
        .map_err(|error| AppError::internal(format!("session actor is invalid: {error}")))?;
    if authority.principal_id != controller_principal_id
        || authority.station_id.as_str() != state.service_id()
    {
        return Err(crate::app_error!(
            FailedPrecondition,
            "controller authority does not bind this session and Station",
        )
        .with_internal_reason("account_id_mismatch"));
    }
    let record = state
        .persistence()
        .principal_resolution_by_account_id(authority)
        .await
        .map_err(|error| {
            AppError::internal(format!("controller authority lookup failed: {error}"))
        })?
        .ok_or_else(|| {
            crate::app_error!(
                FailedPrecondition,
                "controller authority is not accepted by this Station",
            )
            .with_internal_reason("account_id_mismatch")
        })?;
    // The pair's one PCR lineage is its durable principal resolution, and
    // this Station must govern that PCR to accept a provision into it.
    let authority = state
        .authority_commits()
        .current_authority(&record.pcr_realm_id)
        .await
        .map_err(|error| {
            AppError::internal(format!("controller PCR authority lookup failed: {error}"))
        })?
        .ok_or_else(|| {
            crate::app_error!(
                FailedPrecondition,
                "controller Principal Control Realm must be initialized before provisioning an Agent",
            )
            .with_internal_reason("principal_control_realm_missing")
        })?;
    if authority.service_id != state.service_core_id() {
        return Err(crate::app_error!(
            FailedPrecondition,
            "controller Principal Control Realm is governed by another Station",
        )
        .with_internal_reason("principal_control_realm_missing"));
    }
    Ok(record.pcr_realm_id.to_string())
}

/// `did-usage-and-verification.md` §2.2: a proof `verification_method` MUST be
/// a DID URL with a `#fragment` rooted in `root`. A bare `root` DID names no
/// concrete verification method and is rejected.
#[cfg(test)]
fn verification_method_rooted_in(verification_method: &str, root: &str) -> bool {
    verification_method.starts_with(&format!("{root}#"))
}

/// The provision unit's refusals: both declaration uniqueness checks are
/// `failed_precondition` with their registered reason; signer, schema and
/// head refusals share the PCR self-Event mapping.
fn agent_provision_admission_error(
    code: Option<coland_storage::ConflictCode>,
    detail: &str,
) -> AppError {
    use coland_storage::ConflictCode;
    match code {
        Some(
            reason @ (ConflictCode::AgentProvisioningAlreadyDeclared
            | ConflictCode::AgentPcrGenesisDeclarationConflict),
        ) => crate::app_error!(FailedPrecondition, detail).with_reason_code(reason.as_str()),
        other => crate::routing::identity::account::profile_admission_error(other, detail),
    }
}

/// Validate and admit the single controller-authored provisioning fact.
///
/// The containing Event proof is the only signature. The controller-PCR
/// provision unit verifies the signing device at the locked cut and writes
/// the four typed results with the Commit, or nothing.
#[allow(clippy::too_many_arguments)]
pub(super) async fn submit_provision_event(
    state: &AppState,
    session: &SessionRecord,
    controller_realm_id: &str,
    agent_id: &arkret_wire::DidCoreId,
    principal_control_realm_id: &arkret_wire::RealmId,
    controller_authorization_ref: &arkret_wire::DidUrl,
    agent_slug: &str,
    requested_scope_digest: &arkret_wire::Hash,
    submission: arkret_wire::EventAdmissionSubmission,
) -> Result<String, AppError> {
    let event = &submission.event;
    let payload =
        arkret_models_collaboration::events_payloads::agent::AgentProvisionPayload::try_from(event)
            .map_err(|error| AppError::param_invalid(error.to_string()))?;
    let session_core_id = arkret_wire::DidCoreId::new(session.actor.clone()).map_err(|error| {
        AppError::param_invalid(format!("session DID core id is invalid: {error}"))
    })?;
    let session_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        session_core_id.clone(),
        state.service_core_id().clone(),
    ));
    if event.actor_id != session_actor
        || event.realm_id.as_str() != controller_realm_id
        || payload.agent_id != *agent_id
        || payload.controller_principal_id != session_core_id
        || payload.principal_control_realm_id != *principal_control_realm_id
        || payload.controller_authorization_ref != *controller_authorization_ref
        || payload.agent_slug != agent_slug
        || payload.requested_scope_digest != *requested_scope_digest
    {
        return Err(AppError::param_invalid(
            "provision_event does not match the authenticated allocation",
        ));
    }
    if submission.approval_signatures.is_some() {
        return Err(AppError::schema_violation(
            "provision_event carries no approval signatures",
        ));
    }
    let event_id = event.event_id.to_string();
    let committed_at = chrono::Utc::now();
    let method = arkret_wire::DidUrl::new(
        crate::routing::federation::federation_service_signature_key_id(
            state.service_did().as_str(),
        ),
    )
    .map_err(|error| AppError::internal(error.to_string()))?;
    let transaction = state
        .authority_commits()
        .prepare_self_event_transaction(
            event,
            &state.service_core_id(),
            method,
            state.notary_signing_key().as_ref(),
            committed_at,
        )
        .await
        .map_err(|error| match error {
            coland_services::ServiceError::SchemaViolation(detail) => {
                AppError::schema_violation(detail)
            }
            error => agent_provision_admission_error(error.conflict_code(), error.detail()),
        })?;
    state
        .persistence()
        .admit_agent_provision(coland_storage::AgentProvisionAdmissionWrite {
            commit: transaction,
            queued_at: committed_at,
        })
        .await
        .map_err(|error| match error {
            coland_storage::PersistenceError::SchemaViolation(detail) => {
                AppError::schema_violation(detail)
            }
            error => agent_provision_admission_error(error.conflict_code(), &error.to_string()),
        })?;
    Ok(event_id)
}

/// AKP-0008 §4.11 — submit a durable lifecycle transition event
/// (`ak.self.agent.{pause,resume,deactivate}`) driving the transition reducer.
#[allow(clippy::too_many_arguments)]
pub(super) fn validate_durable_agent_lifecycle(
    session: &SessionRecord,
    realm_id: &str,
    agent_id: &str,
    authorization_ref: &str,
    event_kind: &str,
    previous_status: &str,
    reason: Option<&str>,
    event: &Event,
) -> Result<(), AppError> {
    let transition = match event_kind {
        arkret_wire::event_kind_str::SELF_AGENT_PAUSE => "pause",
        arkret_wire::event_kind_str::SELF_AGENT_RESUME => "resume",
        arkret_wire::event_kind_str::SELF_AGENT_DEACTIVATE => "deactivate",
        _ => {
            return Err(AppError::param_invalid(
                "unsupported Agent lifecycle Event kind",
            ));
        }
    };
    let agent_account = event.actor_id.as_account_id().ok_or_else(|| {
        AppError::capability_denied("lifecycle_event Agent actor must be an Account")
    })?;
    let executing_account = event
        .executed_by
        .as_ref()
        .and_then(arkret_wire::ActorId::as_account_id)
        .ok_or_else(|| {
            AppError::capability_denied("lifecycle_event controller must be an Account")
        })?;
    if event.kind.as_str() != event_kind
        || event.realm_id.as_str() != realm_id
        || agent_account.principal_id.as_str() != agent_id
        || executing_account.principal_id.as_str() != session.actor.as_str()
        || agent_account.station_id != executing_account.station_id
        || event.authorization_ref.as_deref() != Some(authorization_ref)
    {
        return Err(AppError::capability_denied(
            "lifecycle_event does not match the Agent controller binding",
        ));
    }
    if event.producer_proof.is_none() {
        return Err(
            AppError::param_invalid("lifecycle_event must carry a controller proof")
                .with_wire_code("controller_signed_event_required"),
        );
    }
    let payload_reason = event.payload.get("reason").and_then(Value::as_str);
    if event.payload.get("transition").and_then(Value::as_str) != Some(transition)
        || event.payload.get("previous_status").and_then(Value::as_str) != Some(previous_status)
        || payload_reason != reason
    {
        return Err(AppError::param_invalid(
            "lifecycle_event payload does not match the requested transition",
        ));
    }
    // The accepted registry contract derives the lifecycle transition from this
    // exact signed Event. Ordinary admission validates that registered contract.
    Ok(())
}

/// Admit an already validated, controller-signed Agent PCR control Event
/// (`ak.agent.key.*`, `ak.self.agent.*`) through the Agent control unit: the
/// unit decides the provision binding, the controller device, accountability
/// and the kind's lifecycle or key-set gate at the Agent PCR cut.
pub(super) async fn submit_signed_agent_event(
    state: &AppState,
    session: &SessionRecord,
    submission: arkret_wire::EventAdmissionSubmission,
) -> Result<String, AppError> {
    let event = &submission.event;
    if submission.approval_signatures.is_some() {
        return Err(AppError::schema_violation(
            "an Agent control Event carries no approval signatures",
        ));
    }
    let account_pk = session
        .account_pk
        .ok_or_else(|| AppError::unauthenticated("session account binding is missing"))?;
    let authenticated = state
        .identities()
        .account_by_id(account_pk)
        .await
        .map_err(|error| AppError::internal(format!("session account lookup failed: {error}")))?
        .ok_or_else(|| AppError::unauthenticated("session account no longer exists"))?;
    if authenticated.pk != account_pk
        || authenticated.account_id.principal_id.as_str() != session.actor
        || authenticated.account_id.station_id.as_str() != session.audience
        || authenticated.account_id.station_id != state.service_core_id()
        || event.executed_by.as_ref()
            != Some(&arkret_wire::ActorId::account(authenticated.account_id))
    {
        return Err(AppError::capability_denied(
            "an Agent control Event is executed by the authenticated full Account",
        ));
    }
    // Authentication and submission shape still precede the exact original
    // witness; accepted retries never refresh today's Directory or issuer cut.
    if state
        .exact_accepted_agent_control_original(event)
        .await
        .map_err(|error| agent_control_admission_error(error.conflict_code(), error.detail()))?
        .is_some()
    {
        return Ok(event.event_id.to_string());
    }
    let original_source = state
        .prepare_agent_control_original_source(event)
        .await
        .map_err(|error| agent_control_admission_error(error.conflict_code(), error.detail()))?;
    let event_id = event.event_id.to_string();
    let committed_at = chrono::Utc::now();
    let method = arkret_wire::DidUrl::new(
        crate::routing::federation::federation_service_signature_key_id(
            state.service_did().as_str(),
        ),
    )
    .map_err(|error| AppError::internal(error.to_string()))?;
    let transaction = state
        .authority_commits()
        .prepare_self_event_transaction(
            event,
            &state.service_core_id(),
            method,
            state.notary_signing_key().as_ref(),
            committed_at,
        )
        .await
        .map_err(|error| agent_control_admission_error(error.conflict_code(), error.detail()))?;
    state
        .stage_agent_control_original_source(&transaction, original_source)
        .await
        .map_err(|error| agent_control_admission_error(error.conflict_code(), error.detail()))?;
    state
        .persistence()
        .admit_agent_control_event(coland_storage::AgentControlAdmissionWrite {
            commit: transaction,
            queued_at: committed_at,
        })
        .await
        .map_err(|error| {
            agent_control_admission_error(error.conflict_code(), &error.to_string())
        })?;
    Ok(event_id)
}

/// The Agent control unit's refusals: a registered reducer projection that
/// cannot apply (a stale `supersedes`, a revoke with nothing active, a status
/// edge outside the FSM) and a missing accountability record are
/// `failed_precondition` with their reason; the rest share the PCR self-Event
/// mapping.
fn agent_control_admission_error(
    code: Option<coland_storage::ConflictCode>,
    detail: &str,
) -> AppError {
    use coland_storage::ConflictCode;
    match code {
        Some(ConflictCode::ReducerProjectionFailed) => {
            crate::app_error!(FailedPrecondition, detail)
                .with_reason_code(arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED)
        }
        other => crate::routing::identity::account::profile_admission_error(other, detail),
    }
}

/// AKP-0008 §4.11 — submit a durable lifecycle transition event
/// (`ak.self.agent.{pause,resume,deactivate}`) driving the transition reducer.
#[allow(clippy::too_many_arguments)]
pub(super) async fn submit_durable_agent_lifecycle(
    state: &AppState,
    session: &SessionRecord,
    realm_id: &str,
    agent_id: &str,
    authorization_ref: &str,
    event_kind: &str,
    previous_status: &str,
    reason: Option<&str>,
    submission: arkret_wire::EventAdmissionSubmission,
) -> Result<String, AppError> {
    validate_durable_agent_lifecycle(
        session,
        realm_id,
        agent_id,
        authorization_ref,
        event_kind,
        previous_status,
        reason,
        &submission.event,
    )?;
    submit_signed_agent_event(state, session, submission).await
}

#[cfg(test)]
mod tests {
    use arkret_wire::ServiceOperationId;

    use super::*;

    #[test]
    fn runtime_agent_key_scope_service_actions_are_registered() {
        let registry = coland_services::protocol_artifacts::operation_ids();
        for action in [
            ServiceOperationId::SELF_COMMITTED_EVENT_STREAM_SUBSCRIBE_V1,
            ServiceOperationId::SELF_COMMITTED_EVENT_READ_SCAN_V1,
            ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
        ] {
            assert!(
                registry.contains(action),
                "dev fanout agent_key_scope action `{action}` must exist in operation registry"
            );
        }
    }

    #[test]
    fn deprecated_self_events_scope_tokens_are_not_registered() {
        let registry = coland_services::protocol_artifacts::operation_ids();
        for action in [
            "events.subscribe",
            "ak.self.events.subscribe",
            "ak.self-events.subscribe",
            "ak.self-events.stream.subscribe",
        ] {
            assert!(
                !registry.contains(action),
                "deprecated self-events shortcut `{action}` must not be used as an agent runtime scope"
            );
        }
    }

    // did-usage-and-verification.md §2.2 — the accountability-grant and
    // selector-claim proofs MUST name a `#fragment` DID URL rooted in the
    // authenticated controller. The bare controller DID names no concrete
    // verification method, and a sibling DID that merely shares the prefix
    // must not slip through the `starts_with` check.
    #[test]
    fn provision_proof_verification_method_rejects_bare_controller_did() {
        let controller = "did:webvh:z6mkfixture:example.test:users:alice";

        assert!(verification_method_rooted_in(
            &format!("{controller}#device-1"),
            controller
        ));
        assert!(!verification_method_rooted_in(controller, controller));
        assert!(!verification_method_rooted_in(
            &format!("{controller}:bob#device-1"),
            controller
        ));
        assert!(!verification_method_rooted_in(
            "did:webvh:z6mkfixture:example.test:users:bob#device-1",
            controller
        ));
    }

    #[test]
    fn fanout_event_timestamp_uses_canonical_millisecond_profile() {
        let created_at = arkret_canonical::format_timestamp_canonical(Utc::now());

        arkret_canonical::validate_timestamp_canonical(&created_at)
            .expect("fan-out Event Envelope timestamp must pass the shared validator");
        assert_eq!(created_at.len(), "2026-07-18T00:00:00.000Z".len());
        assert!(created_at.ends_with('Z'));
    }
}
