use super::*;

mod accountability;
#[cfg(test)]
mod agent_participation;
mod governance;
mod message_rules;
mod realm_circle;

use accountability::*;
#[cfg(test)]
pub(crate) use agent_participation::validate_agent_act_on_behalf_approval;
#[cfg(test)]
pub(crate) use agent_participation::validate_agent_reply_participation;
use governance::*;
#[cfg(test)]
pub(crate) use message_rules::realm_ids_match;
#[cfg(test)]
pub(super) use message_rules::validate_principal_control_realm_binding;
use message_rules::*;
use realm_circle::*;

#[cfg(test)]
pub(crate) fn validate_trusted_sidecar_create_operation(
    operation: &Operation,
    controller: &str,
) -> Result<(), &'static str> {
    if kinds::canonical_kind_for_operation(operation) != Some(arkret_wire::EventKind::SidecarCreate)
        || operation.context.sender.as_account_id().is_none()
    {
        return Err("sidecar_create_denied");
    }
    let payload = operation
        .payload
        .as_object()
        .ok_or("sidecar_create_denied")?;
    if operation.context.sender.signing_principal_id().as_str() != controller
        || payload.get("encryption_profile").and_then(Value::as_str) != Some("mls_rfc9420")
        || payload
            .keys()
            .any(|field| field.as_str() != "encryption_profile")
    {
        return Err("sidecar_create_denied");
    }
    Ok(())
}

#[cfg(test)]
pub fn operation_policy_reason_code(message: &str) -> (salvo::http::StatusCode, &'static str) {
    if message == "agent_pcr_recovery_not_ready" {
        (
            salvo::http::StatusCode::PRECONDITION_FAILED,
            "agent_pcr_recovery_not_ready",
        )
    } else if message.starts_with("direct_conversation_")
        || message == "reaction_outside_scope"
        || message == "failed_precondition"
    {
        (salvo::http::StatusCode::CONFLICT, "failed_precondition")
    } else if message == "applet_registration_unauthorized" {
        // applet-integration.md §4 — surface the spec reason verbatim (matches
        // the dedicated install aggregate's `with_wire_code`), not the generic
        // `capability_denied`.
        (
            salvo::http::StatusCode::FORBIDDEN,
            "applet_registration_unauthorized",
        )
    } else if message == arkret_wire::ReasonCode::TRANSCRIPTION_DENIED {
        (
            salvo::http::StatusCode::FORBIDDEN,
            arkret_wire::ReasonCode::TRANSCRIPTION_DENIED,
        )
    } else if message == "principal_control_realm_mismatch" {
        (salvo::http::StatusCode::FORBIDDEN, "capability_denied")
    } else if message == arkret_wire::ReasonCode::AGENT_PARTICIPATION_CEILING_UNRESOLVED {
        (
            salvo::http::StatusCode::PRECONDITION_FAILED,
            arkret_wire::ReasonCode::AGENT_PARTICIPATION_CEILING_UNRESOLVED,
        )
    } else if message == arkret_wire::ReasonCode::ACCOUNTABILITY_GRANT_MISSING {
        (
            salvo::http::StatusCode::PRECONDITION_FAILED,
            arkret_wire::ReasonCode::ACCOUNTABILITY_GRANT_MISSING,
        )
    } else if message == coland_services::operation_semantics::REASON_KEYPACKAGE_NOT_FOUND {
        (
            salvo::http::StatusCode::PRECONDITION_FAILED,
            coland_services::operation_semantics::REASON_KEYPACKAGE_NOT_FOUND,
        )
    } else if message == "sidecar_create_denied" {
        (salvo::http::StatusCode::FORBIDDEN, "sidecar_create_denied")
    } else if message == "circle_manage_capability_required" {
        (
            salvo::http::StatusCode::FORBIDDEN,
            "circle_manage_capability_required",
        )
    } else if message == "circle_member_manage_capability_required" {
        (
            salvo::http::StatusCode::FORBIDDEN,
            "circle_member_manage_capability_required",
        )
    } else if message == "circle_member_must_be_realm_member" {
        (
            salvo::http::StatusCode::UNPROCESSABLE_ENTITY,
            "circle_member_must_be_realm_member",
        )
    } else if message == arkret_wire::ErrorCode::REALM_FROZEN {
        (
            salvo::http::StatusCode::FORBIDDEN,
            arkret_wire::ErrorCode::REALM_FROZEN,
        )
    } else if matches!(
        message,
        "history_not_visible"
            | "not_member"
            | "policy_denied"
            | "device_revoked"
            | "audit_required"
    ) {
        (
            salvo::http::StatusCode::FORBIDDEN,
            match message {
                "history_not_visible" => "history_not_visible",
                "not_member" => "not_member",
                "policy_denied" => "policy_denied",
                "device_revoked" => "device_revoked",
                "audit_required" => "audit_required",
                _ => "capability_denied",
            },
        )
    } else if message == "not_found" {
        (salvo::http::StatusCode::NOT_FOUND, "not_found")
    } else {
        (salvo::http::StatusCode::FORBIDDEN, "capability_denied")
    }
}

pub async fn validate_operation_policy(
    state: &AppState,
    operations: &[Operation],
) -> Result<(), &'static str> {
    validate_operation_policy_common(state, operations, false, false).await
}

async fn validate_operation_policy_common(
    state: &AppState,
    operations: &[Operation],
    has_plaintext_service_binding: bool,
    agent_membership_cascade: bool,
) -> Result<(), &'static str> {
    for operation in operations {
        validate_one_operation_policy(
            state,
            operation,
            operations,
            has_plaintext_service_binding,
            agent_membership_cascade,
        )
        .await?;
    }
    Ok(())
}

async fn validate_one_operation_policy(
    state: &AppState,
    operation: &Operation,
    operations: &[Operation],
    has_plaintext_service_binding: bool,
    agent_membership_cascade: bool,
) -> Result<(), &'static str> {
    {
        validate_realm_lifecycle_write_gate(state, operation, operations)?;
        let cleanup_transition = agent_membership_cascade_cleanup_transition(operation);
        if cleanup_transition && !agent_membership_cascade {
            return Err("agent_membership_cascade_required");
        }
        if !(agent_membership_cascade && cleanup_transition) {
            validate_agent_operation_membership(state, operation).await?;
        }
        if kinds::canonical_kind_for_operation(operation)
            == Some(arkret_wire::EventKind::SidecarCreate)
        {
            // Only the authenticated ensure aggregate may construct this
            // reducer-derived event; the generic submit path is closed.
            return Err("sidecar_create_denied");
        }
        validate_agent_grant_ceiling(state, operation).await?;
        if kinds::operation_is_message_create(operation)
            && !message_operation_is_encrypted(operation)
            && !has_plaintext_service_binding
            && known_realm_denies_plaintext_service(state, operation.realm_id.as_str()).await
        {
            return Err(
                "private plaintext message operations require this service in plaintext_visible_services",
            );
        }
        validate_principal_control_realm_binding(state, operation)?;
        message_rules::validate_agent_control_realm_binding(state, operation).await?;
        validate_accountability_profile_policy(state, operation).await?;
        // Verify the canonical device possession proof on every
        // ak.device.authorize at ingest.
        if kinds::canonical_kind(operation) == arkret_wire::EventKind::DeviceAuthorize {
            let payload = serde_json::from_value::<
                arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizePayload,
            >(operation.payload.clone())
            .map_err(|_| "ak.device.authorize payload violates SDK artifact schema")?;
            crate::routing::identity::device_signing::validate_device_authorize_binding(
                state,
                &payload,
                operation
                    .context
                    .sender
                    .as_account_id()
                    .ok_or("ak.device.authorize requires an account actor")?,
            )?;
        }
        validate_circle_create_policy(state, operation).await?;
        validate_circle_management_policy(state, operation).await?;
        validate_member_state_policy(state, operation, agent_membership_cascade).await?;
        validate_circle_scope_membership(state, operation)?;
        validate_pin_scope_safety(state, operation)?;
        validate_applet_registration_authz(state, operation).await?;
        validate_call_recording_start_policy(state, operation).await?;
        validate_moderation_event_policy(state, operation).await?;
        validate_organization_moderation_policy_authority(operation)?;
        validate_set_default_strand_policy(state, operation).await?;
        validate_realm_organization_policy(state, operation).await?;
        validate_audience_mention_operation_policy(state, operation).await?;
        validate_reaction_scope_policy(state, operation)?;
    }
    Ok(())
}

fn agent_membership_cascade_cleanup_transition(operation: &Operation) -> bool {
    kinds::canonical_kind_for_operation(operation) == Some(arkret_wire::EventKind::MemberState)
        && operation.payload.get("membership").and_then(Value::as_str) == Some("leave")
        && operation
            .payload
            .get("membership_cause")
            .and_then(Value::as_str)
            == Some("controller_membership_ended")
        && operation
            .payload
            .pointer("/agent_controller_binding/controller_terminal_event_ref")
            .and_then(Value::as_str)
            .is_some()
}

async fn validate_agent_operation_membership(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    let actor_id = operation.context.sender.signing_principal_id().as_str();
    let record = state
        .agent_pairings()
        .agent(actor_id)
        .await
        .map_err(|_| "agent_membership_lookup_failed")?;
    let Some(record) = record else {
        return Ok(());
    };
    // The Agent's own PCR genesis is a lifecycle bootstrap, not a
    // Realm-participation write. Its controller delegation, provision Event,
    // accountability grant and PCR binding have already been checked by the
    // closed envelope gate. Requiring an effective Realm membership here
    // would create a cycle: the Agent PCR must exist before its first
    // controller-generation membership binding can be projected.
    if operation.realm_id.as_str() == record.principal_control_realm_id
        && kinds::canonical_kind_for_operation(operation)
            == Some(arkret_wire::EventKind::RealmCreate)
    {
        return Ok(());
    }
    let result = if operation.realm_id.as_str() == record.principal_control_realm_id {
        crate::routing::identity::agent_pcr::validate_agent_controller_binding(
            state,
            &record,
            operation.created_at,
        )
        .await
    } else {
        crate::routing::identity::agent_pcr::validate_effective_agent_realm_membership(
            state,
            &record,
            operation.realm_id.as_str(),
            operation.created_at,
        )
        .await
    };
    result.map_err(|_| "agent_membership_inactive")
}

#[cfg(test)]
#[expect(
    clippy::items_after_test_module,
    reason = "focused policy tests stay adjacent to the public policy entry point"
)]
mod tests {
    use coland_storage_postgres::Db;

    use super::*;

    fn circle_create_with_payload(payload: Value) -> Operation {
        arkret_event_draft::test_support::raw_projected_operation(
            arkret_identifiers::OperationId::new(
                "ak:operation:01964137-0000-7000-8000-000000000040",
            )
            .unwrap(),
            arkret_identifiers::RealmId::new(
                "ak:realm:AQcksDTzb8Sxrn1BUVVlHtH4vBOy99RKUB4EwOq_413b",
            )
            .unwrap(),
            arkret_wire::EventKind::CircleCreate.as_str(),
            payload,
        )
    }

    #[test]
    fn policy_sender_uses_typed_envelope_sender_for_full_object_create_payload() {
        let op = circle_create_with_payload(serde_json::json!({
            "object": { "created_by": "did:web:example.com:users:alice" },
        }));
        assert_eq!(policy_operation_sender(&op), Some(&op.context.sender));
    }

    #[test]
    fn trusted_sidecar_create_rejects_service_actor() {
        let mut operation = arkret_event_draft::test_support::raw_projected_operation(
            arkret_identifiers::OperationId::new(
                "ak:operation:01964137-0000-7000-8000-000000000041",
            )
            .unwrap(),
            arkret_identifiers::RealmId::new(
                "ak:realm:AQcksDTzb8Sxrn1BUVVlHtH4vBOy99RKUB4EwOq_413b",
            )
            .unwrap(),
            arkret_wire::EventKind::SidecarCreate.as_str(),
            serde_json::json!({
                "encryption_profile": "mls_rfc9420",
                "event_id": "ak:event:AXo80MUBfEyZDoQCP8SJ2j6fRF_ZCzJnhiTSomOJGLCB",
                "sender": "ak:did_core:web:fixture.example"
            }),
        );
        let controller = operation
            .context
            .sender
            .signing_principal_id()
            .as_str()
            .to_owned();
        operation.context.sender = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new(controller.clone()).unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:service.fixture").unwrap(),
        ));
        assert_eq!(
            validate_trusted_sidecar_create_operation(&operation, &controller),
            Ok(())
        );

        operation.context.sender =
            arkret_wire::ActorId::service(arkret_wire::DidCoreId::new(controller.clone()).unwrap());
        assert_eq!(
            validate_trusted_sidecar_create_operation(&operation, &controller),
            Err("sidecar_create_denied")
        );
    }

    #[tokio::test]
    async fn ordinary_circle_create_cannot_claim_reserved_sidecar_shape() {
        let actor = "did:web:example.com:users:alice";
        let operation = circle_create_with_payload(serde_json::json!({
            "object": {
                "id": "ak:circle:AbLN8Zik9Z7ZJiPG_sNwMk4iV0JGKAnWmyOB0FKWVGCV",
                "schema": "ak.schema.circle.v1",
                "realm_id": "ak:realm:AQcksDTzb8Sxrn1BUVVlHtH4vBOy99RKUB4EwOq_413b",
                "title": "Agent Sidecar Scope",
                "display": {
                    "short_name": "SC-ABCDEFGHIJKLMNOP",
                    "color_token": "slate",
                    "symbol": { "glyph": "lock" }
                },
                "directory_visibility": "members",
                "join_rule": "invite",
                "history_access": "since_join",
                "content_encryption_floor": "e2ee_required",
                "metadata_encryption_floor": "e2ee_required",
                "encryption_profile": "mls_rfc9420",
                "state": "active",
                "created_by": actor,
                "created_at": "2026-07-20T00:00:00.000Z"
            }
        }));
        let state = AppState::new(crate::config::AppConfig::test_default(), Db { pool: None });
        assert_eq!(
            validate_circle_create_policy(&state, &operation).await,
            Err("sidecar_create_denied")
        );
    }
}

async fn validate_agent_grant_ceiling(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    if kinds::canonical_kind_for_operation(operation)
        != Some(arkret_wire::EventKind::CapabilityGrant)
    {
        return Ok(());
    }
    let payload: arkret_models_collaboration::events_payloads::CapabilityGrantPayload =
        serde_json::from_value(operation.payload.clone())
            .map_err(|_| "agent_grant_exceeds_requested_scope")?;
    let grant = &payload.grant;
    let arkret_models_collaboration::governance::grant_constraint::CapabilitySubject::Actor(
        subject,
    ) = &grant.subject
    else {
        return Ok(());
    };
    let record = crate::routing::identity::agent_pcr::agent_record_for_actor(state, subject)
        .await
        .map_err(|_| "agent_requested_scope_commitment_invalid")?;
    let Some(record) = record else {
        return Ok(());
    };
    crate::routing::identity::agent_pcr::validate_effective_agent_realm_membership(
        state,
        &record,
        operation.realm_id.as_str(),
        chrono::Utc::now(),
    )
    .await
    .map_err(|_| "agent_requested_scope_commitment_invalid")?;
    if crate::routing::identity::agents::agent_grant_within_requested_scope(
        &record,
        &grant.actions,
        &grant.resources,
        &grant.constraints,
    ) {
        Ok(())
    } else {
        Err("agent_grant_exceeds_requested_scope")
    }
}
