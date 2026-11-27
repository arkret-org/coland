use super::*;

/// strand-and-message.md §9.8.2 — a reaction MUST target an object inside its
/// own effective scope. coland's effective scope is the Realm, so a
/// `ak.reaction.*` whose `target_ref` resolves to a Message in a different
/// Realm is rejected with active `failed_precondition`. The target-kind gate
/// already ran in `validate_operation_semantics`; an unknown /
/// not-yet-observed target is left to the reducer's dependency handling.
pub(super) fn validate_reaction_scope_policy(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    let Some(kind) = kinds::canonical_kind_for_operation(operation) else {
        return Ok(());
    };
    if !matches!(
        &kind,
        arkret_wire::EventKind::ReactionAdd | arkret_wire::EventKind::ReactionRemove
    ) {
        return Ok(());
    }
    let target = reaction_target_ref(&kind, operation);
    let Some(target) = target else {
        return Ok(());
    };
    let target_realm = {
        let projection = state.projections().snapshot();
        projection.message_realm(&target)
    };
    let Some(target_realm) = target_realm else {
        // Target not yet observed — reducer keeps the reaction pending.
        return Ok(());
    };
    if realm_ids_match(operation.realm_id.as_str(), &target_realm) {
        Ok(())
    } else {
        Err("reaction_outside_scope")
    }
}

fn reaction_target_ref(kind: &arkret_wire::EventKind, operation: &Operation) -> Option<String> {
    match kind {
        arkret_wire::EventKind::ReactionAdd => operation
            .typed_payload::<arkret_wire::event_spec::ReactionAdd>()
            .ok()
            .map(|payload| payload.target_ref.as_str().to_owned()),
        arkret_wire::EventKind::ReactionRemove => operation
            .typed_payload::<arkret_wire::event_spec::ReactionRemove>()
            .ok()
            .map(|payload| payload.target_ref.as_str().to_owned()),
        _ => None,
    }
}

/// applet-integration.md §4 / §4b — installing an Applet into a Realm is gated
/// by the machine-readable `ak.realm.admin` capability: the actor submitting a
/// `ak.applet.registration` MUST hold `ak.realm.admin` over the Realm in the
/// durable authorization cut (a covering grant or the effective
/// `ak.realm.owner` aggregate), else reject `applet_registration_unauthorized`.
///
/// The dedicated install aggregate (`POST /_arkret/self/applets/install`)
/// validates and submits the caller-signed registration Event through the same
/// admission path as a raw `/_arkret/self/events` submission. Both paths
/// therefore apply this capability gate without an internal bypass.
pub(super) async fn validate_applet_registration_authz(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    if kinds::canonical_kind_for_operation(operation)
        != Some(arkret_wire::EventKind::AppletRegistration)
    {
        return Ok(());
    }
    let actor = &operation.context.sender;
    let realm_id = operation.realm_id.as_str();
    if crate::authz::actor_may(
        state,
        realm_id,
        actor,
        &[arkret_wire::CapabilityActionId::REALM_ADMIN],
        realm_id,
        operation.created_at,
    )
    .await?
    {
        return Ok(());
    }
    Err("applet_registration_unauthorized")
}

/// Control-stream events derive their exact owning account from the verified envelope actor.
pub(super) const PRINCIPAL_CONTROL_EVENT_KINDS: &[&str] = &[
    arkret_wire::event_kind_str::DEVICE_AUTHORIZE,
    arkret_wire::event_kind_str::DEVICE_REVOKE,
];

/// Phase 2 — principal control realm isolation (key-management.md §4.1). A
/// control-stream event MUST land on its principal's accepted control Realm; it cannot be
/// written into a collaboration realm or another principal's control realm.
pub(in crate::routing::events::operations) fn validate_principal_control_realm_binding(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    let kind = kinds::canonical_kind(operation);
    if !PRINCIPAL_CONTROL_EVENT_KINDS.contains(&kind.as_str()) {
        return Ok(());
    }
    let snapshot = state.projections().snapshot();
    if operation.context.sender.as_account_id().is_some()
        && snapshot.realm_is_principal_control_for_actor(
            operation.realm_id.as_str(),
            &operation.context.sender.to_string(),
        )
    {
        Ok(())
    } else {
        // A principal-control binding failure remains a hard deny. Its
        // former specialized reason is reserved in the current registry.
        Err("principal_control_realm_mismatch")
    }
}

pub(in crate::routing::events::operations) async fn validate_agent_control_realm_binding(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    let kind = kinds::canonical_kind(operation);
    let explicit_agent_control = matches!(
        &kind,
        arkret_wire::EventKind::AgentKeyAuthorize
            | arkret_wire::EventKind::AgentKeyRevoke
            | arkret_wire::EventKind::SelfAgentPause
            | arkret_wire::EventKind::SelfAgentResume
            | arkret_wire::EventKind::SelfAgentDeactivate
    );
    let possible_agent_profile_or_genesis = matches!(
        &kind,
        arkret_wire::EventKind::RealmCreate
            | arkret_wire::EventKind::ProfileCreate
            | arkret_wire::EventKind::ProfileUpdate
    );
    if !explicit_agent_control && !possible_agent_profile_or_genesis {
        return Ok(());
    }
    let agent_actor = agent_control_actor(
        &operation.context.sender,
        &operation.payload,
        explicit_agent_control,
    )?;
    let record = crate::routing::identity::agent_pcr::agent_record_for_actor(state, &agent_actor)
        .await
        .map_err(|_| "agent_principal_binding_unavailable")?;
    let record = match record {
        Some(record) => record,
        None if possible_agent_profile_or_genesis => return Ok(()),
        None => return Err("agent_principal_binding_unavailable"),
    };
    let agent_id = agent_actor.signing_principal_id().as_str();
    let expected = &record.principal_control_realm_id;
    if !realm_ids_match(operation.realm_id.as_str(), expected) {
        return Err("principal_control_realm_mismatch");
    }
    if kind == arkret_wire::EventKind::RealmCreate.as_str() {
        let object = operation
            .payload
            .get("object")
            .ok_or("agent_pcr_genesis_object_missing")?;
        let controller_actor_id = operation
            .context
            .executed_by
            .as_ref()
            .ok_or("agent_pcr_genesis_controller_missing")?;
        let controller_account =
            crate::routing::identity::agent_pcr::agent_controller_account(state, &record)
                .await
                .map_err(|_| "agent_principal_binding_unavailable")?;
        if controller_actor_id != &arkret_wire::ActorId::account(controller_account) {
            return Err("agent_principal_binding_unavailable");
        }
        let initial_resolution =
            crate::routing::identity::agent_pcr::agent_initial_resolution_for_record(&record)
                .map_err(|_| "agent_initial_resolution_unavailable")?;
        crate::routing::identity::agent_pcr::validate_agent_pcr_genesis_object(
            object,
            agent_id,
            controller_actor_id.signing_principal_id().as_str(),
            expected,
            state.config().trust_domain.as_str(),
            &initial_resolution,
        )
        .map_err(|_| "principal_control_realm_profile_mismatch")?;
    }
    Ok(())
}

fn agent_control_actor(
    sender: &arkret_wire::ActorId,
    payload: &Value,
    explicit_agent_control: bool,
) -> Result<arkret_wire::ActorId, &'static str> {
    if explicit_agent_control {
        let principal = payload
            .get("agent_id")
            .and_then(Value::as_str)
            .ok_or("agent_control_event_missing_agent_id")?;
        if sender.signing_principal_id().as_str() != principal {
            return Err("agent_principal_binding_unavailable");
        }
        return Ok(sender.clone());
    }
    if let Some(actor) = payload
        .get("object")
        .and_then(|object| object.get("actor_id"))
    {
        return serde_json::from_value(actor.clone())
            .map_err(|_| "agent_principal_binding_unavailable");
    }
    Ok(sender.clone())
}

pub(crate) fn realm_ids_match(a: &str, b: &str) -> bool {
    a == b
}

#[cfg(test)]
mod agent_actor_tests {
    use super::*;

    #[test]
    fn genesis_profile_and_control_selectors_preserve_full_actor() {
        let principal = arkret_wire::DidCoreId::new("ak:did_core:web:agent.example").unwrap();
        let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            principal.clone(),
            arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ));
        assert_eq!(
            agent_control_actor(&actor, &serde_json::json!({"object":{}}), false).unwrap(),
            actor
        );
        assert_eq!(
            agent_control_actor(
                &actor,
                &serde_json::json!({"object":{"actor_id":actor}}),
                false
            )
            .unwrap(),
            actor
        );
        assert_eq!(
            agent_control_actor(&actor, &serde_json::json!({"agent_id":principal}), true).unwrap(),
            actor
        );
        assert!(
            agent_control_actor(
                &actor,
                &serde_json::json!({"object":{"actor_id":principal}}),
                false
            )
            .is_err()
        );
        assert!(
            agent_control_actor(
                &actor,
                &serde_json::json!({"agent_id":"ak:did_core:web:other.example"}),
                true
            )
            .is_err()
        );
    }
}
