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

/// circle.md §8 — resolve the Circle a write operation lands content into, if
/// any. Returns the `ak:circle:…` id when the operation introduces, mutates, or
/// tombstones a Circle-scoped object, else `None` (Realm-default scope).
/// Object-carrying creates declare scope inline (`payload.object` /
/// `payload.relation` / top-level `scope_circle_id`); updates and lifecycle
/// writes derive scope from the projected target. `ak.message.create` derives
/// scope from the projected Strand — a Message never self-declares its scope.
pub(super) fn operation_target_scope_circle_id(
    projection: &coland_domain::reducer::ProjectionState,
    operation: &Operation,
) -> Option<String> {
    let top_level_scope = || -> Option<String> {
        operation
            .payload
            .get("scope_circle_id")
            .and_then(Value::as_str)
            .filter(|value| value.starts_with("ak:circle:"))
            .map(ToOwned::to_owned)
    };
    let inline_scope = |field: &str| -> Option<String> {
        operation
            .payload
            .get(field)
            .and_then(Value::as_object)
            .and_then(|object| object.get("scope_circle_id"))
            .and_then(Value::as_str)
            .filter(|value| value.starts_with("ak:circle:"))
            .map(ToOwned::to_owned)
    };
    let relation_scope = |field: &str| -> Option<String> {
        operation
            .payload
            .get(field)
            .and_then(Value::as_str)
            .and_then(|relation_id| projection.relation_scope_circle_id(relation_id))
    };
    let strand_scope = |field: &str| -> Option<String> {
        operation
            .payload
            .get(field)
            .and_then(Value::as_str)
            .and_then(|strand_id| projection.strand_scope_circle_id(strand_id))
    };
    let morph_scope = |field: &str| -> Option<String> {
        operation
            .payload
            .get(field)
            .and_then(Value::as_str)
            .and_then(|morph_id| projection.morph_scope_circle_id(morph_id))
    };
    let kind = kinds::canonical_kind_for_operation(operation)?;
    match &kind {
        arkret_wire::EventKind::StrandCreate
        | arkret_wire::EventKind::MorphCreate
        | arkret_wire::EventKind::SpaceCreate => inline_scope("object"),
        arkret_wire::EventKind::RelationCreate => inline_scope("relation")
            .or_else(|| inline_scope("object"))
            .or_else(top_level_scope),
        // `relation_update_payload` names its target with either `relation_id`
        // or `target_ref`; `relation_tombstone_payload` allows only
        // `relation_id`. Both carriers resolve to the same Relation, so the
        // Circle-scope check MUST NOT be bypassable by picking the other one.
        arkret_wire::EventKind::RelationUpdate | arkret_wire::EventKind::RelationTombstone => {
            relation_scope("relation_id").or_else(|| relation_scope("target_ref"))
        }
        arkret_wire::EventKind::MessageCreate => strand_scope("strand_id"),
        arkret_wire::EventKind::MessageRevise => {
            let message_id = operation.payload.get("message_id")?.as_str()?;
            let (_, _, strand_id) = projection.message_origin(message_id)?;
            projection.strand_scope_circle_id(&strand_id)
        }
        arkret_wire::EventKind::StrandUpdate => strand_scope("target_ref"),
        arkret_wire::EventKind::MorphUpdate
        | arkret_wire::EventKind::MorphArchive
        | arkret_wire::EventKind::MorphRestore => morph_scope("target_ref"),
        arkret_wire::EventKind::StrandArchive
        | arkret_wire::EventKind::StrandRestore
        | arkret_wire::EventKind::StrandMove
        | arkret_wire::EventKind::StrandReorder => {
            strand_scope("target_ref").or_else(|| strand_scope("strand_id"))
        }
        arkret_wire::EventKind::ReactionAdd | arkret_wire::EventKind::ReactionRemove => {
            // A reaction's scope is the target Message's Strand scope — reacting
            // into a Circle is a write into that scope and requires Circle
            // membership just like authoring there. Unknown target (not yet
            // observed) → None: the reducer keeps the reaction pending and a
            // non-member cannot name a Circle message id it never received.
            let target = reaction_target_ref(&kind, operation)?;
            let (_, _, thread_id) = projection.message_origin(&target)?;
            projection.strand_scope_circle_id(&thread_id)
        }
        _ => None,
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

/// circle.md §8 — the membership half of the two-layer authorization AND for
/// Circle-scoped writes:
///
/// ```text
/// authorized ⇔ capability_grant(actor, action)
///              ∧ (effective_scope.kind == "realm" ∨ actor ∈ Circle.members)
/// ```
///
/// Holding a Realm-wide capability does **not** authorize writing into a Circle:
/// the author MUST also be a member of that Circle. Without this gate any holder
/// of a Realm-wide grant — notably an Applet bot / Ghost Actor
/// (`extensions/applet-integration.md` §3.4.1, which requires a deployment to be
/// able to keep Realm-level automation out of Circles) — could inject Strands /
/// Morphs / Messages into a Circle it never joined. The Sync-side scope filter
/// (`circle_scope_visible_to_actor` in delivery) only hides reads from
/// non-members; it does not stop the write, so membership MUST be enforced at
/// admission too.
///
/// Coverage: object-carrying creates (Strand / Morph / Space / Relation),
/// relation update/tombstone, `ak.message.create`, Strand update / lifecycle,
/// Morph update / lifecycle, and `ak.reaction.add` / `ak.reaction.remove`
/// (scope derived from the target Message's Strand).
///
/// Membership is evaluated against the current Circle projection (coland's
/// convergence frontier), matching the delivery-side check. Peer / service-
/// originated federation operations without a typed actor stay accepted
/// (convergence / backfill), mirroring the ban / moderation gates; direct client
/// and Applet submits always carry an actor and are gated.
pub(super) fn validate_circle_scope_membership(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    let projection = state.projections().snapshot();
    let Some(scope_circle_id) = operation_target_scope_circle_id(&projection, operation) else {
        return Ok(());
    };
    projection.validate_scope_circle_id(&scope_circle_id, operation.realm_id.as_str())?;
    let actor = &operation.context.sender;
    if projection.circle_scope_visible_to_actor(&scope_circle_id, &actor.to_string()) {
        Ok(())
    } else {
        Err("circle_scope_membership_required")
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
