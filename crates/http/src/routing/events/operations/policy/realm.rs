use super::*;

pub(super) fn validate_realm_lifecycle_write_gate(
    state: &AppState,
    operation: &Operation,
    operations: &[Operation],
) -> Result<(), &'static str> {
    let kind = kinds::canonical_kind(operation);
    let realm_id = operation.realm_id.as_str();
    let projection = state.projections().snapshot();
    if projection.realm_is_in_terminal_state(realm_id)
        && !arkret_wire::events::kinds::is_audit_kind(&kind)
    {
        return Err("failed_precondition");
    }
    // A new Realm's closed founding batch has no durable projection yet.
    // Its genesis and registered follow-ups use initial facets, while actual
    // archive/freeze cells are always enforced. Batch validation still owns
    // the complete founding shape and authority checks.
    let is_registered_bootstrap_kind = arkret_schema::REALM_BOOTSTRAP_PROFILES
        .iter()
        .flat_map(|profile| profile.ordered_slots)
        .any(|slot| slot.event_kind == kind.as_str());
    let staged_creation = is_registered_bootstrap_kind
        && operations.iter().any(|candidate| {
            kinds::canonical_kind_for_operation(candidate)
                == Some(arkret_wire::EventKind::RealmCreate)
                && candidate.realm_id == operation.realm_id
        });
    let blocked = projection.realm_is_archived(realm_id)
        || projection.realm_is_frozen(realm_id)
        || (!staged_creation && projection.realm_ordinary_writes_blocked(realm_id));
    if blocked && !arkret_wire::events::kinds::realm_write_gate_exempt(&kind, &operation.payload) {
        return Err(arkret_wire::ErrorCode::REALM_FROZEN);
    }
    Ok(())
}

/// Policy-layer acting-principal accessor.
///
/// The executing principal is an accepted envelope fact. Payload `actor_id`
/// fields name targets and must never participate in authorization.
pub(super) fn policy_operation_sender(operation: &Operation) -> Option<&arkret_wire::ActorId> {
    Some(&operation.context.sender)
}

pub(super) fn policy_realm_member_joined(
    state: &AppState,
    realm_id: &str,
    actor: &arkret_wire::ActorId,
) -> bool {
    {
        let projection = state.projections().snapshot();
        {
            projection
                .member(realm_id, &actor.to_string())
                .map(|membership| membership.state == "join")
        }
    }
    .unwrap_or(false)
}
