use super::*;

pub(super) fn validate_pin_scope_safety(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    if !kinds::canonical_kind_for_operation(operation)
        .is_some_and(|kind| arkret_wire::events::kinds::is_pin_kind(&kind))
    {
        return Ok(());
    }
    let projection = state.projections().snapshot();
    projection.check_pin_scope_safety(operation)
}

/// `zh/models/actor.md` section 3.3.1 preflight for a profile Event on any
/// admission path that reaches the shared policy gates: every
/// `accountable_principal_ids` entry of the resulting profile needs a
/// committed `identity_accountability` record -- from an independent grant or
/// an Agent provision projection -- that is active at the Station's Commit
/// time coordinate. The Actor Profile PCR unit repeats the decision at the
/// exact accepting Commit under the PCR lock; this gate only refuses early.
pub(super) async fn validate_accountability_profile_policy(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    let kind = kinds::canonical_kind_for_operation(operation);
    let (subject, issuers) = match kind {
        Some(arkret_wire::EventKind::ProfileCreate) => {
            let create: arkret_models_collaboration::events_payloads::ActorProfileCreatePayload =
                serde_json::from_value(operation.payload.clone())
                    .map_err(|_| arkret_wire::ErrorCode::SCHEMA_VIOLATION)?;
            (
                create
                    .object
                    .principal_id
                    .ok_or(arkret_wire::ErrorCode::SCHEMA_VIOLATION)?,
                create
                    .object
                    .accountable_principal_ids
                    .ok_or(arkret_wire::ErrorCode::SCHEMA_VIOLATION)?,
            )
        }
        Some(arkret_wire::EventKind::ProfileUpdate) => {
            let update: arkret_models_collaboration::events_payloads::ActorProfileUpdatePayload =
                serde_json::from_value(operation.payload.clone())
                    .map_err(|_| arkret_wire::ErrorCode::SCHEMA_VIOLATION)?;
            let subject = operation.context.sender.signing_principal_id().clone();
            let issuers = match update
                .patch
                .iter()
                .find(|(path, _)| path.as_str() == "accountable_principal_ids")
            {
                Some((_, op)) => match op {
                    arkret_wire::PatchOp::DirectValue(value)
                    | arkret_wire::PatchOp::Explicit {
                        op: arkret_wire::PatchOpKind::Set,
                        value: Some(value),
                    } => serde_json::from_value::<Vec<arkret_wire::DidCoreId>>(value.clone())
                        .map_err(|_| arkret_wire::ErrorCode::SCHEMA_VIOLATION)?,
                    _ => Vec::new(),
                },
                None => {
                    let account = operation
                        .context
                        .sender
                        .as_account_id()
                        .ok_or(arkret_wire::ErrorCode::SCHEMA_VIOLATION)?;
                    state
                        .persistence()
                        .current_actor_profile(account)
                        .await
                        .map_err(|_| arkret_wire::ErrorCode::TEMPORARILY_UNAVAILABLE)?
                        .and_then(|record| record.profile.accountable_principal_ids)
                        .unwrap_or_default()
                }
            };
            (subject, issuers)
        }
        _ => return Ok(()),
    };
    let at = chrono::Utc::now();
    for issuer in &issuers {
        let verified = state
            .persistence()
            .accountability_verified_at(issuer, &subject, at)
            .await
            .map_err(|_| arkret_wire::ErrorCode::TEMPORARILY_UNAVAILABLE)?;
        if !verified {
            return Err(arkret_wire::ReasonCode::ACCOUNTABILITY_GRANT_MISSING);
        }
    }
    Ok(())
}
