use arkret_models_collaboration::governance::agent_participation::ParticipationBits;

use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AgentParticipationMode {
    ReplyMessage,
    ReactionAdd,
    ReactionRemove,
    ActOnBehalf,
}

impl AgentParticipationMode {
    fn rejection_reason(self) -> &'static str {
        match self {
            Self::ReplyMessage => "agent_reply_not_permitted",
            Self::ReactionAdd => "agent_reaction_add_not_permitted",
            Self::ReactionRemove => "agent_reaction_remove_not_permitted",
            Self::ActOnBehalf => "agent_act_on_behalf_not_permitted",
        }
    }
}

fn autonomous_participation_mode(
    operation: &Operation,
) -> Result<AgentParticipationMode, &'static str> {
    match agent_participation_action(operation) {
        Some(arkret_wire::EventKind::MessageCreate) => Ok(AgentParticipationMode::ReplyMessage),
        Some(arkret_wire::EventKind::ReactionAdd) => Ok(AgentParticipationMode::ReactionAdd),
        Some(arkret_wire::EventKind::ReactionRemove) => Ok(AgentParticipationMode::ReactionRemove),
        _ => Err("agent_participation_action_unknown"),
    }
}

fn ap_effective_for_mode(mode: AgentParticipationMode, effective: ParticipationBits) -> bool {
    match mode {
        AgentParticipationMode::ReplyMessage => effective.reply_message,
        AgentParticipationMode::ReactionAdd => effective.reaction_add,
        AgentParticipationMode::ReactionRemove => effective.reaction_remove,
        AgentParticipationMode::ActOnBehalf => effective.act_on_behalf,
    }
}

pub(super) async fn agent_exists(
    state: &AppState,
    principal_id: &str,
) -> Result<bool, &'static str> {
    state
        .agent_pairings()
        .agent(principal_id)
        .await
        .map(|record| record.is_some())
        .map_err(|_| "agent_principal_lookup_unavailable")
}

pub(super) async fn agent_lifecycle_rejection_reason(
    state: &AppState,
    agent_id: &str,
) -> Result<Option<&'static str>, &'static str> {
    let record_state = state
        .agent_pairings()
        .agent(agent_id)
        .await
        .map_err(|_| "agent_principal_lookup_unavailable")?
        .map(|record| record.state);
    match record_state {
        Some(arkret_models_collaboration::agent_operations::AgentLifecycleState::Paused) => {
            return Ok(Some("agent_paused"));
        }
        Some(arkret_models_collaboration::agent_operations::AgentLifecycleState::Deactivated) => {
            return Ok(Some("agent_deactivated"));
        }
        _ => {}
    }

    let projected = {
        let projection = state.projections().snapshot();
        let agent_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new(agent_id)
                .map_err(|_| "agent_principal_lookup_unavailable")?,
            state.service_core_id(),
        ));
        projection
            .agent_lifecycles
            .get(&agent_actor.to_string())
            .copied()
    };
    Ok(match projected {
        Some(arkret_models_collaboration::agent_operations::AgentLifecycleState::Paused) => {
            Some("agent_paused")
        }
        Some(arkret_models_collaboration::agent_operations::AgentLifecycleState::Deactivated) => {
            Some("agent_deactivated")
        }
        _ => None,
    })
}

pub(super) fn agent_participation_action(operation: &Operation) -> Option<arkret_wire::EventKind> {
    kinds::canonical_kind_for_operation(operation)
}

pub(super) async fn validate_agent_act_on_behalf_authorization_ref(
    state: &AppState,
    operation: &Operation,
    agent_id: &str,
) -> Result<String, &'static str> {
    let authorization_ref = operation
        .payload
        .get("authorization_ref")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or("agent_act_on_behalf_authorization_ref_missing")?;
    if !authorization_ref.starts_with("ak:grant:") {
        return Err("agent_act_on_behalf_authorization_ref_invalid");
    }
    let Some(action) = agent_participation_action(operation) else {
        return Err("agent_act_on_behalf_authorization_action_unsupported");
    };
    agent_grant_covers_operation(
        state,
        operation,
        agent_id,
        authorization_ref,
        action.as_str(),
        AgentGrantRefReasons {
            actor_invalid: "agent_act_on_behalf_actor_id_invalid",
            inactive: "agent_act_on_behalf_authorization_ref_inactive",
            scope: "agent_act_on_behalf_authorization_ref_scope",
        },
    )
    .await?;
    Ok(authorization_ref.to_owned())
}

/// The refusal reasons of one Agent grant-reference check.
struct AgentGrantRefReasons {
    actor_invalid: &'static str,
    inactive: &'static str,
    scope: &'static str,
}

/// `authorization_ref` names a grant that is effective for the Agent Account
/// in the operation's Realm at the durable authorization cut, names `action`,
/// and has a resource covering the operation's target.
async fn agent_grant_covers_operation(
    state: &AppState,
    operation: &Operation,
    agent_id: &str,
    authorization_ref: &str,
    action: &str,
    reasons: AgentGrantRefReasons,
) -> Result<(), &'static str> {
    let agent = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new(agent_id.to_owned()).map_err(|_| reasons.actor_invalid)?,
        operation.context.sender.route_service_id().clone(),
    ));
    let authorization = crate::authz::actor_realm_authorization(
        state,
        &operation.realm_id,
        &agent,
        operation.created_at,
    )
    .await
    .map_err(|error| {
        tracing::error!(?error, realm_id = %operation.realm_id, "agent grant read failed");
        arkret_wire::ErrorCode::INTERNAL_ERROR
    })?;
    let grant = authorization
        .grants
        .iter()
        .find(|effective| effective.grant.id.as_str() == authorization_ref)
        .ok_or(reasons.inactive)?;
    let resource = operation
        .object_id
        .as_deref()
        .unwrap_or_else(|| operation.realm_id.as_str());
    let target =
        crate::authz::resource_selector(&operation.realm_id, resource).ok_or(reasons.scope)?;
    if !coland_storage::grant_names_target(&grant.grant, &[action], &target) {
        return Err(reasons.scope);
    }
    Ok(())
}

/// Authorize one act-on-behalf Operation by its controller confirmation.
///
/// `covering_committed_at` is the signed `committed_at` of the RealmCommit
/// that covers this Operation's Event. It is the only clock the approval
/// window is judged against (`constraint-schema.md` §9.2.6): an Event
/// covered after the approval's `expires_at` lacks a valid confirmation and
/// fails as `approval_required`.
pub(crate) async fn validate_agent_act_on_behalf_approval(
    state: &AppState,
    operation: &Operation,
    agent_id: &str,
    covering_committed_at: chrono::DateTime<chrono::Utc>,
) -> Result<(), &'static str> {
    let request_id = operation
        .payload
        .get("request_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or("agent_act_on_behalf_approval_request_id_missing")?;
    let approval_nonce = operation
        .payload
        .get("approval_nonce")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or("agent_act_on_behalf_approval_nonce_missing")?;
    let action = agent_participation_action(operation)
        .ok_or("agent_act_on_behalf_approval_action_unsupported")?;
    let approval_event_id = state
        .projections()
        .agent_action_confirmation(&operation.context.event_id)
        .ok_or("dependency_missing")?;
    let confirmed = require_committed_agent_action_approval(
        state,
        operation,
        &approval_event_id,
        ConfirmationClaim {
            agent_id,
            request_id,
            approval_nonce,
            action: action.as_str(),
        },
    )
    .await?;
    if !confirmed.admits_commit_at(covering_committed_at) {
        return Err(arkret_wire::ReasonCode::APPROVAL_REQUIRED);
    }
    Ok(())
}

/// What the act-on-behalf Operation claims its confirmation approved.
struct ConfirmationClaim<'a> {
    agent_id: &'a str,
    request_id: &'a str,
    approval_nonce: &'a str,
    action: &'a str,
}

/// Publication is authorized only by the exact `ak.agent.action_approve`
/// Event the governing Station committed in the target Realm: that
/// confirmation consumed the controller's nonce for this complete
/// `approved_event_id` and nothing else (`constraint-schema.md` §9.2.6;
/// `event-payload.schema.json` `agent_action_approve_payload`). The
/// controller-private request it confirms is never read here; every bound
/// field comes from the committed Event itself, and anything short of it is a
/// missing dependency, so the gate fails closed.
async fn require_committed_agent_action_approval(
    state: &AppState,
    operation: &Operation,
    approval_event_id: &arkret_wire::EventId,
    claim: ConfirmationClaim<'_>,
) -> Result<
    arkret_models_collaboration::events_payloads::agent::AgentActionApprovePayload,
    &'static str,
> {
    let committed = state
        .authority_commits()
        .committed_event(approval_event_id)
        .await
        .map_err(|_| "dependency_missing")?
        .ok_or("dependency_missing")?;
    let event = &committed.event;
    let controller = event.actor_id.as_account_id();
    if &event.event_id != approval_event_id
        || &committed.commit.event_ref != approval_event_id
        || event.kind != arkret_wire::EventKind::AgentActionApprove
        || event.realm_id != operation.realm_id
        || committed.commit.realm_id != operation.realm_id
        || event.executed_by.is_some()
        || controller.is_none()
        || operation.context.sender.as_account_id() != controller
    {
        return Err("dependency_missing");
    }
    let payload = serde_json::to_value(&event.payload).map_err(|_| "dependency_missing")?;
    let confirmed: arkret_models_collaboration::events_payloads::agent::AgentActionApprovePayload =
        serde_json::from_value(payload.clone()).map_err(|_| "dependency_missing")?;
    let request_matches = confirmed
        .request_id
        .as_deref()
        .or(confirmed.draft_id.as_deref())
        == Some(claim.request_id);
    if !request_matches
        || confirmed.approval_nonce != claim.approval_nonce
        || confirmed.approved_event_id != operation.context.event_id
    {
        return Err("dependency_missing");
    }
    if confirmed.agent_id.as_str() != claim.agent_id {
        return Err("agent_act_on_behalf_approval_agent_mismatch");
    }
    if confirmed.proposed_action != claim.action {
        return Err("agent_act_on_behalf_approval_action_mismatch");
    }
    if !payload
        .get("target")
        .is_some_and(|target| agent_action_target_matches(target, operation))
    {
        return Err("agent_act_on_behalf_approval_target_mismatch");
    }
    Ok(confirmed)
}

fn agent_action_target_matches(target: &Value, operation: &Operation) -> bool {
    match target.get("kind").and_then(Value::as_str) {
        Some("realm") => target
            .get("realm_id")
            .and_then(Value::as_str)
            .is_some_and(|realm_id| realm_id == operation.realm_id.as_str()),
        Some("strand") => {
            let Some(target_ref) = target.get("object_ref").and_then(Value::as_str) else {
                return false;
            };
            operation
                .payload
                .get("strand_id")
                .and_then(Value::as_str)
                .is_some_and(|strand_id| strand_id == target_ref)
        }
        Some("message") | Some("object") => {
            let Some(target_ref) = target.get("object_ref").and_then(Value::as_str) else {
                return false;
            };
            operation.object_id.as_deref() == Some(target_ref)
                || operation
                    .payload
                    .get("message_id")
                    .and_then(Value::as_str)
                    .is_some_and(|message_id| message_id == target_ref)
        }
        _ => false,
    }
}

pub(super) fn operation_agent_context(operation: &Operation) -> Option<&Value> {
    operation
        .payload
        .get("agent_context")
        .or_else(|| {
            operation
                .payload
                .get("provenance")
                .and_then(|provenance| provenance.get("agent_context"))
        })
        .filter(|value| !value.is_null())
}

pub(super) fn agent_context_string<'a>(
    context: &'a Value,
    field: &str,
    missing_reason: &'static str,
) -> Result<&'a str, &'static str> {
    let object = context.as_object().ok_or("agent_context_invalid")?;
    object
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(missing_reason)
}

pub(super) fn agent_context_agent_id(operation: &Operation) -> Option<&str> {
    operation_agent_context(operation).and_then(|context| {
        context
            .as_object()
            .and_then(|object| object.get("agent_id"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
    })
}

pub(super) fn operation_agent_provenance(operation: &Operation) -> Option<&Value> {
    operation
        .payload
        .get("provenance")
        .or_else(|| operation.payload.get("agent_provenance"))
        .filter(|value| value.is_object())
}

pub(super) fn operation_provenance_agent_id(operation: &Operation) -> Option<&str> {
    operation_agent_provenance(operation).and_then(|provenance| {
        provenance
            .get("agent_id")
            .or_else(|| provenance.get("executed_by"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
    })
}

pub(super) fn operation_executed_by(operation: &Operation) -> Option<&str> {
    operation
        .context
        .executed_by
        .as_ref()
        .map(|actor| actor.signing_principal_id().as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .or_else(|| {
            operation_agent_provenance(operation).and_then(|provenance| {
                provenance
                    .get("executed_by")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
            })
        })
}

pub(super) fn operation_provenance_marks_agent(operation: &Operation) -> bool {
    let Some(provenance) = operation_agent_provenance(operation) else {
        return false;
    };
    provenance
        .get("kind")
        .and_then(Value::as_str)
        .is_some_and(|value| value == "agent")
        || operation_provenance_agent_id(operation).is_some()
}

async fn operation_agent_write_context(
    state: &AppState,
    operation: &Operation,
) -> Result<Option<(String, AgentParticipationMode)>, &'static str> {
    let authorization_ref = operation.context.authorization_ref.as_deref();
    if let (Some(executed_by), Some(authorization_ref)) =
        (operation.context.executed_by.as_ref(), authorization_ref)
    {
        use crate::routing::identity::agent_pcr::{
            agent_controller_account, agent_record_for_actor,
        };
        if let Some(record) = agent_record_for_actor(state, &operation.context.sender)
            .await
            .map_err(|_| "agent_principal_lookup_unavailable")?
        {
            let controller_account = agent_controller_account(state, &record)
                .await
                .map_err(|_| "agent_principal_lookup_unavailable")?;
            if executed_by == &arkret_wire::ActorId::account(controller_account)
                && record.principal_control_realm_id == operation.realm_id.as_str()
                && record.controller_authorization_ref.as_str() == authorization_ref
            {
                return Ok(None);
            }
        }
    }
    if let Some(executed_by) = operation_executed_by(operation)
        && (agent_context_agent_id(operation) == Some(executed_by)
            || operation_provenance_marks_agent(operation)
            || agent_exists(state, executed_by).await?)
    {
        return Ok(Some((
            executed_by.to_owned(),
            AgentParticipationMode::ActOnBehalf,
        )));
    }
    if let Some(agent_id) = agent_context_agent_id(operation) {
        let mode = if operation_executed_by(operation).is_some() {
            AgentParticipationMode::ActOnBehalf
        } else {
            autonomous_participation_mode(operation)?
        };
        return Ok(Some((agent_id.to_owned(), mode)));
    }
    if operation_provenance_marks_agent(operation)
        && let Some(agent_id) = operation_provenance_agent_id(operation)
            .map(ToOwned::to_owned)
            .or_else(|| Some(operation.context.sender.to_string()))
    {
        let mode = if operation_executed_by(operation).is_some() {
            AgentParticipationMode::ActOnBehalf
        } else {
            autonomous_participation_mode(operation)?
        };
        return Ok(Some((agent_id, mode)));
    }
    if let Some(sender) = policy_operation_sender(operation)
        && agent_exists(state, sender.signing_principal_id().as_str()).await?
    {
        return Ok(Some((
            sender.signing_principal_id().to_string(),
            autonomous_participation_mode(operation)?,
        )));
    }
    Ok(None)
}

pub(super) async fn validate_agent_context_authorization_ref(
    state: &AppState,
    operation: &Operation,
    agent_id: &str,
    authorization_ref: &str,
) -> Result<(), &'static str> {
    // A two-principal Direct Conversation is itself an explicit invitation to
    // exchange messages. Bind reply authority to that canonical Realm/binding
    // instead of requiring a second capability grant that the materialization
    // protocol does not emit for the peer.
    if authorization_ref == operation.realm_id.as_str()
        && agent_participation_action(operation) == Some(arkret_wire::EventKind::MessageCreate)
    {
        let binding = super::governance::active_direct_conversation_binding_for_realm(
            state,
            operation.realm_id.as_str(),
        )
        .await?
        .ok_or("agent_context_authorization_ref_inactive")?;
        let strand_id = operation
            .payload
            .get("strand_id")
            .and_then(Value::as_str)
            .ok_or("agent_context_authorization_ref_scope")?;
        if binding
            .participants_unordered
            .iter()
            .any(|participant| participant == agent_id)
            && binding.main_strand_id == strand_id
        {
            return Ok(());
        }
        return Err("agent_context_authorization_ref_scope");
    }
    if !authorization_ref.starts_with("ak:grant:") {
        return Err("agent_context_authorization_ref_invalid");
    }
    let Some(action) = agent_participation_action(operation) else {
        return Err("agent_context_authorization_action_unsupported");
    };
    agent_grant_covers_operation(
        state,
        operation,
        agent_id,
        authorization_ref,
        action.as_str(),
        AgentGrantRefReasons {
            actor_invalid: "agent_context_actor_id_invalid",
            inactive: "agent_context_authorization_ref_inactive",
            scope: "agent_context_authorization_ref_scope",
        },
    )
    .await
}

pub(super) async fn validate_agent_context(
    state: &AppState,
    operation: &Operation,
    expected_agent_id: &str,
    envelope_authorization_ref: Option<&str>,
) -> Result<(), &'static str> {
    let context = operation_agent_context(operation).ok_or("agent_context_missing")?;
    let agent_id = agent_context_string(context, "agent_id", "agent_context_agent_id_missing")?;
    if agent_id != expected_agent_id {
        return Err("agent_context_agent_mismatch");
    }
    agent_context_string(
        context,
        "operator_or_controller",
        "agent_context_operator_or_controller_missing",
    )?;
    agent_context_string(
        context,
        "execution_purpose",
        "agent_context_execution_purpose_missing",
    )?;
    let context_authorization_ref = agent_context_string(
        context,
        "authorization_ref",
        "agent_context_authorization_ref_missing",
    )?;
    validate_agent_context_authorization_ref(state, operation, agent_id, context_authorization_ref)
        .await?;
    if let Some(envelope_authorization_ref) = envelope_authorization_ref
        && context_authorization_ref != envelope_authorization_ref
    {
        return Err("agent_context_authorization_ref_mismatch");
    }
    Ok(())
}

/// AKP-0016 §5.2 / AKP-0008 §4.10 + architecture §7 enforcement
/// (coland-native): every agent-originated Event carries auditable
/// `agent_context`. Reply-as-agent uses the `reply` bit; act-on-behalf uses
/// envelope-derived `executed_by`, requires a referenced active grant, and
/// uses the `act_on_behalf` bit. Non-agent actors fall through to standard
/// authz.
pub async fn validate_agent_reply_participation(
    state: &AppState,
    operations: &[Operation],
    covering_committed_at: chrono::DateTime<chrono::Utc>,
) -> Result<(), &'static str> {
    for operation in operations {
        let Some((agent_id, mode)) = operation_agent_write_context(state, operation).await? else {
            continue;
        };
        if let Some(reason) = agent_lifecycle_rejection_reason(state, &agent_id).await? {
            return Err(reason);
        }
        let authorization_ref = if mode == AgentParticipationMode::ActOnBehalf {
            Some(validate_agent_act_on_behalf_authorization_ref(state, operation, &agent_id).await?)
        } else {
            None
        };
        validate_agent_context(state, operation, &agent_id, authorization_ref.as_deref()).await?;
        let strand_id = operation.payload.get("strand_id").and_then(Value::as_str);
        let Some(scope_keys) = crate::routing::agent_participation::scope_keys_for_message(
            state,
            operation.realm_id.as_str(),
            strand_id,
        ) else {
            // The message's Strand is not projected, so its participation
            // policy layer cannot be resolved; fail closed as an unresolved
            // ceiling rather than a plain not-permitted bit.
            return Err(arkret_wire::ReasonCode::AGENT_PARTICIPATION_CEILING_UNRESOLVED);
        };
        let Some(resolved) =
            crate::routing::agent_participation::resolve_agent_participation_for_scope_keys(
                state,
                &agent_id,
                &scope_keys,
            )
            .await
        else {
            return Err(mode.rejection_reason());
        };
        if resolved.ceiling_unresolved {
            return Err(arkret_wire::ReasonCode::AGENT_PARTICIPATION_CEILING_UNRESOLVED);
        }
        if !ap_effective_for_mode(mode, resolved.effective) {
            return Err(mode.rejection_reason());
        }
        if authorization_ref.is_some() {
            validate_agent_act_on_behalf_approval(
                state,
                operation,
                &agent_id,
                covering_committed_at,
            )
            .await?;
        }
    }
    Ok(())
}
