use salvo::oapi::endpoint;

use super::*;

pub(super) fn participation_scope_kind(scope: &ParticipationScope) -> &'static str {
    match scope {
        ParticipationScope::Realm { .. } => "realm",
        ParticipationScope::Circle { .. } => "circle",
        ParticipationScope::Strand { .. } => "strand",
    }
}

pub(super) fn participation_from_value(row: &Value) -> ParticipationBits {
    crate::routing::agent_participation::participation_from_value(row)
}

pub(super) fn agent_participation_failed_precondition(reason: &'static str) -> AppError {
    crate::app_error!(FailedPrecondition, reason).with_rejection_code(reason)
}

#[endpoint(
    operation_id = "ak.self.agent.participation.resource.replace",
    summary = "Replace an agent's participation policy",
    tags("agent_participation")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ak.self.agent.participation.resource.replace.v1")
)]
pub(super) async fn set_agent_participation(
    aa: AuthArgs,
    agent_id: PathParam<String>,
    body: JsonBody<ParticipationReplaceRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentParticipationResponseBody> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let agent_id = agent_id.into_inner();
    let record = require_agent_controller(state, &session, &agent_id).await?;
    crate::routing::identity::agent_pcr::validate_agent_controller_binding(
        state,
        &record,
        chrono::Utc::now(),
    )
    .await?;
    let body = body.into_inner();
    let scope_value = serde_json::to_value(&body.target_scope).unwrap_or(Value::Null);
    let scope_key = body.target_scope.scope_key();
    let accepted_version = body
        .expected_version
        .checked_add(1)
        .filter(|version| *version <= MAX_PARTICIPATION_REPLACE_EXPECTED_VERSION)
        .ok_or_else(|| AppError::param_invalid("expected_version exceeds supported range"))?;
    let selection_value = serde_json::to_value(body.selection).unwrap_or(Value::Null);
    if !state
        .agent_participations()
        .compare_and_swap_selection(
            json!({
                "agent_id": agent_id,
                "scope_kind": participation_scope_kind(&body.target_scope),
                "scope_key": scope_key,
                "realm_id": body.target_scope.realm_id().as_str(),
                "scope": scope_value.clone(),
                "version": accepted_version,
                "message_creation_allowed": body.selection.message_creation_allowed,
                "reaction_addition_allowed": body.selection.reaction_addition_allowed,
                "reaction_removal_allowed": body.selection.reaction_removal_allowed,
                "third_party_mention_delivery_allowed": body.selection.third_party_mention_delivery_allowed,
                "acting_on_behalf_allowed": body.selection.acting_on_behalf_allowed,
            }),
            body.expected_version,
        )
        .await
        .map_err(|err| AppError::internal(format!("participation persist failed: {err}")))?
    {
        return Err(agent_participation_failed_precondition("cas_conflict"));
    }
    append_audit_log(
        state,
        Some(&session.actor),
        arkret_wire::ServiceOperationId::SELF_AGENT_PARTICIPATION_RESOURCE_REPLACE_V1,
        json!({
            "agent_id": agent_id,
            "controller_account_id": arkret_wire::AccountId::new(
                arkret_wire::DidCoreId::new(session.actor.clone()).map_err(|error| {
                    AppError::internal(format!("session actor is invalid: {error}"))
                })?,
                state.service_core_id().clone(),
            ),
            "scope": scope_value,
            "scope_key": scope_key,
            "selection": selection_value,
            "accepted_version": accepted_version,
        }),
        "accepted",
    )
    .await;
    json_ok(load_agent_participation_outcome(state, &agent_id).await?)
}

#[endpoint(
    operation_id = "ak.self.agent.participation.resource.get",
    summary = "Get an agent's participation policy",
    tags("agent_participation")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.agent.participation.resource.get.v1"))]
pub(super) async fn get_agent_participation(
    aa: AuthArgs,
    agent_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentParticipationResponseBody> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let agent_id = agent_id.into_inner();
    let record = require_agent_controller(state, &session, &agent_id).await?;
    crate::routing::identity::agent_pcr::validate_agent_controller_binding(
        state,
        &record,
        chrono::Utc::now(),
    )
    .await?;
    json_ok(load_agent_participation_outcome(state, &agent_id).await?)
}

pub(crate) async fn load_agent_participation_outcome(
    state: &AppState,
    agent_id: &str,
) -> Result<AgentParticipationResponseBody, AppError> {
    let selections = state
        .agent_participations()
        .selections(agent_id)
        .await
        .map_err(|err| AppError::internal(format!("participation read failed: {err}")))?;
    let mut entries = Vec::with_capacity(selections.len());
    for row in &selections {
        let scope_value = row.get("scope").ok_or_else(|| {
            agent_participation_failed_precondition(
                arkret_wire::ReasonCode::AGENT_PARTICIPATION_CEILING_UNRESOLVED,
            )
        })?;
        let scope =
            serde_json::from_value::<ParticipationScope>(scope_value.clone()).map_err(|_| {
                agent_participation_failed_precondition(
                    arkret_wire::ReasonCode::AGENT_PARTICIPATION_CEILING_UNRESOLVED,
                )
            })?;
        let selection = participation_from_value(row);
        let version = row.get("version").and_then(Value::as_u64).unwrap_or(0);
        if version == 0
            || version > MAX_PARTICIPATION_REPLACE_EXPECTED_VERSION
            || row.get("agent_id").and_then(Value::as_str) != Some(agent_id)
            || row.get("scope_key").and_then(Value::as_str) != Some(scope.scope_key().as_str())
            || row.get("realm_id").and_then(Value::as_str) != Some(scope.realm_id().as_str())
            || row.get("scope_kind").and_then(Value::as_str)
                != Some(participation_scope_kind(&scope))
            || [
                "message_creation_allowed",
                "reaction_addition_allowed",
                "reaction_removal_allowed",
                "third_party_mention_delivery_allowed",
                "acting_on_behalf_allowed",
            ]
            .iter()
            .any(|key| row.get(*key).and_then(Value::as_bool).is_none())
        {
            return Err(agent_participation_failed_precondition(
                arkret_wire::ReasonCode::AGENT_PARTICIPATION_CEILING_UNRESOLVED,
            ));
        }
        entries.push(AgentParticipationEntry {
            scope,
            selection,
            version,
            next_replace_input: (version <= arkret_models_collaboration::governance::agent_participation::MAX_PARTICIPATION_REPLACE_EXPECTED_VERSION).then_some(ParticipationNextReplaceInput {
                expected_version: version,
            }),
        });
    }
    Ok(AgentParticipationResponseBody {
        agent_id: agent_id.to_owned(),
        agent_participation_entries: entries,
    })
}
