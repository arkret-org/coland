//! Management restrictions on concrete actions before grant/quota selection.
use arkret_models_collaboration::governance::operation_wire::{
    AgentPolicyOperation, Policy, PolicyResourceKind, PolicyResourceSelector,
};
use arkret_policy::agent_management::{AgentManagementContext, evaluate_agent_management};
use arkret_wire::{AccountId, CapabilityActionId, PolicyEffect, RealmId, ServiceOperationId};
use coland_storage::{AuthorizationOperation, PersistenceError, PersistenceResult};

fn unavailable(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("failed_precondition: {detail}"))
}

/// Resolve the continuous reading ceiling from the same authoritative snapshot.
/// Control Realms and independently founded Directs keep their own contracts.
pub(crate) async fn read_controller_in_connection(
    conn: &mut diesel_async::AsyncPgConnection,
    realm: &RealmId,
    circle: Option<&arkret_wire::CircleId>,
    actor: &arkret_wire::ActorId,
) -> PersistenceResult<Option<arkret_wire::ActorId>> {
    if !crate::committed_disclosure::ordinary_agent_read_ceiling(
        crate::account_stream_scan::realm_purpose(conn, realm).await?,
    ) {
        return Ok(None);
    }
    let at = chrono::Utc::now();
    let Some(controller) = crate::realm_authorization_cut::owned_controller_snapshot_in_connection(
        conn, realm, actor, at,
    )
    .await?
    else {
        return Ok(None);
    };
    require_member_event_read_in_connection(
        conn,
        realm,
        circle,
        controller
            .as_account_id()
            .ok_or_else(|| unavailable("controller Account is missing"))?,
        actor
            .as_account_id()
            .ok_or_else(|| unavailable("Agent Account is missing"))?,
        at,
    )
    .await?;
    Ok(Some(controller))
}

/// Canonical Event reads use the content event.read action, independently of
/// the member/history source that admits the read. This is not a delivery gate.
pub(crate) async fn require_member_event_read_in_connection(
    conn: &mut diesel_async::AsyncPgConnection,
    realm: &RealmId,
    circle: Option<&arkret_wire::CircleId>,
    controller: &AccountId,
    agent: &AccountId,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    let policies =
        crate::policy_current_results::read_scoped_agent_management_policy_snapshot_in_connection(
            conn, realm, circle,
        )
        .await?;
    require_member_event_read(&policies, realm, controller, agent, at)
}

fn require_member_event_read(
    policies: &[Policy],
    realm: &RealmId,
    controller: &AccountId,
    agent: &AccountId,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    // Reading an Event can disclose referenced objects and private preimages.
    // Until those scopes are resolved, narrower rules cannot prove a nonmatch.
    if policies
        .iter()
        .flat_map(|policy| &policy.rules)
        .any(|rule| {
            rule.resources.as_ref().is_some_and(|resources| {
                resources
                    .iter()
                    .any(|resource| resource.kind != PolicyResourceKind::Realm)
            })
        })
    {
        return Err(unavailable(
            "Agent Event read resource evidence is unavailable",
        ));
    }
    let resources = [PolicyResourceSelector {
        kind: PolicyResourceKind::Realm,
        realm_id: Some(realm.clone()),
        resource_ref: Some(realm.to_string()),
    }];
    let effect = evaluate_agent_management(
        Some(policies),
        &AgentManagementContext {
            realm_id: realm,
            ownership: Some((controller, agent)),
            operation: AgentPolicyOperation::Read,
            content_action: Some(
                CapabilityActionId::from_wire("ak.event.read")
                    .ok_or_else(|| unavailable("Event read action is unregistered"))?,
            ),
            resources: Some(&resources),
            at,
        },
    )
    .map_err(unavailable)?;
    match effect {
        PolicyEffect::Allow => Ok(()),
        PolicyEffect::Deny => Err(PersistenceError::Conflict(
            "capability_denied: Agent management forbids Event reading".to_owned(),
        )),
        PolicyEffect::Quarantine | PolicyEffect::RequireReview => Err(unavailable(
            "Agent Event read requires unresolved quarantine or review evidence",
        )),
    }
}

/// The caller has verified the prospective member's ownership. Do not read
/// an existing Agent join here: this gate precedes its first membership write.
pub(crate) async fn require_join_in_connection(
    conn: &mut diesel_async::AsyncPgConnection,
    realm: &RealmId,
    controller: &AccountId,
    agent: &AccountId,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    let policies =
        crate::policy_current_results::read_scoped_agent_management_policies_in_connection(
            conn, realm, None,
        )
        .await?;
    require_join(&policies, realm, controller, agent, at)
}

fn require_join(
    policies: &[Policy],
    realm: &RealmId,
    controller: &AccountId,
    agent: &AccountId,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    require_realm_intent(
        policies,
        realm,
        controller,
        agent,
        at,
        AgentPolicyOperation::Join,
    )
}

/// Opening public intent is distinct from continuous public serving. Ownership,
/// the signed mode transition and its exact CAS are verified by the caller.
pub(crate) fn require_publish_in_connection<'a>(
    conn: &'a mut diesel_async::AsyncPgConnection,
    realm: &'a RealmId,
    controller: &'a AccountId,
    agent: &'a AccountId,
    at: chrono::DateTime<chrono::Utc>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = PersistenceResult<()>> + Send + 'a>> {
    // Keep the complete Policy reader's state out of the enclosing mode/UOW
    // future, which already contains the other same-cut admission consumers.
    Box::pin(async move {
        let policies =
            crate::policy_current_results::read_scoped_agent_management_policies_in_connection(
                conn, realm, None,
            )
            .await?;
        require_realm_intent(
            &policies,
            realm,
            controller,
            agent,
            at,
            AgentPolicyOperation::Publish,
        )
    })
}

fn require_realm_intent(
    policies: &[Policy],
    realm: &RealmId,
    controller: &AccountId,
    agent: &AccountId,
    at: chrono::DateTime<chrono::Utc>,
    operation: AgentPolicyOperation,
) -> PersistenceResult<()> {
    let intent = match operation {
        AgentPolicyOperation::Join => "joining",
        AgentPolicyOperation::Publish => "publishing",
        _ => return Err(unavailable("Agent Realm intent operation is unsupported")),
    };
    // Realm membership/public intent does not establish a Strand/object action.
    // Unsupported scoped evidence must not be treated as a nonmatching ban.
    if policies
        .iter()
        .flat_map(|policy| &policy.rules)
        .any(|rule| {
            rule.resources.as_ref().is_some_and(|resources| {
                resources
                    .iter()
                    .any(|resource| resource.kind != PolicyResourceKind::Realm)
            })
        })
    {
        return Err(unavailable(format!(
            "Agent {intent} resource evidence is unavailable"
        )));
    }
    let resources = [PolicyResourceSelector {
        kind: PolicyResourceKind::Realm,
        realm_id: Some(realm.clone()),
        resource_ref: Some(realm.to_string()),
    }];
    let effect = evaluate_agent_management(
        Some(policies),
        &AgentManagementContext {
            realm_id: realm,
            ownership: Some((controller, agent)),
            operation,
            content_action: None,
            resources: Some(&resources),
            at,
        },
    )
    .map_err(unavailable)?;
    match effect {
        PolicyEffect::Allow => Ok(()),
        PolicyEffect::Deny => Err(PersistenceError::Conflict(format!(
            "capability_denied: Agent management forbids {intent}"
        ))),
        PolicyEffect::Quarantine | PolicyEffect::RequireReview => Err(unavailable(format!(
            "Agent {intent} requires unresolved quarantine or review evidence"
        ))),
    }
}

/// Every requested action must pass: grant admission has no alternative-action
/// semantics. The issuer's own grant/root authority is checked separately.
pub(crate) async fn require_authorization_in_connection(
    conn: &mut diesel_async::AsyncPgConnection,
    realm: &RealmId,
    controller: &AccountId,
    agent: &AccountId,
    actions: &[String],
    resources: &[arkret_wire::WireResourceSelector],
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    let policies =
        crate::policy_current_results::read_scoped_agent_management_policies_in_connection(
            conn, realm, None,
        )
        .await?;
    require_authorization(&policies, realm, controller, agent, actions, resources, at)
}

fn require_authorization(
    policies: &[Policy],
    realm: &RealmId,
    controller: &AccountId,
    agent: &AccountId,
    actions: &[String],
    resources: &[arkret_wire::WireResourceSelector],
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    if actions.is_empty() || resources.is_empty() {
        return Err(unavailable("Agent authorization coverage is empty"));
    }
    // A join-only default-allow Policy does not constrain authorizing an
    // existing Agent. Keep the coverage guard only when this operation may
    // be restricted; the SDK evaluator below still validates every Policy.
    let authorization_is_restricted = policies.iter().any(|policy| {
        policy.default_effect != PolicyEffect::Allow
            || policy.rules.iter().any(|rule| {
                rule.agent_operations
                    .as_ref()
                    .is_none_or(|operations| operations.contains(&AgentPolicyOperation::Authorize))
            })
    });
    // A broad grant selector is a coverage promise, not an actual resource.
    // Until containment/intersection is established, never let a narrower
    // management restriction disappear by testing only the grant's Realm.
    if authorization_is_restricted
        && (policies.iter().flat_map(|p| &p.rules).any(|rule| {
            rule.resources.as_ref().is_some_and(|selectors| {
                selectors
                    .iter()
                    .any(|selector| selector.kind != PolicyResourceKind::Realm)
            })
        }) || resources.iter().any(|resource| {
            resource.kind != arkret_wire::ResourceSelectorKind::Realm
                || resource.realm_id.as_ref() != Some(realm)
                || resource.match_scope.is_some()
        }))
    {
        return Err(unavailable(
            "Agent authorization resource coverage is unavailable",
        ));
    }
    let actual_resources = [PolicyResourceSelector {
        kind: PolicyResourceKind::Realm,
        realm_id: Some(realm.clone()),
        resource_ref: Some(realm.to_string()),
    }];
    for action in actions {
        let descriptor = arkret_schema::capability_action(action)
            .ok_or_else(|| unavailable("Agent authorization action is unknown"))?;
        let content_action = if descriptor.event_mapping_kind == "aggregate_admin"
            || ServiceOperationId::from_wire(action).is_some()
        {
            if authorization_is_restricted {
                return Err(unavailable(
                    "Agent authorization action coverage is unavailable",
                ));
            }
            None
        } else {
            Some(
                CapabilityActionId::from_wire(action)
                    .ok_or_else(|| unavailable("Agent authorization content action is unknown"))?,
            )
        };
        let effect = evaluate_agent_management(
            Some(policies),
            &AgentManagementContext {
                realm_id: realm,
                ownership: Some((controller, agent)),
                operation: AgentPolicyOperation::Authorize,
                content_action,
                resources: Some(&actual_resources),
                at,
            },
        )
        .map_err(unavailable)?;
        match effect {
            PolicyEffect::Allow => {}
            PolicyEffect::Deny => {
                return Err(PersistenceError::Conflict(
                    "capability_denied: Agent management forbids authorization".to_owned(),
                ));
            }
            PolicyEffect::Quarantine | PolicyEffect::RequireReview => {
                return Err(unavailable(
                    "Agent authorization requires unresolved quarantine or review evidence",
                ));
            }
        }
    }
    Ok(())
}

/// Ownership and operation facts have already been resolved at the accepting cut.
/// This is not a read/delivery gate and never establishes ownership itself.
/// An empty result holds no permission path; the caller may try a separately
/// registered `.own` action, but must not admit or reserve quota for this result.
pub(crate) async fn executable_actions_in_connection<'a>(
    conn: &mut diesel_async::AsyncPgConnection,
    realm: &RealmId,
    controller: &AccountId,
    agent: &AccountId,
    operation: &AuthorizationOperation<'a>,
) -> PersistenceResult<Vec<&'a str>> {
    let fact_circle = operation
        .facts
        .circle_id
        .as_ref()
        .map(|id| id.parse::<arkret_wire::CircleId>())
        .transpose()
        .map_err(unavailable)?;
    if operation
        .target
        .circle_id
        .as_ref()
        .zip(fact_circle.as_ref())
        .is_some_and(|(target, fact)| target != fact)
    {
        return Err(unavailable("Agent management Circle facts conflict"));
    }
    let policies =
        crate::policy_current_results::read_scoped_agent_management_policies_in_connection(
            conn,
            realm,
            operation.target.circle_id.as_ref().or(fact_circle.as_ref()),
        )
        .await?;
    executable_actions(&policies, realm, controller, agent, operation)
}

fn executable_actions<'a>(
    policies: &[Policy],
    realm: &RealmId,
    controller: &AccountId,
    agent: &AccountId,
    operation: &AuthorizationOperation<'a>,
) -> PersistenceResult<Vec<&'a str>> {
    coland_storage::agent_management_actions(
        policies,
        realm,
        controller,
        agent,
        operation,
        Some(AgentPolicyOperation::Execute),
    )
}

#[cfg(test)]
mod tests;
