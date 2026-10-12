//! Backend-neutral Agent management filtering over verified actual facts.
use arkret_models_collaboration::governance::operation_wire::{
    AgentPolicyOperation, Policy, PolicyResourceKind, PolicyResourceSelector,
};
use arkret_policy::agent_management::{AgentManagementContext, evaluate_agent_management};
use arkret_wire::{AccountId, CapabilityActionId, PolicyEffect, RealmId, ServiceOperationId};

use crate::{AuthorizationOperation, PersistenceError, PersistenceResult};

fn unavailable(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("failed_precondition: {detail}"))
}

pub fn agent_management_actions<'a>(
    policies: &[Policy],
    realm: &RealmId,
    controller: &AccountId,
    agent: &AccountId,
    operation: &AuthorizationOperation<'a>,
    policy_operation: Option<AgentPolicyOperation>,
) -> PersistenceResult<Vec<&'a str>> {
    if operation.actor.as_account_id() != Some(agent)
        || operation.target.realm_id.as_ref() != Some(realm)
    {
        return Err(unavailable(
            "Agent management operation identity is unavailable",
        ));
    }
    // Object selector facts are not yet resolved by this admission adapter.
    // Refuse such evidence instead of making a scoped deny fail to match.
    if policies.iter().flat_map(|p| &p.rules).any(|rule| {
        rule.resources.as_ref().is_some_and(|resources| {
            resources.iter().any(|resource| {
                matches!(
                    resource.kind,
                    PolicyResourceKind::Object | PolicyResourceKind::Service
                )
            })
        })
    }) {
        return Err(unavailable(
            "Agent management object resource evidence is unavailable",
        ));
    }
    let mut resources = vec![PolicyResourceSelector {
        kind: PolicyResourceKind::Realm,
        realm_id: Some(realm.clone()),
        resource_ref: Some(realm.to_string()),
    }];
    for (kind, target, fact) in [
        (
            PolicyResourceKind::Strand,
            operation.target.strand_id.as_ref().map(ToString::to_string),
            operation.facts.strand_id.as_ref(),
        ),
        (
            PolicyResourceKind::Space,
            operation.target.space_id.as_ref().map(ToString::to_string),
            operation.facts.space_id.as_ref(),
        ),
    ] {
        if target
            .as_ref()
            .zip(fact)
            .is_some_and(|(target, fact)| target != fact)
        {
            return Err(unavailable("Agent management resource facts conflict"));
        }
        if let Some(id) = target.or_else(|| fact.cloned()) {
            let valid = match kind {
                PolicyResourceKind::Strand => id.parse::<arkret_wire::StrandId>().is_ok(),
                PolicyResourceKind::Space => id.parse::<arkret_wire::SpaceId>().is_ok(),
                _ => false,
            };
            if !valid {
                return Err(unavailable("Agent management resource identity is invalid"));
            }
            resources.push(PolicyResourceSelector {
                kind,
                realm_id: Some(realm.clone()),
                resource_ref: Some(id),
            });
        }
    }
    let mut allowed = Vec::new();
    let mut aggregates = Vec::new();
    let mut concrete_count = 0;
    let mut restricted = false;
    for &token in operation.actions {
        let descriptor = arkret_schema::capability_action(token)
            .ok_or_else(|| unavailable("Agent management action mapping is unavailable"))?;
        if descriptor.event_mapping_kind == "aggregate_admin" {
            aggregates.push(token);
            continue;
        }
        concrete_count += 1;
        if ServiceOperationId::from_wire(token).is_some() {
            return Err(unavailable(
                "Agent management content action is unavailable",
            ));
        }
        let action = CapabilityActionId::from_wire(token)
            .ok_or_else(|| unavailable("Agent management content action is unknown"))?;
        let effect = evaluate_agent_management(
            Some(policies),
            &AgentManagementContext {
                realm_id: realm,
                ownership: Some((controller, agent)),
                operation: policy_operation.clone().unwrap_or_else(|| {
                    if descriptor.target_event_kinds.is_empty() {
                        AgentPolicyOperation::Read
                    } else {
                        AgentPolicyOperation::Execute
                    }
                }),
                content_action: Some(action),
                resources: Some(&resources),
                at: operation.at,
            },
        )
        .map_err(unavailable)?;
        match effect {
            PolicyEffect::Allow => allowed.push(token),
            PolicyEffect::Deny => {}
            PolicyEffect::Quarantine | PolicyEffect::RequireReview => restricted = true,
        }
    }
    if concrete_count == 0 {
        return Err(unavailable(
            "Agent management concrete action mapping is unavailable",
        ));
    }
    if allowed.is_empty() && restricted {
        return Err(unavailable(
            "Agent management requires unresolved quarantine or review evidence",
        ));
    }
    // An existing aggregate grant remains a permission path only when none
    // of this operation's concrete paths were filtered by management. It is
    // never evaluated as a content action or used to bypass a restricted path.
    if allowed.len() == concrete_count {
        allowed.extend(aggregates);
    }
    Ok(allowed)
}
