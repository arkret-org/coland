//! Backend result adapter for the shared SDK Agent ceiling.
use arkret_models_collaboration::governance::operation_wire::{AgentPolicyOperation, Policy};
use arkret_wire::{AccountId, RealmId};

use crate::{AuthorizationOperation, PersistenceError, PersistenceResult};
pub fn agent_management_actions<'a>(
    policies: &[Policy],
    realm: &RealmId,
    controller: &AccountId,
    agent: &AccountId,
    operation: &AuthorizationOperation<'a>,
    policy_operation: Option<AgentPolicyOperation>,
) -> PersistenceResult<Vec<&'a str>> {
    arkret_policy::agent_content_ceiling::agent_management_actions(
        policies,
        realm,
        controller,
        agent,
        operation,
        policy_operation,
    )
    .map_err(|error| match error {
        arkret_wire::WireError::Protocol(detail) => PersistenceError::Conflict(detail),
        other => PersistenceError::Conflict(other.to_string()),
    })
}
