//! Publication guard for the optional own-Agent membership projection.
use super::*;

struct MembershipGuard {
    held: Box<DeliveryGuard>,
    expires_at: chrono::DateTime<chrono::Utc>,
    actor: ActorId,
    targets: Vec<arkret_wire::WireResourceSelector>,
    constraints: Vec<arkret_models_collaboration::governance::grant_constraint::GrantConstraint>,
}

#[async_trait::async_trait]
impl AccountContentDeliveryGuard for MembershipGuard {
    fn permits_handoff(&self) -> bool {
        let at = chrono::Utc::now();
        at < self.expires_at
            && self.targets.iter().all(|target| {
                let op = coland_storage::AuthorizationOperation {
                    actor: &self.actor,
                    target,
                    facts: &coland_storage::OperationFacts::default(),
                    at,
                    actions: &[arkret_wire::ServiceOperationId::SELF_ACCOUNT_STREAM_SUBSCRIBE_V1],
                };
                matches!(
                    arkret_policy::grant_evaluation::evaluate_constraint_ceiling(
                        &op,
                        &self.constraints
                    ),
                    arkret_policy::grant_evaluation::GrantEvaluation::Allowed(_)
                )
            })
    }
    async fn finish(self: Box<Self>) -> PersistenceResult<()> {
        self.held.finish().await
    }
}

pub(super) async fn acquire(
    mut held: Box<DeliveryGuard>,
    account: &AccountId,
    station: &DidCoreId,
    input: &coland_storage::AccountContentDeliveryInput,
    items: &[arkret_models_collaboration::sync_frames::demand_sync::AccountRealmView],
) -> PersistenceResult<Option<Box<dyn AccountContentDeliveryGuard>>> {
    use arkret_models_collaboration::events_payloads::agent::{
        AgentKeyAuthorizePayload, AgentKeyScopeResourceKind,
    };
    use arkret_models_collaboration::sync_frames::demand_sync::RealmListMembership;
    const OP: &str = arkret_wire::ServiceOperationId::SELF_ACCOUNT_STREAM_SUBSCRIBE_V1;
    let denied = || unavailable("Agent membership subscription is unavailable");
    let endpoint = input.agent_endpoint.as_ref().ok_or_else(denied)?;
    let evidence = input
        .qualified_agent_scope_evidence
        .as_ref()
        .ok_or_else(denied)?;
    let (scopes, details) = input.agent_session_scope.as_ref().ok_or_else(denied)?;
    if &account.station_id != station
        || account.principal_id != endpoint.agent_id
        || details.agent_key_authorization_ref != endpoint.authorization_ref.event_id
        || details.controller_principal_id
            != evidence.accepted_binding().controller_account.principal_id
        || !scopes.iter().any(|scope| scope == OP)
    {
        return Err(denied());
    }
    let actor = ActorId::account(account.clone());
    let actor_key = actor.canonical_key().map_err(PersistenceError::database)?;
    let mut targets = Vec::new();
    for item in items {
        if item.membership != RealmListMembership::Join
            || item.title.is_some()
            || item.default_strand_id.is_some()
            || item.revision != item.activity_position
        {
            return Err(denied());
        }
        // Both accepted current and its exact projected revision must survive
        // until the HTTP/WS writer releases this transaction at handoff.
        let live = sql_query("SELECT TRUE AS present FROM account_summary_current c
            JOIN account_summary_versions v ON v.actor_key=c.actor_key AND v.realm_id=c.realm_id AND v.revision=c.revision
            JOIN member_state_current_states m ON m.member_id=c.actor_key AND m.realm_id=c.realm_id
            WHERE c.actor_key=$1 AND c.realm_id=$2 AND c.agent_membership_only AND c.available
              AND c.membership='join' AND m.membership='join' AND v.activity_position=$3 FOR SHARE OF m,c")
            .bind::<Text,_>(&actor_key).bind::<Text,_>(item.realm_id.as_str())
            .bind::<diesel::sql_types::BigInt,_>(i64::try_from(item.revision).map_err(PersistenceError::database)?)
            .get_result::<crate::ExistsRow>(held.connection()).await.optional().map_err(PersistenceError::database)?;
        if live.is_none() {
            return Err(denied());
        }
        targets.push(arkret_wire::WireResourceSelector::realm(
            item.realm_id.clone(),
        ));
    }
    if targets.is_empty() {
        targets.push(
            serde_json::from_value(
                serde_json::json!({"kind":"actor","actor_id":account.principal_id}),
            )
            .map_err(PersistenceError::database)?,
        );
    }
    Box::pin(crate::agent_current_states::lock_agent_producer_current(
        held.connection(),
        &endpoint.pcr_realm_id,
        &endpoint.agent_id,
    ))
    .await?;
    Box::pin(
        crate::authority_commit::check_agent_endpoint_current_in_connection(
            held.connection(),
            &endpoint.pcr_realm_id,
            &endpoint.agent_id,
            &endpoint.authorization_ref,
            &endpoint.verification_method,
            chrono::Utc::now(),
        ),
    )
    .await?;
    let source = crate::committed_disclosure::accepted_full_event_in_connection(
        held.connection(),
        &endpoint.authorization_ref.event_id,
    )
    .await?
    .ok_or_else(denied)?;
    let key: AgentKeyAuthorizePayload = serde_json::from_value(
        serde_json::to_value(&source.event.payload).map_err(PersistenceError::database)?,
    )
    .map_err(PersistenceError::database)?;
    let provision = Box::pin(provision_scope_in_connection(
        held.connection(),
        endpoint,
        evidence,
        station,
    ))
    .await?;
    let mut constraints = Vec::new();
    for ceiling in [&provision, &key.agent_key_scope] {
        if !ceiling.actions.iter().any(|a| a == OP)
            || !ceiling.resources.iter().any(|r| {
                r.service_id.as_ref().is_none_or(|id| id == station)
                    && match r.kind {
                        AgentKeyScopeResourceKind::Operation => r.operation.as_deref() == Some(OP),
                        AgentKeyScopeResourceKind::Service => {
                            r.service_id.as_ref() == Some(station)
                                && r.operation
                                    .as_deref()
                                    .is_none_or(|operation| operation == OP)
                        }
                        _ => false,
                    }
                    && r.realm_id.is_none()
                    && r.schema_ref.is_none()
                    && r.resource_ref.is_none()
            })
        {
            return Err(denied());
        }
        constraints.extend(ceiling.constraints.iter().cloned());
    }
    let credential_expiry = input.credential_expires_at.ok_or_else(denied)?;
    let guard = MembershipGuard {
        held,
        expires_at: key
            .expires_at
            .map_or(credential_expiry, |end| end.min(credential_expiry)),
        actor,
        targets,
        constraints,
    };
    if !guard.permits_handoff() {
        return Err(denied());
    }
    Ok(Some(Box::new(guard)))
}
