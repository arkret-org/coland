//! Deployment-private content ceilings from the same durable authorization cut.

use arkret_models_collaboration::events_payloads::agent::{
    AgentKeyAuthorizePayload, AgentKeyScope,
};
use arkret_wire::{ActorId, Event, RealmCommit, RealmId, WireResourceSelector};

use super::*;

fn unavailable(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Database(format!("Agent session source is unavailable: {detail}"))
}

#[derive(QueryableByName)]
struct Source {
    #[diesel(sql_type = Jsonb)]
    envelope: Value,
    #[diesel(sql_type = Jsonb)]
    commit_json: Value,
    #[diesel(sql_type = Jsonb)]
    requested_scope: Value,
    #[diesel(sql_type = Bool)]
    active: bool,
}

#[derive(QueryableByName)]
struct Target {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Jsonb)]
    value: Value,
    #[diesel(sql_type = Jsonb)]
    commit_json: Value,
    #[diesel(sql_type = Bool)]
    ordinary: bool,
    #[diesel(sql_type = Bool)]
    governed_here: bool,
    #[diesel(sql_type = Bool)]
    restricted_policy: bool,
}

pub(crate) async fn read(
    conn: &mut AsyncPgConnection,
    request: &AgentSessionAuthorityRequest,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<AgentSessionAuthorityOutcome> {
    let source = sql_query("SELECT e.envelope,c.commit_json,a.requested_scope,EXISTS(SELECT 1 FROM agent_key_current_results k CROSS JOIN LATERAL jsonb_array_elements(k.value->'authorizations') d WHERE k.realm_id=a.principal_control_realm_id AND d->>'tag_id'=$3||':1' AND d->'value'=e.envelope->'payload') AS active FROM agent_principals a JOIN agent_status_current_results s ON s.realm_id=a.principal_control_realm_id AND s.agent_id=a.id JOIN canonical_events e ON e.envelope->>'event_id'=$3 AND e.state='committed' JOIN realm_commits c ON c.event_pk=e.pk AND c.realm_id=a.principal_control_realm_id WHERE a.id=$1 AND a.controller_principal_id=$2 AND a.authorized_event_ref=$3 AND s.value='\"active\"'::jsonb")
        .bind::<Text,_>(request.agent_account_id.principal_id.as_str())
        .bind::<Text,_>(request.controller_account_id.principal_id.as_str())
        .bind::<Text,_>(request.agent_key_authorization_ref.as_str())
        .get_result::<Source>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(||unavailable("current Agent/key binding is absent"))?;
    let event: Event = serde_json::from_value(source.envelope).map_err(unavailable)?;
    let commit: RealmCommit = serde_json::from_value(source.commit_json).map_err(unavailable)?;
    commit.validate_content_address().map_err(unavailable)?;
    let key = AgentKeyAuthorizePayload::try_from(&event).map_err(unavailable)?;
    if !key.agent_key_scope.constraints.is_empty() {
        return Err(unavailable(
            "mandatory key constraints need a complete source projection",
        ));
    }
    if !source.active
        || event.event_id != request.agent_key_authorization_ref
        || commit.event_ref != event.event_id
        || commit.realm_id != event.realm_id
        || event.actor_id != ActorId::account(request.agent_account_id.clone())
        || event.executed_by != Some(ActorId::account(request.controller_account_id.clone()))
        || key.verification_method != request.verification_method
        || key.expires_at.is_some_and(|expiry| at >= expiry)
    {
        return Err(unavailable("current accepted Agent source changed"));
    }
    let provision: AgentKeyScope =
        serde_json::from_value(source.requested_scope).map_err(unavailable)?;
    if !arkret_models_collaboration::agent_scope::agent_key_scope_within_provision(
        &key.agent_key_scope,
        &provision,
    ) {
        return Err(unavailable("key exceeds its immutable provision ceiling"));
    }

    // A single exact Strand avoids manufacturing a Cartesian product from
    // independently qualified action/resource paths. Other profiles retain
    // their registered source gates and cannot fall through this ordinary cut.
    let [strand] = request.resource_scope.strand_ids.as_slice() else {
        return Err(unavailable("source requires one exact Strand selector"));
    };
    if !request.resource_scope.realm_ids.is_empty() {
        return Err(unavailable(
            "mixed resource selectors need separate source requests",
        ));
    }
    let strand_event =
        arkret_wire::EventId::from_token_bytes(strand.token_bytes()).map_err(unavailable)?;
    let target=sql_query("SELECT p.realm_id,p.value,c.commit_json,(NOT(p.value ? 'scope_circle_id') AND EXISTS(SELECT 1 FROM canonical_events e WHERE e.envelope->>'event_id'=$2 AND e.state='committed' AND e.envelope->'scope_ref'->>'kind'='realm')) AS ordinary,EXISTS(SELECT 1 FROM realm_authorities r WHERE r.realm_id=p.realm_id AND r.service_id=$3) AS governed_here,EXISTS(SELECT 1 FROM realm_policy_bundle_current_results b WHERE b.realm_id=p.realm_id AND b.value->'agent_participation' IS NOT NULL AND b.value->'agent_participation'<>'null'::jsonb) AS restricted_policy FROM strand_current_results p JOIN realm_commits c ON c.commit_id=p.current_commit_id AND c.realm_id=p.realm_id AND c.stream_position=p.current_stream_position WHERE p.strand_id=$1")
        .bind::<Text,_>(strand.as_str()).bind::<Text,_>(strand_event.as_str())
        .bind::<Text,_>(request.agent_account_id.station_id.as_str())
        .get_result::<Target>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(||unavailable("exact current Strand is absent"))?;
    if !target.ordinary {
        return Err(unavailable("resource is not an ordinary Realm Strand"));
    }
    if !target.governed_here {
        return Err(unavailable(
            "resource governance belongs to another Station",
        ));
    }
    if target.restricted_policy {
        return Err(unavailable(
            "Realm participation policy needs its complete source projection",
        ));
    }
    let realm = RealmId::new(target.realm_id).map_err(unavailable)?;
    if crate::account_stream_scan::realm_purpose(conn, &realm).await?
        != Some(arkret_models_collaboration::events_payloads::realm::RealmPurpose::Collaboration)
    {
        return Err(unavailable(
            "resource requires its dedicated profile authority",
        ));
    }
    let current: arkret_models_collaboration::objects::strand::Strand =
        serde_json::from_value(target.value).map_err(unavailable)?;
    let covering: RealmCommit = serde_json::from_value(target.commit_json).map_err(unavailable)?;
    covering.validate_content_address().map_err(unavailable)?;
    if current.id.as_ref() != Some(strand)
        || current.realm_id != realm
        || current.scope_circle_id.is_some()
        || current.agent_participation.is_some()
        || current.state != Some(arkret_wire::ObjectState::Active)
        || covering.realm_id != realm
        || covering.stream_ref
            != (arkret_wire::CommitStreamRef::Realm {
                realm_id: realm.clone(),
            })
    {
        return Err(unavailable(
            "Strand current identity, lifecycle or covering stream changed",
        ));
    }
    let resource = WireResourceSelector::strand(realm.clone(), strand.clone());
    let cut = crate::realm_authorization_cut::RealmAuthorizationCut::read(
        conn,
        &realm,
        &ActorId::account(request.agent_account_id.clone()),
    )
    .await?;
    let authorization = cut
        .bounded_actor_authorization_in_connection(conn, at)
        .await?;
    if authorization.agent_ceiling.as_ref().is_none_or(|ceiling| {
        ceiling.controller.actor != ActorId::account(request.controller_account_id.clone())
    }) {
        return Err(unavailable(
            "current controller/membership/management backing is unavailable",
        ));
    }
    let facts = coland_storage::OperationFacts::default();
    let mut grant_refs = BTreeSet::new();
    for action in &request.requested_scope {
        if arkret_wire::ServiceOperationId::from_wire(action).is_some() {
            continue;
        }
        let actions = [action.as_str()];
        if !matches!(
            authorization.evaluate(&actions, &resource, &facts),
            coland_storage::GrantEvaluation::Allowed(_)
        ) {
            return Ok(empty(request));
        }
        let operation = coland_storage::AuthorizationOperation {
            actor: &authorization.actor,
            actions: &actions,
            target: &resource,
            at,
            facts: &facts,
        };
        let Some(chosen) = authorization.grants.iter().find(|row| {
            coland_storage::grant_names_target(&row.grant, &actions, &resource)
                && matches!(
                    coland_storage::evaluate_grants(&operation, std::iter::once(&row.grant)),
                    coland_storage::GrantEvaluation::Allowed(_)
                )
        }) else {
            return Ok(empty(request));
        };
        grant_refs.insert(chosen.grant.id.clone());
    }
    let mut selected: AgentKeyScope = serde_json::from_value(serde_json::json!({
        "actions":request.requested_scope,"resources":key.agent_key_scope.resources,
        "constraints":key.agent_key_scope.constraints,
    }))
    .map_err(unavailable)?;
    selected.resources.retain(|entry|entry.kind==arkret_models_collaboration::events_payloads::agent::AgentKeyScopeResourceKind::Operation);
    selected.resources.push(
        serde_json::from_value(serde_json::json!({
            "kind":"strand","realm_id":realm,"resource_ref":strand,
        }))
        .map_err(unavailable)?,
    );
    if !arkret_models_collaboration::agent_scope::agent_key_scope_within_provision(
        &selected,
        &key.agent_key_scope,
    ) {
        return Ok(empty(request));
    }
    Ok(AgentSessionAuthorityOutcome {
        binding: request.clone(),
        granted_scope: request.requested_scope.clone(),
        realm_ids: Vec::new(),
        strand_ids: vec![strand.clone()],
        allowed_tracks: request
            .resource_scope
            .track_names
            .iter()
            .map(ToString::to_string)
            .collect(),
        allowed_data_labels: Vec::new(),
        allowed_endpoints: Vec::new(),
        capability_grant_refs: grant_refs.into_iter().collect(),
        policy_refs: Vec::new(),
    })
}

fn empty(request: &AgentSessionAuthorityRequest) -> AgentSessionAuthorityOutcome {
    AgentSessionAuthorityOutcome {
        binding: request.clone(),
        granted_scope: Vec::new(),
        realm_ids: Vec::new(),
        strand_ids: Vec::new(),
        allowed_tracks: Vec::new(),
        allowed_data_labels: Vec::new(),
        allowed_endpoints: Vec::new(),
        capability_grant_refs: Vec::new(),
        policy_refs: Vec::new(),
    }
}
