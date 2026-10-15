//! Deployment-private content ceilings from the same durable authorization cut.

use arkret_models_collaboration::events_payloads::agent::{
    AgentKeyAuthorizePayload, AgentKeyScope,
};
use arkret_wire::{
    ActorId, CapabilityActionId, CommitStreamRef, Event, RealmCommit, RealmId, ScopeRef,
    WireResourceSelector,
};

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

struct ContentTarget {
    realm: RealmId,
    scope: ScopeRef,
    resource: WireResourceSelector,
}

/// One resource per issuance keeps action/resource/constraint correlation in
/// the existing flat session carrier. A Realm selector never proves a child
/// Circle or Sidecar source; those still require their exact consumer gates.
async fn content_target(
    conn: &mut AsyncPgConnection,
    request: &AgentSessionAuthorityRequest,
) -> PersistenceResult<ContentTarget> {
    #[derive(QueryableByName)]
    struct Row {
        #[diesel(sql_type = Jsonb)]
        value: Value,
        #[diesel(sql_type = Jsonb)]
        commit_json: Value,
    }
    let (realm, scope, resource) = match (
        request.resource_scope.realm_ids.as_slice(),
        request.resource_scope.strand_ids.as_slice(),
    ) {
        ([realm], []) => (
            realm.clone(),
            ScopeRef::Realm {
                realm_id: realm.clone(),
            },
            WireResourceSelector::realm(realm.clone()),
        ),
        ([], [strand]) => {
            let row = sql_query("SELECT p.value,c.commit_json FROM strand_current_results p JOIN realm_commits c ON c.commit_id=p.current_commit_id AND c.realm_id=p.realm_id AND c.stream_position=p.current_stream_position JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' WHERE p.strand_id=$1")
                .bind::<Text,_>(strand.as_str()).get_result::<Row>(&mut *conn).await.optional()
                .map_err(PersistenceError::database)?.ok_or_else(||unavailable("exact current Strand is absent"))?;
            let current: arkret_models_collaboration::objects::strand::Strand =
                serde_json::from_value(row.value).map_err(unavailable)?;
            let covering: RealmCommit =
                serde_json::from_value(row.commit_json).map_err(unavailable)?;
            covering.validate_content_address().map_err(unavailable)?;
            if current.id.as_ref() != Some(strand)
                || current.state != Some(arkret_wire::ObjectState::Active)
                || covering.realm_id != current.realm_id
                || request
                    .resource_scope
                    .track_names
                    .iter()
                    .any(|track| !current.tracks.contains_key(track.as_str()))
            {
                return Err(unavailable(
                    "Strand lifecycle or participation ceiling is unavailable",
                ));
            }
            let scope = match covering.stream_ref {
                CommitStreamRef::Realm { ref realm_id }
                    if realm_id == &current.realm_id && current.scope_circle_id.is_none() =>
                {
                    ScopeRef::Realm {
                        realm_id: realm_id.clone(),
                    }
                }
                CommitStreamRef::Circle {
                    ref realm_id,
                    ref circle_id,
                } if realm_id == &current.realm_id
                    && current.scope_circle_id.as_ref() == Some(circle_id) =>
                {
                    ScopeRef::Circle {
                        realm_id: realm_id.clone(),
                        circle_id: circle_id.clone(),
                    }
                }
                _ => {
                    return Err(unavailable(
                        "Strand current has a different effective scope",
                    ));
                }
            };
            let realm = current.realm_id;
            (
                realm.clone(),
                scope,
                WireResourceSelector::strand(realm, strand.clone()),
            )
        }
        _ => {
            return Err(unavailable(
                "request needs one exact Realm or Strand selector",
            ));
        }
    };
    let governed = sql_query("SELECT EXISTS(SELECT 1 FROM realm_authorities WHERE realm_id=$1 AND service_id=$2) AS present")
        .bind::<Text,_>(realm.as_str()).bind::<Text,_>(request.agent_account_id.station_id.as_str())
        .get_result::<crate::query_rows::ExistsRow>(&mut *conn).await.map_err(PersistenceError::database)?.present;
    if !governed {
        return Err(unavailable(
            "resource governance belongs to another Station",
        ));
    }
    Ok(ContentTarget {
        realm,
        scope,
        resource,
    })
}

fn membership_read(action: &str) -> bool {
    matches!(
        CapabilityActionId::from_wire(action),
        Some(
            CapabilityActionId::EventRead
                | CapabilityActionId::StrandRead
                | CapabilityActionId::ObjectRead
                | CapabilityActionId::ObjectReadContent
                | CapabilityActionId::ObjectReadHistory
                | CapabilityActionId::ObjectReadMetadata
        )
    )
}

/// Qualification deliberately precedes MLS readiness. Desired Sidecar endpoints
/// need a ceiling to obtain their Welcome; payload consumers still require
/// effective authority and exact accepted Add/Welcome/claim lineage.
async fn read_source(
    conn: &mut AsyncPgConnection,
    request: &AgentSessionAuthorityRequest,
    target: &ContentTarget,
    direct: bool,
) -> PersistenceResult<bool> {
    let actor = ActorId::account(request.agent_account_id.clone());
    if direct {
        let Some(profile) =
            crate::direct_conversation_admission::direct_conversation_realm_in_connection(
                conn,
                &target.realm,
            )
            .await?
        else {
            return Ok(false);
        };
        if !profile.pair().is_some_and(|pair| pair.contains(&actor))
            || !profile.pair_grants_direct_message_snapshot(conn).await?
        {
            return Ok(false);
        }
        if let Some(binding) =
            crate::direct_conversation_admission::binding_current_snapshot_in_connection(
                conn,
                &target.realm,
            )
            .await?
        {
            binding.binding_digest().map_err(unavailable)?;
            if binding.endorsements.iter().any(|entry| {
                entry.value.realm_id != target.realm
                    || !entry.value.unordered_participant_ids.contains(&actor)
            }) {
                return Ok(false);
            }
        }
        return Ok(
            crate::account_stream_scan::caller_realm_floor_in_connection(
                conn,
                &target.realm,
                &actor,
            )
            .await?
            .is_some(),
        );
    }
    Ok(match &target.scope {
        ScopeRef::Realm { realm_id } => {
            crate::account_stream_scan::caller_realm_floor_in_connection(conn, realm_id, &actor)
                .await?
                .is_some()
        }
        ScopeRef::Circle {
            realm_id,
            circle_id,
        } => crate::account_stream_scan::caller_circle_floor_in_connection(
            conn, realm_id, circle_id, &actor,
        )
        .await?
        .is_some(),
        ScopeRef::Sidecar {
            realm_id,
            sidecar_id,
        } => {
            let Some(cut) =
                crate::sidecar_access::cut_in_connection(conn, realm_id, sidecar_id).await?
            else {
                return Ok(false);
            };
            cut.controller_account_id == request.controller_account_id
                && crate::sidecar_access::desired_participant(&cut, &actor)
        }
        _ => false,
    })
}

pub(crate) async fn read(
    conn: &mut AsyncPgConnection,
    request: &AgentSessionAuthorityRequest,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<AgentSessionAuthorityOutcome> {
    let source = sql_query("SELECT e.envelope,c.commit_json,a.requested_scope,EXISTS(SELECT 1 FROM agent_key_current_results k CROSS JOIN LATERAL jsonb_array_elements(k.value->'authorizations') d WHERE k.realm_id=a.principal_control_realm_id AND d->>'tag_id'=$3||':1' AND d->'value'=e.envelope->'payload') AS active FROM agent_principals a JOIN agent_status_current_results s ON s.realm_id=a.principal_control_realm_id AND s.agent_id=a.id JOIN canonical_events e ON e.envelope->>'event_id'=$3 AND e.state='committed' JOIN realm_commits c ON c.event_pk=e.pk AND c.realm_id=a.principal_control_realm_id WHERE a.id=$1 AND a.controller_principal_id=$2 AND s.value='\"active\"'::jsonb")
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
    let (_, provision_payload, provision_ref) =
        crate::agent_provisioning::declared_agent_provision_snapshot_in_connection(
            conn,
            &event.realm_id,
        )
        .await
        .map_err(crate::PgTransactionError::into_persistence)?
        .ok_or_else(|| unavailable("accepted immutable provision is absent"))?;
    let accepted = crate::committed_disclosure::accepted_full_event_in_connection(
        conn,
        &provision_ref.event_id,
    )
    .await?
    .ok_or_else(|| unavailable("accepted provision envelope is absent"))?;
    provision_payload
        .validate_envelope(&accepted.event)
        .map_err(unavailable)?;
    if provision_payload.agent_id != request.agent_account_id.principal_id
        || provision_payload.controller_principal_id != request.controller_account_id.principal_id
        || accepted.event.actor_id != ActorId::account(request.controller_account_id.clone())
        || arkret_models_collaboration::agent_scope::agent_requested_scope_digest(
            &request.agent_account_id.principal_id,
            &request.controller_account_id.principal_id,
            &provision,
        )
        .map_err(unavailable)?
            != provision_payload.requested_scope_digest
    {
        return Err(unavailable(
            "private provision ceiling differs from its accepted commitment",
        ));
    }

    if !arkret_models_collaboration::agent_scope::agent_key_scope_within_provision(
        &provision,
        &key.agent_key_scope,
    ) {
        return Err(unavailable("key exceeds its immutable provision ceiling"));
    }

    if request.agent_account_id.station_id != request.controller_account_id.station_id
        || request.requested_scope.is_empty()
        || request
            .requested_scope
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != request.requested_scope.len()
    {
        return Err(unavailable("session source request binding is invalid"));
    }
    let target = content_target(conn, request).await?;
    let realm = &target.realm;
    let purpose = crate::account_stream_scan::realm_purpose(conn, realm).await?;
    use arkret_models_collaboration::events_payloads::realm::RealmPurpose;
    let direct = match purpose {
        Some(RealmPurpose::Collaboration) => false,
        Some(RealmPurpose::DirectConversation)
            if matches!(target.scope, ScopeRef::Realm { .. }) =>
        {
            true
        }
        _ => {
            return Err(unavailable(
                "resource requires its dedicated profile authority",
            ));
        }
    };
    let actor = ActorId::account(request.agent_account_id.clone());
    let cut =
        crate::realm_authorization_cut::RealmAuthorizationCut::read(conn, realm, &actor).await?;
    let authorization = cut
        .bounded_actor_authorization_in_connection(conn, at)
        .await?;
    let evidence_grants = request
        .approval_evidence_refs
        .iter()
        .map(arkret_wire::GrantId::from_event_id)
        .collect::<BTreeSet<_>>();
    if request.approval_evidence_refs.len() > 32
        || request
            .approval_evidence_refs
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        return Ok(empty(request));
    }
    for reference in &request.approval_evidence_refs {
        let Some(accepted) =
            crate::committed_disclosure::accepted_full_event_in_connection(conn, reference).await?
        else {
            return Ok(empty(request));
        };
        if accepted.event.kind != arkret_wire::EventKind::CapabilityGrant
            || accepted.event.actor_id != ActorId::account(request.controller_account_id.clone())
            || accepted.event.executed_by.is_some()
            || accepted.event.realm_id != target.realm
            || !authorization.grants.iter().any(|row| {
                row.grant.id == arkret_wire::GrantId::from_event_id(reference)
                    && row.grant.issuer_id == accepted.event.actor_id
                    && matches!(&row.grant.subject, arkret_models_collaboration::governance::grant_constraint::CapabilitySubject::Actor(subject) if subject == &actor)
            })
        {
            return Ok(empty(request));
        }
    }
    if !direct
        && authorization.agent_ceiling.as_ref().is_none_or(|ceiling| {
            ceiling.controller.actor != ActorId::account(request.controller_account_id.clone())
        })
    {
        return Err(unavailable(
            "current controller/membership backing is unavailable",
        ));
    }
    let can_read = read_source(conn, request, &target, direct).await?;
    let direct_write = if direct && can_read {
        let bound = crate::direct_conversation_admission::binding_current_snapshot_in_connection(
            conn, realm,
        )
        .await?
        .is_some();
        bound && sql_query("SELECT EXISTS(SELECT 1 FROM direct_conversation_group_states WHERE realm_id=$1 AND current_exact_pair) AS present")
            .bind::<Text,_>(realm.as_str()).get_result::<crate::query_rows::ExistsRow>(&mut *conn).await.map_err(PersistenceError::database)?.present
    } else {
        false
    };

    let circle = match &target.scope {
        ScopeRef::Circle { circle_id, .. } => Some(circle_id),
        _ => None,
    };
    let policies = if direct {
        Vec::new()
    } else {
        crate::policy_current_results::read_scoped_agent_management_policy_snapshot_in_connection(
            conn, realm, circle,
        )
        .await?
    };
    let resources =
        crate::agent_management_admission::selector_content_resources(realm, &target.resource)?;
    let mut participation =
        arkret_models_collaboration::governance::agent_participation::ParticipationBits::ALL;
    let mut scopes = vec![format!("realm:{realm}")];
    if let Some(circle) = circle {
        scopes.push(format!("circle:{realm}:{circle}"));
    }
    if let Some(strand) = &target.resource.strand_id {
        scopes.push(format!("strand:{realm}:{strand}"));
    }
    let private_selection = if !direct {
        crate::agent_participation_admission::selection_snapshot(
            conn,
            request.agent_account_id.principal_id.as_str(),
            &scopes,
        )
        .await?
    } else {
        None
    };
    if !direct {
        for scope in scopes {
            if let Some(component) =
                crate::agent_participation_admission::governance_component_snapshot(
                    conn,
                    realm.as_str(),
                    &scope,
                )
                .await?
            {
                participation = participation.intersect(component);
            }
        }
    }

    let mut grant_refs = BTreeSet::new();
    let tracks: Vec<_> = if request.resource_scope.track_names.is_empty() {
        vec![None]
    } else {
        request
            .resource_scope
            .track_names
            .iter()
            .map(|track| Some(track.to_string()))
            .collect()
    };
    let mut granted_scope = Vec::new();
    let mut approvable_scope = BTreeSet::new();
    'action: for action in &request.requested_scope {
        if arkret_wire::ServiceOperationId::from_wire(action).is_some() {
            if key.agent_key_scope.actions.contains(action) && provision.actions.contains(action) {
                granted_scope.push(action.clone());
            }
            continue;
        }
        let Some(action_id) = CapabilityActionId::from_wire(action) else {
            continue 'action;
        };
        if !match action_id {
            CapabilityActionId::MessageCreate => participation.reply_message,
            CapabilityActionId::ReactionAdd => participation.reaction_add,
            CapabilityActionId::ReactionRemove => participation.reaction_remove,
            _ => true,
        } {
            continue 'action;
        }
        let actions = [action.as_str()];
        let read = membership_read(action);
        if read && !can_read {
            continue 'action;
        }
        if !direct {
            let effect = arkret_policy::agent_management::evaluate_agent_management(
                Some(&policies), &arkret_policy::agent_management::AgentManagementContext {
                    realm_id: realm, ownership: Some((&request.controller_account_id, &request.agent_account_id)),
                    operation: if membership_read(action) {
                        arkret_models_collaboration::governance::operation_wire::AgentPolicyOperation::Read
                    } else {
                        arkret_models_collaboration::governance::operation_wire::AgentPolicyOperation::Execute
                    },
                    content_action: Some(action_id), resources: Some(&resources), at,
                }).map_err(unavailable)?;
            if effect != arkret_wire::PolicyEffect::Allow {
                continue 'action;
            }
        }
        let mut action_refs = BTreeSet::new();
        let mut action_requires_approval = false;
        let profile_write = direct_write
            && crate::direct_conversation_admission::participant_session_action(action);
        for track in &tracks {
            let facts = coland_storage::OperationFacts {
                strand_id: target.resource.strand_id.as_ref().map(ToString::to_string),
                circle_id: circle.map(ToString::to_string),
                track: track.clone(),
                object_kind: (action == "ak.message.create").then(|| "message".to_owned()),
                ..Default::default()
            };
            let operation = coland_storage::AuthorizationOperation {
                actor: &actor,
                actions: &actions,
                target: &target.resource,
                at,
                facts: &facts,
            };
            if crate::agent_management_admission::require_key_scope_content_ceiling(
                &key.agent_key_scope,
                &operation,
            )
            .is_err()
                || crate::agent_management_admission::require_key_scope_content_ceiling(
                    &provision, &operation,
                )
                .is_err()
            {
                continue 'action;
            }
            // Membership/profile reads are independent sources, but matching
            // global refusals apply to both Agent and controller at this cut.
            if read || profile_write {
                if coland_storage::evaluate_grants(
                    &operation,
                    authorization.grants.iter().map(|row| &row.grant),
                )
                .is_refusal()
                    || authorization.agent_ceiling.as_ref().is_some_and(|ceiling| {
                        coland_storage::evaluate_grants(
                            &coland_storage::AuthorizationOperation {
                                actor: &ceiling.controller.actor,
                                ..operation
                            },
                            ceiling.controller.grants.iter().map(|row| &row.grant),
                        )
                        .is_refusal()
                    })
                {
                    continue 'action;
                }
                continue;
            }
            // A profile read does not manufacture any write authority.
            if direct || matches!(target.scope, ScopeRef::Sidecar { .. }) {
                continue 'action;
            }
            match authorization.evaluate(&actions, &target.resource, &facts) {
                coland_storage::GrantEvaluation::Allowed(_) => {}
                coland_storage::GrantEvaluation::Unnamed
                    if evidence_grants.is_empty()
                        && matches!(
                            action_id,
                            CapabilityActionId::MessageCreate
                                | CapabilityActionId::MessageRedactOwn
                                | CapabilityActionId::MessageReviseOwn
                                | CapabilityActionId::ReactionAdd
                                | CapabilityActionId::ReactionRemove
                        )
                        && can_read
                        && private_selection
                            .as_ref()
                            .is_some_and(|selected| match action_id {
                                CapabilityActionId::MessageCreate => selected.reply_message,
                                CapabilityActionId::ReactionAdd => selected.reaction_add,
                                CapabilityActionId::ReactionRemove => selected.reaction_remove,
                                _ => false,
                            }) =>
                {
                    let Some(ceiling) = authorization.agent_ceiling.as_ref() else {
                        continue 'action;
                    };
                    let controller = &ceiling.controller;
                    let controller_verdict =
                        controller.evaluate(&actions, &target.resource, &facts);
                    let owner_covers = controller.root_controller
                        && arkret_policy::owner_may_author_action(action).unwrap_or(false)
                        && !controller_verdict.is_refusal();
                    let management = arkret_policy::agent_management::evaluate_agent_management(
                        Some(&policies), &arkret_policy::agent_management::AgentManagementContext {
                            realm_id: realm, ownership: Some((&request.controller_account_id, &request.agent_account_id)),
                            operation: arkret_models_collaboration::governance::operation_wire::AgentPolicyOperation::Authorize,
                            content_action: Some(action_id), resources: Some(&resources), at,
                        }).map_err(unavailable)?;
                    if management != arkret_wire::PolicyEffect::Allow
                        || !(owner_covers
                            || matches!(
                                controller_verdict,
                                coland_storage::GrantEvaluation::Allowed(_)
                            ))
                        || matches!(
                            action_id,
                            CapabilityActionId::MessageRedactOwn
                                | CapabilityActionId::MessageReviseOwn
                        ) && facts.target_owner.is_none()
                    {
                        continue 'action;
                    }
                    action_requires_approval = true;
                    continue;
                }
                _ => continue 'action,
            }
            let Some(chosen) = authorization.grants.iter().find(|row| {
                (evidence_grants.is_empty() || evidence_grants.contains(&row.grant.id))
                    && coland_storage::grant_names_target(&row.grant, &actions, &target.resource)
                    && matches!(
                        coland_storage::evaluate_grants(&operation, std::iter::once(&row.grant)),
                        coland_storage::GrantEvaluation::Allowed(_)
                    )
            }) else {
                continue 'action;
            };
            action_refs.insert(chosen.grant.id.clone());
        }
        if action_requires_approval {
            approvable_scope.insert(action.clone());
            continue 'action;
        }
        grant_refs.extend(action_refs);
        granted_scope.push(action.clone());
    }
    if request
        .requested_scope
        .iter()
        .any(|action| arkret_wire::ServiceOperationId::from_wire(action).is_none())
        && granted_scope
            .iter()
            .all(|action| arkret_wire::ServiceOperationId::from_wire(action).is_some())
    {
        let mut outcome = empty(request);
        outcome.approval_required = !approvable_scope.is_empty()
            && request
                .requested_scope
                .iter()
                .filter(|action| arkret_wire::ServiceOperationId::from_wire(action).is_none())
                .all(|action| approvable_scope.contains(action));
        return Ok(outcome);
    }
    if !evidence_grants.is_subset(&grant_refs) {
        return Ok(empty(request));
    }
    let mut selected: AgentKeyScope = serde_json::from_value(serde_json::json!({
        "actions":granted_scope,"resources":key.agent_key_scope.resources,
        "constraints":key.agent_key_scope.constraints,
    }))
    .map_err(unavailable)?;
    selected.resources.retain(|entry|entry.kind==arkret_models_collaboration::events_payloads::agent::AgentKeyScopeResourceKind::Operation);
    selected.resources.push(
        serde_json::from_value(match &target.resource.strand_id {
            Some(strand) => {
                serde_json::json!({"kind":"strand","realm_id":realm,"resource_ref":strand})
            }
            None => serde_json::json!({"kind":"realm","realm_id":realm}),
        })
        .map_err(unavailable)?,
    );
    if !arkret_models_collaboration::agent_scope::agent_key_scope_within_provision(
        &key.agent_key_scope,
        &selected,
    ) {
        return Ok(empty(request));
    }
    Ok(AgentSessionAuthorityOutcome {
        binding: request.clone(),
        granted_scope,
        approval_required: false,
        realm_ids: request.resource_scope.realm_ids.clone(),
        strand_ids: request.resource_scope.strand_ids.clone(),
        allowed_tracks: request
            .resource_scope
            .track_names
            .iter()
            .map(ToString::to_string)
            .collect(),
        allowed_data_labels: Vec::new(),
        allowed_endpoints: Vec::new(),
        capability_grant_refs: grant_refs.into_iter().collect(),
        policy_refs: policies
            .iter()
            .map(|policy| policy.id.to_string())
            .collect(),
    })
}

fn empty(request: &AgentSessionAuthorityRequest) -> AgentSessionAuthorityOutcome {
    AgentSessionAuthorityOutcome {
        binding: request.clone(),
        granted_scope: Vec::new(),
        approval_required: false,
        realm_ids: Vec::new(),
        strand_ids: Vec::new(),
        allowed_tracks: Vec::new(),
        allowed_data_labels: Vec::new(),
        allowed_endpoints: Vec::new(),
        capability_grant_refs: Vec::new(),
        policy_refs: Vec::new(),
    }
}
