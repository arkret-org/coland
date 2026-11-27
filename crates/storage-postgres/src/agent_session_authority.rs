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
            let row = sql_query("SELECT p.value,c.commit_json FROM strand_current_states p JOIN realm_commits c ON c.commit_id=p.current_commit_id AND c.realm_id=p.realm_id AND c.stream_position=p.current_stream_position JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' WHERE p.strand_id=$1")
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
            // A known request shape cannot be represented safely by this
            // flat ceiling. Narrow to no content authority, not a dependency fault.
            return Err(PersistenceError::Conflict(format!(
                "{}: content ceiling requires one exact Realm or Strand selector",
                coland_storage::ConflictCode::CapabilityDenied.as_str(),
            )));
        }
    };
    Ok(ContentTarget {
        realm,
        scope,
        resource,
    })
}

pub(crate) fn membership_read(action: &str) -> bool {
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
            binding.binding.validate_shape().map_err(unavailable)?;
            if binding.binding.realm_id != target.realm
                || !binding.binding.unordered_participant_ids.contains(&actor)
            {
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
) -> PersistenceResult<AgentSessionAuthorityView> {
    match read_at_cut(conn, request, at).await {
        Err(error)
            if error.conflict_code() == Some(coland_storage::ConflictCode::CapabilityDenied) =>
        {
            // A verified current refusal is a bound empty ceiling. Missing or
            // corrupt source dependencies remain errors for the issuer.
            Ok(empty(request))
        }
        outcome => outcome,
    }
}

async fn bound_native_key_scope(
    conn: &mut AsyncPgConnection,
    agent: &arkret_wire::AccountId,
    controller: &arkret_wire::AccountId,
    authorization: &arkret_wire::EventId,
    method: &arkret_wire::DidUrl,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<(AgentKeyAuthorizePayload, AgentKeyScope)> {
    let source = sql_query("SELECT e.envelope,c.commit_json,a.requested_scope,EXISTS(SELECT 1 FROM agent_key_current_states k CROSS JOIN LATERAL jsonb_array_elements(k.value->'authorizations') d WHERE k.realm_id=a.principal_control_realm_id AND d->>'tag_id'=$3||':1' AND d->'value'=e.envelope->'payload') AS active FROM agent_principals a JOIN agent_status_current_states s ON s.realm_id=a.principal_control_realm_id AND s.agent_id=a.id JOIN canonical_events e ON e.envelope->>'event_id'=$3 AND e.state='committed' JOIN realm_commits c ON c.event_pk=e.pk AND c.realm_id=a.principal_control_realm_id WHERE a.id=$1 AND a.controller_principal_id=$2 AND a.requested_scope IS NOT NULL AND s.value='\"active\"'::jsonb")
        .bind::<Text,_>(agent.principal_id.as_str())
        .bind::<Text,_>(controller.principal_id.as_str())
        .bind::<Text,_>(authorization.as_str())
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
        || event.event_id != *authorization
        || commit.event_ref != event.event_id
        || commit.realm_id != event.realm_id
        || event.actor_id != ActorId::account(agent.clone())
        || event.executed_by != Some(ActorId::account(controller.clone()))
        || key.verification_method != *method
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
    if provision_payload.agent_id != agent.principal_id
        || provision_payload.controller_principal_id != controller.principal_id
        || accepted.event.actor_id != ActorId::account(controller.clone())
        || arkret_models_collaboration::agent_scope::agent_requested_scope_digest(
            &agent.principal_id,
            &controller.principal_id,
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

    if agent.station_id != controller.station_id {
        return Err(unavailable("controller Station differs"));
    }
    Ok((key, provision))
}

async fn native_key_scope(
    conn: &mut AsyncPgConnection,
    request: &AgentSessionAuthorityRequest,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<(AgentKeyAuthorizePayload, AgentKeyScope)> {
    if request.requested_scope.is_empty()
        || request
            .requested_scope
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != request.requested_scope.len()
    {
        return Err(unavailable("session source request binding is invalid"));
    }
    bound_native_key_scope(
        conn,
        &request.agent_account_id,
        &request.controller_account_id,
        &request.agent_key_authorization_ref,
        &request.verification_method,
        at,
    )
    .await
}

pub(crate) async fn require_forwarded_message_source(
    conn: &mut AsyncPgConnection,
    event: &Event,
    evidence: &arkret_models_identity::AgentProducerEvidence,
    session: &arkret_models_identity::SessionGrantMetadata,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    let verified = arkret_identity::agent_authority_evidence::verify_forwarded_agent_producer(
        event,
        evidence,
        &session.account_id.station_id,
        at,
        None,
    )
    .map_err(unavailable)?;
    let state = verified
        .evidence()
        .agent_authority_state_evidence
        .state
        .as_ref()
        .ok_or_else(|| unavailable("missing Agent authority"))?;
    let scope = session
        .scope_details
        .as_ref()
        .ok_or_else(|| unavailable("missing session scope"))?;
    if verified.account() != &session.account_id
        || scope.controller_principal_id != state.authorization.controller_principal_id
        || scope.agent_key_authorization_ref != state.key_authorization_event.event_id
        || at >= session.expires_at
    {
        return Err(PersistenceError::Conflict(
            "capability_denied: session differs from the exact signed message".into(),
        ));
    }
    crate::agent_origin::check_origin_cut(conn, event, state).await?;
    let controller = arkret_wire::AccountId::new(
        scope.controller_principal_id.clone(),
        session.account_id.station_id.clone(),
    );
    crate::agent_interaction_current_states::owned_provenance_in_connection(
        conn,
        &session.account_id,
        &controller,
        at,
        true,
    )
    .await?
    .ok_or_else(|| {
        PersistenceError::Conflict("capability_denied: Agent ownership is no longer current".into())
    })?;
    let (key, provision) = bound_native_key_scope(
        conn,
        &session.account_id,
        &controller,
        &scope.agent_key_authorization_ref,
        &state.authorization.verification_method,
        at,
    )
    .await?;
    let strand = event
        .payload
        .get("strand_id")
        .and_then(Value::as_str)
        .ok_or_else(|| unavailable("missing message Strand"))?
        .parse::<arkret_wire::StrandId>()
        .map_err(unavailable)?;
    let mut scopes = vec![format!("realm:{}", event.realm_id)];
    if let Some(circle) = event.scope_ref.circle_id() {
        scopes.push(format!("circle:{}:{circle}", event.realm_id));
    }
    scopes.push(format!("strand:{}:{strand}", event.realm_id));
    let agent = session.account_id.principal_id.as_str();
    crate::agent_participation_admission::lock_selection(conn, agent, true).await?;
    if !crate::agent_participation_admission::selection_snapshot(conn, agent, &scopes)
        .await?
        .is_some_and(|selection| selection.message_creation_allowed)
    {
        return Err(PersistenceError::Conflict(
            "failed_precondition: agent_reply_not_permitted".into(),
        ));
    }
    let target = WireResourceSelector::strand(event.realm_id.clone(), strand.clone());
    let facts = coland_storage::OperationFacts {
        strand_id: Some(strand.to_string()),
        circle_id: event.scope_ref.circle_id().map(ToString::to_string),
        track: event
            .payload
            .get("track_name")
            .and_then(Value::as_str)
            .map(str::to_owned),
        object_kind: Some("message".to_owned()),
        ..Default::default()
    };
    let operation = coland_storage::AuthorizationOperation {
        actor: &event.actor_id,
        actions: &["ak.message.create"],
        target: &target,
        at,
        facts: &facts,
    };
    crate::agent_management_admission::require_session_content_ceiling(
        &session.scopes,
        scope,
        &operation,
    )?;
    crate::agent_management_admission::require_key_scope_content_ceiling(
        &key.agent_key_scope,
        &operation,
    )?;
    crate::agent_management_admission::require_key_scope_content_ceiling(&provision, &operation)
}

pub(crate) async fn home_content_queries(
    conn: &mut AsyncPgConnection,
    request: &AgentSessionAuthorityRequest,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<Option<coland_storage::HomeContentQueries>> {
    use arkret_models_collaboration::governance::realm_join_intake::{
        OwnedAgentContentAction, OwnedAgentContentIntent,
    };
    #[derive(QueryableByName)]
    struct Governor {
        #[diesel(sql_type=Text)]
        service_id: String,
        #[diesel(sql_type=BigInt)]
        generation: i64,
    }
    let target = content_target(conn, request).await?;
    let authority =
        sql_query("SELECT service_id,generation FROM realm_authorities WHERE realm_id=$1")
            .bind::<Text, _>(target.realm.as_str())
            .get_result::<Governor>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?
            .ok_or_else(|| unavailable("target governing Station is unknown"))?;
    if authority.service_id == request.agent_account_id.station_id.as_str() {
        return Ok(None);
    }
    let (key, provision) = native_key_scope(conn, request, at).await?;
    // Use the two accepted originals held by H to name the query. Only G's
    // live decision establishes their currency for issuance.
    let pair = crate::agent_interaction_current_states::governed_join_pair(
        conn,
        &target.realm,
        &request.agent_account_id,
        at,
        false,
        None,
    )
    .await?
    .filter(|pair| pair.controller == request.controller_account_id)
    .ok_or_else(|| unavailable("bound Agent and controller join originals are unavailable"))?;
    // Only committed local ownership and lifecycle can initiate this signed disclosure.
    crate::agent_interaction_current_states::owned_provenance_in_connection(
        conn,
        &request.agent_account_id,
        &request.controller_account_id,
        at,
        false,
    )
    .await?
    .ok_or_else(|| unavailable("current Agent ownership is unavailable"))?;
    let mut scopes = vec![format!("realm:{}", target.realm)];
    if let Some(circle) = target.scope.circle_id() {
        scopes.push(format!("circle:{}:{circle}", target.realm));
    }
    if let Some(strand) = &target.resource.strand_id {
        scopes.push(format!("strand:{}:{strand}", target.realm));
    }
    let selected = crate::agent_participation_admission::selection_snapshot(
        conn,
        request.agent_account_id.principal_id.as_str(),
        &scopes,
    )
    .await?;
    let actor = ActorId::account(request.agent_account_id.clone());
    let mut service_operations = Vec::new();
    let mut intents = Vec::new();
    for name in &request.requested_scope {
        if arkret_wire::ServiceOperationId::from_wire(name).is_some() {
            if key.agent_key_scope.actions.contains(name) && provision.actions.contains(name) {
                service_operations.push(name.clone());
            }
            continue;
        }
        let Ok(action) =
            serde_json::from_value::<OwnedAgentContentAction>(Value::String(name.clone()))
        else {
            continue;
        };
        if !request.approval_evidence_refs.is_empty()
            || !request.resource_scope.track_names.is_empty()
        {
            continue;
        }
        let private_permits = match action {
            OwnedAgentContentAction::MessageCreate => selected
                .as_ref()
                .is_some_and(|v| v.message_creation_allowed),
            OwnedAgentContentAction::ReactionAdd => selected
                .as_ref()
                .is_some_and(|v| v.reaction_addition_allowed),
            OwnedAgentContentAction::ReactionRemove => selected
                .as_ref()
                .is_some_and(|v| v.reaction_removal_allowed),
            _ => true,
        };
        let actions = [name.as_str()];
        let facts = coland_storage::OperationFacts {
            strand_id: target.resource.strand_id.as_ref().map(ToString::to_string),
            circle_id: target.scope.circle_id().map(ToString::to_string),
            object_kind: (action == OwnedAgentContentAction::MessageCreate)
                .then(|| "message".to_owned()),
            ..Default::default()
        };
        let operation = coland_storage::AuthorizationOperation {
            actor: &actor,
            actions: &actions,
            target: &target.resource,
            at,
            facts: &facts,
        };
        if private_permits
            && crate::agent_management_admission::require_key_scope_content_ceiling(
                &key.agent_key_scope,
                &operation,
            )
            .is_ok()
            && crate::agent_management_admission::require_key_scope_content_ceiling(
                &provision, &operation,
            )
            .is_ok()
        {
            intents.push(OwnedAgentContentIntent {
                controller_account_id: request.controller_account_id.clone(),
                controller_membership_commit_id: pair.controller_commit.commit_id.clone(),
                agent_key_authorization_ref: request.agent_key_authorization_ref.clone(),
                action,
                effective_scope: target.scope.clone(),
                request_digest: request.intent_digest.clone(),
                strand_id: target.resource.strand_id.clone(),
            });
        }
    }
    Ok(Some(coland_storage::HomeContentQueries {
        governor: arkret_wire::DidCoreId::new(authority.service_id).map_err(unavailable)?,
        generation: u64::try_from(authority.generation).map_err(unavailable)?,
        realm: target.realm,
        membership: pair.agent_commit.commit_id,
        service_operations,
        intents,
    }))
}

async fn read_at_cut(
    conn: &mut AsyncPgConnection,
    request: &AgentSessionAuthorityRequest,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<AgentSessionAuthorityView> {
    let (key, provision) = native_key_scope(conn, request, at).await?;
    let target = content_target(conn, request).await?;
    let realm = &target.realm;
    let governed = sql_query("SELECT EXISTS(SELECT 1 FROM realm_authorities WHERE realm_id=$1 AND service_id=$2) AS present")
        .bind::<Text,_>(realm.as_str()).bind::<Text,_>(request.agent_account_id.station_id.as_str())
        .get_result::<crate::query_rows::ExistsRow>(&mut *conn).await.map_err(PersistenceError::database)?.present;
    if !governed {
        return Err(unavailable(
            "resource governance belongs to another Station",
        ));
    }
    let purpose = crate::account_stream_scan::realm_purpose(conn, realm).await?;
    use arkret_models_collaboration::events_payloads::realm::RealmPurpose;
    let personal = purpose == Some(RealmPurpose::PrincipalControl)
        && matches!(target.scope, ScopeRef::Realm { .. })
        && crate::morph_projection_reads::human_realm_in_connection(
            conn,
            &request.controller_account_id,
        )
        .await?
            == *realm;
    // This is a credential ceiling. Each private consumer still verifies its exact
    // Sidecar, accepted enrollment and current endpoint at the point of delivery.
    let mut enabled_private_read = false;
    let mut private_reply = false;
    if personal {
        let rows=sql_query("SELECT to_jsonb(sidecar_id) AS payload FROM sidecar_current_states WHERE realm_id=$1 AND controller_account_id=$2 AND value->>'state'='active' ORDER BY sidecar_id")
            .bind::<Text,_>(realm.as_str()).bind::<Jsonb,_>(serde_json::to_value(&request.controller_account_id).map_err(unavailable)?)
            .load::<crate::JsonPayloadRow>(&mut *conn).await.map_err(PersistenceError::database)?;
        for row in rows {
            let id = serde_json::from_value(row.payload).map_err(unavailable)?;
            if let Some(cut) = crate::sidecar_access::cut_in_connection(conn, realm, &id).await?
                && cut
                    .desired_agent_ids
                    .contains(&request.agent_account_id.principal_id)
            {
                enabled_private_read = true;
                private_reply |= crate::sidecar_authority_cut::enrollment(
                    conn,
                    realm,
                    &id,
                    &request.agent_account_id,
                )
                .await?
                .is_some_and(|r| r.value["private_reply_allowed"] == true);
            }
        }
    }
    let direct = match purpose {
        Some(RealmPurpose::Collaboration) => false,
        Some(RealmPurpose::PrincipalControl) if personal && enabled_private_read => false,
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
            || !authorization.current_grant_record(&arkret_wire::GrantId::from_event_id(reference)).is_some_and(|grant| {
                grant.issuer_id == accepted.event.actor_id
                    && matches!(&grant.subject, arkret_models_collaboration::governance::grant_constraint::CapabilitySubject::Actor(subject) if subject == &actor)
            })
        {
            return Ok(empty(request));
        }
    }
    if !direct
        && !personal
        && authorization.agent_ceiling.as_ref().is_none_or(|ceiling| {
            ceiling.controller.actor != ActorId::account(request.controller_account_id.clone())
        })
    {
        return Err(unavailable(
            "current controller/membership backing is unavailable",
        ));
    }
    let can_read = enabled_private_read || read_source(conn, request, &target, direct).await?;
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
        crate::policy_current_states::read_scoped_agent_management_policy_snapshot_in_connection(
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
    // Only shared project actions inherit Realm, Circle and Strand participation policy.
    let project_participation = !direct && !personal;
    let private_selection = if project_participation {
        crate::agent_participation_admission::selection_snapshot(
            conn,
            request.agent_account_id.principal_id.as_str(),
            &scopes,
        )
        .await?
    } else {
        None
    };
    if project_participation {
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
            CapabilityActionId::MessageCreate => participation.message_creation_allowed,
            CapabilityActionId::ReactionAdd => participation.reaction_addition_allowed,
            CapabilityActionId::ReactionRemove => participation.reaction_removal_allowed,
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
        let profile_write = (private_reply && action_id == CapabilityActionId::MessageCreate)
            || (direct_write
                && crate::direct_conversation_admission::participant_session_action(action));
        for track in &tracks {
            let facts = coland_storage::OperationFacts {
                strand_id: target.resource.strand_id.as_ref().map(ToString::to_string),
                circle_id: circle.map(ToString::to_string),
                track: track.clone(),
                object_kind: (action == arkret_wire::CapabilityActionId::MESSAGE_CREATE)
                    .then(|| "message".to_owned()),
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
                if authorization
                    .evaluate_with_approvals_checked(&actions, &target.resource, &facts, &[])?
                    .is_refusal()
                {
                    continue 'action;
                }
                continue;
            }
            // A profile read does not manufacture any write authority.
            if direct || matches!(target.scope, ScopeRef::Sidecar { .. }) {
                continue 'action;
            }
            let satisfied = match authorization.evaluate_with_approvals_checked(
                &actions,
                &target.resource,
                &facts,
                &[],
            )? {
                coland_storage::GrantEvaluation::Allowed(paths) => paths,
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
                                CapabilityActionId::MessageCreate => {
                                    selected.message_creation_allowed
                                }
                                CapabilityActionId::ReactionAdd => {
                                    selected.reaction_addition_allowed
                                }
                                CapabilityActionId::ReactionRemove => {
                                    selected.reaction_removal_allowed
                                }
                                _ => false,
                            }) =>
                {
                    let Some(ceiling) = authorization.agent_ceiling.as_ref() else {
                        continue 'action;
                    };
                    let controller = &ceiling.controller;
                    let controller_verdict = controller.evaluate_with_approvals_checked(
                        &actions,
                        &target.resource,
                        &facts,
                        &[],
                    )?;
                    let owner_covers = controller.root_controller()
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
            };
            let Some(chosen) = satisfied.iter().find(|path| {
                evidence_grants.is_empty() || evidence_grants.contains(&path.grant.id)
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
    Ok(AgentSessionAuthorityView {
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

fn empty(request: &AgentSessionAuthorityRequest) -> AgentSessionAuthorityView {
    AgentSessionAuthorityView {
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
