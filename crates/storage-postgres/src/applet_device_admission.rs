//! Native managed Device business gates at the accepting, locked PCR/Realm cut.
use arkret_models_collaboration::governance::grant_constraint::{
    CapabilitySubject, GrantConstraintEffect, GrantConstraintKind, GrantConstraintSubkind,
};
use arkret_models_collaboration::governance::membership_invite::{
    MembershipPayload, MembershipPayloadState,
};
use arkret_models_collaboration::governance::operation_wire::{
    AppletPolicyOperation, PolicyResourceKind, PolicyResourceSelector,
};
use arkret_wire::{ActorId, CapabilityActionId, Event, EventKind, GrantId, PolicyEffect, ScopeRef};
use coland_storage::{AppletManagedDeviceScopeGuard, PersistenceError, PersistenceResult};
use diesel::sql_types::{Jsonb, Text};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::{Value, json};

use crate::capability_grant_current_results::{CapabilityGrantCurrentResultReadRow, decode_row};

fn denied(detail: &str) -> PersistenceError {
    PersistenceError::Conflict(format!("capability_denied: {detail}"))
}
#[derive(QueryableByName)]
struct JsonRow {
    #[diesel(sql_type=Jsonb)]
    value: Value,
}

/// The actual domain action, never a union of alternative membership actions.
pub(crate) fn action(event: &Event) -> PersistenceResult<CapabilityActionId> {
    if event.executed_by.is_none() && event.kind == EventKind::MessageCreate {
        return Ok(CapabilityActionId::MessageCreate);
    }
    if event.executed_by.is_none()
        && matches!(
            event.kind,
            EventKind::ProfileCreate | EventKind::ProfileUpdate
        )
    {
        return Ok(CapabilityActionId::AppletPublish);
    }
    if event.kind != EventKind::MemberState || event.executed_by.is_some() {
        return Err(denied("native Event has no implemented business consumer"));
    }
    let payload: MembershipPayload = serde_json::from_value(json!(&event.payload))
        .map_err(|e| PersistenceError::SchemaViolation(e.to_string()))?;
    if payload.member_id != event.actor_id
        || payload.membership != MembershipPayloadState::Join
        || payload.agent_controller_binding.is_some()
        || payload.membership_cause.is_some()
        || payload.invite_ref.is_some()
        || payload.strand_id.is_some()
        || payload
            .realm_id
            .as_ref()
            .is_some_and(|realm| realm != &event.realm_id)
        || !matches!(&event.scope_ref, ScopeRef::Realm {realm_id} if realm_id == &event.realm_id)
    {
        return Err(denied(
            "Applet join must retain its own Account and actual Realm",
        ));
    }
    Ok(CapabilityActionId::AppletJoin)
}

pub(crate) async fn installation(
    conn: &mut AsyncPgConnection,
    event: &Event,
    guard: &AppletManagedDeviceScopeGuard,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<(arkret_models_integration::AppletRegistrationPayload, Value)> {
    let authority = &guard.authority;
    let actual_action = action(event)?;
    let encrypted=sql_query("SELECT to_jsonb(EXISTS(SELECT 1 FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE e.state='committed' AND e.kind='ak.mls.genesis' AND c.realm_id=$1 AND e.envelope->'scope_ref'=$2)) AS value")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Jsonb,_>(json!(event.scope_ref)).get_result::<JsonRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    if event.kind == EventKind::MemberState && encrypted.value.as_bool() != Some(false) {
        return Err(PersistenceError::Conflict("applet_e2ee_join_unauthorized: independent Applet MLS join consent is not established at this cut".into()));
    }

    if event.actor_id != ActorId::account(authority.account_id.clone())
        || event.applet_id.as_ref() != Some(&authority.applet_id)
        || event.scope_ref != guard.effective_scope
    {
        return Err(denied("native Event differs from its authenticated scope"));
    }
    installation_for_device(
        conn,
        authority,
        &guard.effective_scope,
        &guard.service_did_document,
        &[actual_action],
        at,
        true,
    )
    .await
}

/// Current exact installation and accepted native identity, independent of an
/// Event carrier. Read callers must derive `scope` from the real target bytes.
pub(crate) async fn installation_for_device(
    conn: &mut AsyncPgConnection,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    scope: &ScopeRef,
    service_did_document: &arkret_identity::DidDocument,
    actions: &[CapabilityActionId],
    at: chrono::DateTime<chrono::Utc>,
    writer: bool,
) -> PersistenceResult<(arkret_models_integration::AppletRegistrationPayload, Value)> {
    if !matches!(scope, ScopeRef::Realm { .. } | ScopeRef::Circle { .. })
        || !authority.scopes.permits(scope, actions)
    {
        return Err(denied("native resource exceeds its original Device pair"));
    }
    let registration = crate::managed_message_actor::registration_for_scope(
        conn,
        scope.realm_id(),
        &authority.applet_id,
    )
    .await?;
    if registration.service_id != authority.source_service_id {
        return Err(denied(
            "native provision Service differs from current registration",
        ));
    }
    registration
        .manifest
        .registration_epoch_evidence
        .validate_against_did_document(service_did_document)
        .map_err(|_| {
            denied("current Service document does not bind the accepted registration epoch")
        })?;
    let key = coland_storage::applet_effective_scope_key(scope)?;
    let locking = if writer {
        "FOR UPDATE OF i,m"
    } else {
        "FOR SHARE OF i,m NOWAIT"
    };
    let query = format!(
        "SELECT i.record AS value FROM applet_installations i JOIN applet_registration_current_results r ON r.realm_id=$3 AND r.applet_id=i.applet_id JOIN applet_registration_instances a ON a.realm_id=r.realm_id AND a.applet_id=r.applet_id AND a.instance_event_ref=r.instance_event_ref AND a.registration_event_ref=i.record#>>'{{registration_event,event_id}}' JOIN applet_managed_identities m ON m.applet_id=i.applet_id AND m.target_station_id=$4 WHERE i.applet_id=$1 AND i.effective_scope_key=$2 AND m.record->>'globally_fenced_at' IS NULL {locking}"
    );
    let row = sql_query(query)
        .bind::<Text, _>(authority.applet_id.as_str())
        .bind::<Text, _>(key)
        .bind::<Text, _>(scope.realm_id().as_str())
        .bind::<Text, _>(authority.account_id.station_id.as_str())
        .get_result::<JsonRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .ok_or_else(|| denied("native Applet exact installation is absent or fenced"))?;
    if row.value["effective_scope"] != json!(scope)
        || row.value["package"]["registration_epoch"] != json!(registration.registration_epoch)
        || row.value.get("revoked_at").is_some_and(|v| !v.is_null())
        || !matches!(
            row.value["status"].as_str(),
            Some("installed" | "partially_installed")
        )
    {
        return Err(denied("native Applet exact installation is inactive"));
    }
    crate::managed_message_actor::require_managed_identity_in_connection(
        conn,
        &ActorId::account(authority.account_id.clone()),
        &authority.applet_id,
        &registration,
        at,
    )
    .await?;
    Ok((registration, row.value))
}

/// Subject-only metadata binds an active accepted installation grant. It never
/// spends a fabricated join capability or lets a Service sign the consent.
pub(crate) async fn require_installation_binding(
    conn: &mut AsyncPgConnection,
    event: &Event,
    guard: &AppletManagedDeviceScopeGuard,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    let (registration, installation) = installation(conn, event, guard, at).await?;
    let service = ActorId::service(registration.service_id.clone());
    let id: GrantId = event
        .authorization_ref
        .as_ref()
        .ok_or_else(|| denied("subject-only Applet action has no installation grant"))?
        .as_str()
        .parse()
        .map_err(|_| denied("Applet installation grant selector is invalid"))?;
    let installed = installation
        .get("capability_grant_events")
        .and_then(Value::as_array)
        .ok_or_else(|| denied("exact installation grant originals are absent"))?;
    let source = installed
        .iter()
        .find(|source| {
            source
                .get("event_id")
                .and_then(Value::as_str)
                .and_then(|id| id.parse::<arkret_wire::EventId>().ok())
                .map(|id| GrantId::from_event_id(&id))
                .as_ref()
                == Some(&id)
        })
        .ok_or_else(|| denied("subject-only action reference is outside its exact installation"))?;
    let rows=sql_query("SELECT realm_id,grant_id,status,current_event_id,current_commit_id,current_stream_ref,current_stream_position,value FROM capability_grant_current_results WHERE realm_id=$1 ORDER BY grant_id FOR SHARE")
        .bind::<Text,_>(event.realm_id.as_str()).load::<CapabilityGrantCurrentResultReadRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let mut grants = std::collections::BTreeMap::new();
    for row in rows {
        let row = decode_row(row)?;
        grants.insert(row.grant_id, row.value);
    }
    let grant = grants.get(&id).ok_or_else(|| {
        PersistenceError::Conflict(
            "revision_unavailable: accepted installation grant current is unavailable".into(),
        )
    })?;
    if !matches!(&grant.subject,CapabilitySubject::Actor(actor) if actor==&service)
        || !crate::capability_grant_current_results::grant_is_active_at(grant, at)
        || source["actor_id"] != json!(grant.issuer_id)
    {
        return Err(denied(
            "subject-only action installation grant is not active for its exact Service",
        ));
    }
    let bindings = grant
        .constraints
        .iter()
        .filter(|c| c.constraint_subkind == Some(GrantConstraintSubkind::AppletAuthority))
        .collect::<Vec<_>>();
    let [binding] = bindings.as_slice() else {
        return Err(denied("installation Applet binding is not unique"));
    };
    if binding.constraint_kind != GrantConstraintKind::AuthorityControl
        || binding.effect != GrantConstraintEffect::Allow
        || binding.evaluation_class != Some(arkret_wire::EvaluationClass::GrantLocal)
        || binding.applet_id.as_ref() != Some(&registration.applet_id)
        || binding.registration_epoch.as_ref() != Some(&registration.registration_epoch)
        || binding.executed_by.as_ref() != Some(&service)
    {
        return Err(denied("subject-only action installation authority differs"));
    }
    let root=sql_query("SELECT realm_id,controller_actor_id,controller_epoch,authority_generation,authority_event_ref FROM realm_authority_root_current_results WHERE realm_id=$1")
        .bind::<Text,_>(event.realm_id.as_str()).get_result::<crate::capability_grant_current_results::RealmAuthorityRootReadRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    crate::capability_grant_current_results::validate_ancestor_graph(
        &GrantId::from_event_id(&event.event_id),
        &id,
        &grants,
        &crate::capability_grant_current_results::decode_authority_root(root)?,
        &event.realm_id,
        at,
        &mut std::collections::BTreeSet::new(),
        0,
    )?;
    Ok(())
}

pub(crate) async fn select_management(
    conn: &mut AsyncPgConnection,
    event: &Event,
    registration: &arkret_models_integration::AppletRegistrationPayload,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<(
    Vec<arkret_models_collaboration::governance::operation_wire::Policy>,
    arkret_policy::applet_management::AppletManagementDecision,
)> {
    let operation = match event.kind {
        EventKind::MemberState => AppletPolicyOperation::Join,
        EventKind::MessageCreate => AppletPolicyOperation::Execute,
        _ => AppletPolicyOperation::Publish,
    };
    let circle = match &event.scope_ref {
        ScopeRef::Circle { circle_id, .. } => Some(circle_id),
        _ => None,
    };
    let service = ActorId::service(registration.service_id.clone());
    // A complete authoritative read is mandatory even when no Policy exists.
    let policies =
        crate::policy_current_results::read_scoped_applet_management_policies_in_connection(
            conn,
            &event.realm_id,
            circle,
        )
        .await?;
    let mut resources = crate::agent_management_admission::event_content_resources(event)?;
    if let Some(circle) = circle {
        resources.push(PolicyResourceSelector {
            kind: PolicyResourceKind::Object,
            realm_id: Some(event.realm_id.clone()),
            resource_ref: Some(circle.to_string()),
        });
    }
    let decision = arkret_policy::applet_management::select_applet_management(
        Some(&policies),
        &arkret_policy::applet_management::AppletManagementContext {
            realm_id: &event.realm_id,
            requester_actor_id: &service,
            applet_id: &registration.applet_id,
            effective_scope: &event.scope_ref,
            managed_actor_id: Some(&event.actor_id),
            operation,
            content_action: (operation == AppletPolicyOperation::Execute)
                .then_some(CapabilityActionId::MessageCreate),
            device_control: None,
            resources: Some(&resources),
            at,
        },
    )
    .map_err(|e| PersistenceError::SchemaViolation(e.to_string()))?;
    if matches!(
        decision.effect,
        PolicyEffect::Deny | PolicyEffect::Quarantine
    ) {
        return Err(denied(
            "current Applet management Policy rejects the native action",
        ));
    }
    Ok((policies, decision))
}

/// A native Device spends its own terminal business grant. Its Service parent
/// is evaluated separately as that Service, including the original quota key.
/// The ordinary Message unit still admits the child, governance and content.
pub(crate) async fn require_business_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    guard: &AppletManagedDeviceScopeGuard,
    commit: &arkret_wire::RealmCommit,
    prepared: Option<&coland_storage::EventApprovalCommit>,
) -> PersistenceResult<Vec<crate::approval_admission::QualifiedApproval>> {
    use arkret_models_collaboration::events_payloads::CapabilityGrantCreateBody;
    use arkret_models_collaboration::governance::grant_constraint::{
        IssuerAuthorityRef, ManagedActorRole,
    };
    if event.kind != EventKind::MessageCreate {
        return Err(denied("native business action has no domain consumer"));
    }
    let at = commit.committed_at;
    let (registration, _) = installation(conn, event, guard, at).await?;
    let service = ActorId::service(registration.service_id.clone());
    let cut = crate::boxed_future(|| {
        crate::realm_authorization_cut::RealmAuthorizationCut::read_for_event(conn, event)
    })
    .await?;
    cut.require_open_lifecycle(event)?;
    cut.require_governed_member(&event.kind)?;
    let (target, mut facts) = cut.event_operation(event);
    facts.applet_id = Some(registration.applet_id.to_string());
    facts.executed_by = Some(service.clone());
    facts.registration_epoch = Some(registration.registration_epoch.to_string());
    let id: GrantId = event
        .authorization_ref
        .as_ref()
        .ok_or_else(|| denied("native business has no terminal grant"))?
        .as_str()
        .parse()
        .map_err(PersistenceError::database)?;
    let rows=sql_query("SELECT realm_id,grant_id,status,current_event_id,current_commit_id,current_stream_ref,current_stream_position,value FROM capability_grant_current_results WHERE realm_id=$1 ORDER BY grant_id FOR SHARE")
        .bind::<Text,_>(event.realm_id.as_str()).load::<CapabilityGrantCurrentResultReadRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let mut grants = std::collections::BTreeMap::new();
    for row in rows {
        let row = decode_row(row)?;
        grants.insert(row.grant_id, row.value);
    }
    let child = grants
        .get(&id)
        .ok_or_else(|| denied("native terminal grant has no current"))?;
    if child.issuer_id != service
        || !matches!(&child.subject,CapabilitySubject::Actor(actor) if actor==&event.actor_id)
        || child.status != arkret_models_collaboration::governance::grant_constraint::CapabilityGrantStatus::Active
    {
        return Err(denied(
            "native terminal grant differs from its real subject or Service source",
        ));
    }
    let parents = child
        .issuer_authority_refs
        .iter()
        .map(|source| match source {
            IssuerAuthorityRef::Grant { grant_id } => grants
                .get(grant_id)
                .ok_or_else(|| denied("native Service source has no current")),
            _ => Err(denied(
                "native terminal child must name actual Service grants",
            )),
        })
        .collect::<PersistenceResult<Vec<_>>>()?;
    let sources=sql_query("SELECT e.envelope->'payload' AS value FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE e.state='committed' AND e.kind='ak.applet.managed_actor.provision' AND e.envelope#>'{payload,actor_id}'=$1")
        .bind::<Jsonb,_>(json!(event.actor_id)).load::<JsonRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    if sources.len() != 1 {
        return Err(denied("native business has no unique accepted provision"));
    }
    let provision: arkret_models_integration::AppletManagedActorProvisionPayload =
        serde_json::from_value(sources.into_iter().next().unwrap().value)
            .map_err(PersistenceError::database)?;
    if provision.actor_id != event.actor_id
        || provision.applet_id != registration.applet_id
        || provision.service_id != registration.service_id
    {
        return Err(denied("native business role source differs"));
    }
    let role = match provision.actor_role {
        arkret_models_integration::AppletManagedActorRole::Bot => ManagedActorRole::Bot,
        arkret_models_integration::AppletManagedActorRole::Ghost => ManagedActorRole::Ghost,
    };
    let definition = CapabilityGrantCreateBody {
        schema: child.schema.clone(),
        realm_id: child.realm_id.clone(),
        issuer_id: child.issuer_id.clone(),
        subject: child.subject.clone(),
        actions: child.actions.clone(),
        resources: child.resources.clone(),
        constraints: child.constraints.clone(),
        issuer_authority_refs: child.issuer_authority_refs.clone(),
        issued_at: child.issued_at,
    };
    crate::capability_grant_current_results::validate_managed_sources(&parents, &definition, role)?;
    let root=sql_query("SELECT realm_id,controller_actor_id,controller_epoch,authority_generation,authority_event_ref FROM realm_authority_root_current_results WHERE realm_id=$1")
        .bind::<Text,_>(event.realm_id.as_str()).get_result::<crate::capability_grant_current_results::RealmAuthorityRootReadRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let root = crate::capability_grant_current_results::decode_authority_root(root)?;
    let sources = arkret_policy::grant_authority::current_sources(
        child, CapabilityActionId::MessageCreate.as_str(), &target, &grants, at,
        |source| matches!(source, IssuerAuthorityRef::RealmRoot { realm_id, authority_event_ref, authority_generation }
            if realm_id==&event.realm_id && authority_event_ref==&root.authority_event_ref
                && authority_generation==&root.authority_generation),
    ).map_err(|error| PersistenceError::Conflict(error.to_string()))?;
    let actions = [CapabilityActionId::MessageCreate.as_str()];
    let mut accepted = Vec::new();
    let mut reservations = Vec::new();
    let mut actors = std::collections::BTreeSet::from([service.clone()]);
    for source in &sources {
        if let CapabilitySubject::Actor(actor) = &source.subject {
            actors.insert(actor.clone());
        }
    }
    for actor in actors {
        let matching=arkret_policy::grant_authority::current_subject_grants(
            &actor,actions[0],&target,&grants,at,
            |source|matches!(source,IssuerAuthorityRef::RealmRoot{realm_id,authority_event_ref,authority_generation}
                if realm_id==&event.realm_id && authority_event_ref==&root.authority_event_ref
                    && authority_generation==&root.authority_generation),
        ).map_err(|error|PersistenceError::Conflict(error.to_string()))?;
        let mut source_facts = facts.clone();
        source_facts.executed_by = Some(actor.clone());
        accepted.extend(
            crate::boxed_future(|| {
                crate::managed_message_actor::require_source_global_refusals(
                    conn,
                    event,
                    commit,
                    prepared,
                    &matching,
                    &actor,
                    &actions,
                    &target,
                    &source_facts,
                )
            })
            .await?,
        );
    }
    for source in sources {
        let CapabilitySubject::Actor(actor) = &source.subject else {
            return Err(denied(
                "native ancestor source has no complete Actor subject",
            ));
        };
        let mut source_facts = facts.clone();
        source_facts.executed_by = Some(actor.clone());
        let (approvals, quota) = crate::boxed_future(|| {
            crate::managed_message_actor::evaluate_producer_grant(
                conn,
                event,
                commit,
                prepared,
                source,
                actor,
                &actions,
                &target,
                &source_facts,
                true,
            )
        })
        .await?;
        accepted.extend(approvals);
        reservations.extend(quota);
    }
    if !crate::capability_quota::try_reserve_in_connection(
        conn,
        &reservations,
        event.event_id.as_str(),
    )
    .await?
    {
        return Err(PersistenceError::Conflict(
            "rate_limited: Applet ancestor quota is exhausted".into(),
        ));
    }
    Ok(accepted)
}
