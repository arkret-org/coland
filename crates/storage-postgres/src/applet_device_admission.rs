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
use crate::managed_forward_admission::Source;

fn denied(detail: &str) -> PersistenceError {
    PersistenceError::Conflict(format!("capability_denied: {detail}"))
}
#[derive(QueryableByName)]
struct JsonRow {
    #[diesel(sql_type=Jsonb)]
    value: Value,
}

#[derive(QueryableByName)]
struct InstallationRow {
    #[diesel(sql_type=Jsonb)]
    value: Value,
    #[diesel(sql_type=diesel::sql_types::Bool)]
    globally_fenced: bool,
}

/// The actual domain action, never a union of alternative membership actions.
pub(crate) fn action(event: &Event) -> PersistenceResult<CapabilityActionId> {
    if event.executed_by.is_none() {
        match event.kind {
            EventKind::MlsGenesis => return Ok(CapabilityActionId::MlsGenesis),
            EventKind::MlsCommit => return Ok(CapabilityActionId::MlsCommit),
            _ => {}
        }
    }
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
    if event.kind == EventKind::CircleMemberState && event.executed_by.is_none() {
        let payload: arkret_models_collaboration::events_payloads::circle::CircleMemberStatePayload =
            serde_json::from_value(json!(&event.payload))
                .map_err(|e| PersistenceError::SchemaViolation(e.to_string()))?;
        if payload.member_id != event.actor_id
            || !matches!(&event.scope_ref, ScopeRef::Circle {realm_id,circle_id}
                if realm_id == &event.realm_id && circle_id == &payload.circle_id)
        {
            return Err(denied(
                "native Circle membership must retain its own Account and actual Circle",
            ));
        }
        return match payload.membership {
            arkret_models_collaboration::governance::circle::CircleMembership::Join => {
                Ok(CapabilityActionId::AppletJoin)
            }
            arkret_models_collaboration::governance::circle::CircleMembership::Leave => {
                Ok(CapabilityActionId::CircleMemberAdd)
            }
            _ => Err(denied(
                "native Circle membership has no implemented self transition",
            )),
        };
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

pub(crate) fn device_actions(event: &Event) -> PersistenceResult<Vec<CapabilityActionId>> {
    let actual = action(event)?;
    let mut actions = vec![actual];
    if event.kind == EventKind::CircleMemberState && actual == CapabilityActionId::AppletJoin {
        actions.push(CapabilityActionId::CircleMemberAdd);
    }
    Ok(actions)
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
    let mls_join = matches!(
        event.kind,
        EventKind::MemberState | EventKind::CircleMemberState
    ) && actual_action == CapabilityActionId::AppletJoin
        && encrypted.value.as_bool() != Some(false);

    if event.actor_id != ActorId::account(authority.account_id.clone())
        || event.applet_id.as_ref() != Some(&authority.applet_id)
        || event.scope_ref != guard.effective_scope
    {
        return Err(denied("native Event differs from its authenticated scope"));
    }
    let actions = device_actions(event)?;
    let installed = installation_for_device(
        conn,
        authority,
        &guard.effective_scope,
        &guard.service_did_document,
        &actions,
        at,
        true,
    )
    .await?;
    if mls_join || matches!(event.kind, EventKind::MlsGenesis | EventKind::MlsCommit) {
        crate::boxed_future(|| {
            crate::applet_e2ee::require_current_consent(
                conn,
                &installed.0,
                &installed.1,
                &guard.effective_scope,
                at,
            )
        })
        .await?;
    }
    Ok(installed)
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
    crate::boxed_future(|| {
        installation_at_scope(conn, authority, scope, service_did_document, at, writer)
    })
    .await
}

/// The registered KeyPackage control rule requires an exact original scope,
/// without pretending that an empty business-action set authorizes anything.
pub(crate) async fn installation_for_keypackage_publication(
    conn: &mut AsyncPgConnection,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    scope: &ScopeRef,
    service_did_document: &arkret_identity::DidDocument,
    at: chrono::DateTime<chrono::Utc>,
    writer: bool,
) -> PersistenceResult<(arkret_models_integration::AppletRegistrationPayload, Value)> {
    if !matches!(scope, ScopeRef::Realm { .. } | ScopeRef::Circle { .. })
        || !authority.scopes.contains_scope(scope)
    {
        return Err(denied(
            "native KeyPackage exceeds its original Device scope",
        ));
    }
    crate::boxed_future(|| {
        installation_at_scope(conn, authority, scope, service_did_document, at, writer)
    })
    .await
}

async fn installation_at_scope(
    conn: &mut AsyncPgConnection,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    scope: &ScopeRef,
    service_did_document: &arkret_identity::DidDocument,
    at: chrono::DateTime<chrono::Utc>,
    writer: bool,
) -> PersistenceResult<(arkret_models_integration::AppletRegistrationPayload, Value)> {
    installation_identity(
        conn,
        &authority.account_id,
        &authority.applet_id,
        &authority.source_service_id,
        scope,
        service_did_document,
        at,
        writer,
        None,
    )
    .await
}

#[expect(
    clippy::too_many_arguments,
    reason = "The same installation cut accepts a local PCR or one verified remote identity, without synthesizing Device scopes."
)]
async fn installation_identity(
    conn: &mut AsyncPgConnection,
    account: &arkret_wire::AccountId,
    applet: &arkret_wire::AppletId,
    service: &arkret_wire::DidCoreId,
    scope: &ScopeRef,
    service_did_document: &arkret_identity::DidDocument,
    at: chrono::DateTime<chrono::Utc>,
    writer: bool,
    forwarded: Option<&coland_storage::ForwardedManagedActorSource>,
) -> PersistenceResult<(arkret_models_integration::AppletRegistrationPayload, Value)> {
    let registration =
        crate::managed_message_actor::registration_for_scope(conn, scope.realm_id(), applet)
            .await?;
    if &registration.service_id != service {
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
        "SELECT i.record AS value,(m.record->>'globally_fenced_at' IS NOT NULL) AS globally_fenced FROM applet_installations i JOIN applet_registration_current_results r ON r.realm_id=$3 AND r.applet_id=i.applet_id JOIN applet_registration_instances a ON a.realm_id=r.realm_id AND a.applet_id=r.applet_id AND a.instance_event_ref=r.instance_event_ref AND a.registration_event_ref=i.record#>>'{{registration_event,event_id}}' JOIN applet_managed_identities m ON m.applet_id=i.applet_id AND m.target_station_id=i.record->>'target_station_id' WHERE i.applet_id=$1 AND i.effective_scope_key=$2 AND ($4::text IS NULL OR m.target_station_id=$4) {locking}"
    );
    let row = sql_query(query)
        .bind::<Text, _>(applet.as_str())
        .bind::<Text, _>(key)
        .bind::<Text, _>(scope.realm_id().as_str())
        .bind::<diesel::sql_types::Nullable<Text>, _>(
            forwarded.is_none().then_some(account.station_id.as_str()),
        )
        .get_result::<InstallationRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .ok_or_else(|| denied("native Applet exact installation is absent or fenced"))?;
    if row.globally_fenced
        || row.value.get("revoked_at").is_some_and(|v| !v.is_null())
        || row.value["status"] == "revoked"
    {
        return Err(PersistenceError::Conflict(
            "applet_revoked: native exact installation is fenced".into(),
        ));
    }
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
    if let Some(source) = forwarded {
        source
            .verified()
            .ensure_live(at)
            .map_err(|e| denied(&e.to_string()))?;
        if source.verified().account() != account
            || &source.provision().applet_id != applet
            || &source.provision().service_id != service
        {
            return Err(denied(
                "forwarded managed identity differs from the actual registration",
            ));
        }
    } else {
        crate::managed_message_actor::require_managed_identity_in_connection(
            conn,
            &ActorId::account(account.clone()),
            applet,
            &registration,
            at,
        )
        .await?;
    }
    Ok((registration, row.value))
}

pub(crate) async fn installation_source(
    conn: &mut AsyncPgConnection,
    event: &Event,
    source: Source<'_>,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<(arkret_models_integration::AppletRegistrationPayload, Value)> {
    source.ensure_event(event, at)?;
    match source {
        Source::Local(guard) => installation(conn, event, guard, at).await,
        Source::Forwarded(_) => {
            let installed = installation_identity(
                conn,
                source.account(),
                source.applet(),
                source.service(),
                &event.scope_ref,
                source.document(),
                at,
                true,
                source.forwarded(),
            )
            .await?;
            if matches!(event.kind, EventKind::MlsGenesis | EventKind::MlsCommit)
                || (matches!(
                    event.kind,
                    EventKind::MemberState | EventKind::CircleMemberState
                ) && action(event)? == CapabilityActionId::AppletJoin)
            {
                let encrypted=sql_query("SELECT to_jsonb(EXISTS(SELECT 1 FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE e.state='committed' AND e.kind='ak.mls.genesis' AND c.realm_id=$1 AND e.envelope->'scope_ref'=$2)) AS value")
                    .bind::<Text,_>(event.realm_id.as_str()).bind::<Jsonb,_>(json!(event.scope_ref)).get_result::<JsonRow>(&mut *conn).await.map_err(PersistenceError::database)?;
                if encrypted.value.as_bool() != Some(false)
                    || matches!(event.kind, EventKind::MlsGenesis | EventKind::MlsCommit)
                {
                    crate::applet_e2ee::require_current_consent(
                        conn,
                        &installed.0,
                        &installed.1,
                        &event.scope_ref,
                        at,
                    )
                    .await?;
                }
            }
            Ok(installed)
        }
    }
}

/// Subject-only metadata binds an active accepted installation grant. It never
/// spends a fabricated join capability or lets a Service sign the consent.
pub(crate) async fn require_installation_binding(
    conn: &mut AsyncPgConnection,
    event: &Event,
    guard: &AppletManagedDeviceScopeGuard,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    require_installation_source(conn, event, Source::Local(guard), at).await
}

pub(crate) async fn require_installation_source(
    conn: &mut AsyncPgConnection,
    event: &Event,
    source: Source<'_>,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    let (registration, installation) = installation_source(conn, event, source, at).await?;
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
        EventKind::CircleMemberState if action(event)? == CapabilityActionId::AppletJoin => {
            AppletPolicyOperation::Join
        }
        EventKind::MessageCreate
        | EventKind::CircleMemberState
        | EventKind::MlsGenesis
        | EventKind::MlsCommit => AppletPolicyOperation::Execute,
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
            device_control: None,
            realm_id: &event.realm_id,
            requester_actor_id: &service,
            applet_id: &registration.applet_id,
            effective_scope: &event.scope_ref,
            managed_actor_id: Some(&event.actor_id),
            operation,
            content_action: if operation == AppletPolicyOperation::Execute {
                Some(business_action(event)?)
            } else {
                None
            },
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

pub(crate) fn business_action(event: &Event) -> PersistenceResult<CapabilityActionId> {
    action(event)?;
    match event.kind {
        EventKind::MessageCreate => Ok(CapabilityActionId::MessageCreate),
        EventKind::CircleMemberState => Ok(CapabilityActionId::CircleMemberAdd),
        EventKind::MlsGenesis => Ok(CapabilityActionId::MlsGenesis),
        EventKind::MlsCommit => Ok(CapabilityActionId::MlsCommit),
        _ => Err(denied("native business action has no domain consumer")),
    }
}

struct BusinessBasis {
    service: ActorId,
    action: CapabilityActionId,
    target: arkret_wire::WireResourceSelector,
    facts: coland_storage::OperationFacts,
    grants: std::collections::BTreeMap<
        GrantId,
        arkret_models_collaboration::governance::grant_constraint::CapabilityGrant,
    >,
    root: crate::capability_grant_current_results::RealmAuthorityRootCurrent,
    sources: Vec<arkret_models_collaboration::governance::grant_constraint::CapabilityGrant>,
}

/// Pure current source preparation for private review; no quota or vote is spent.
async fn business_basis(
    conn: &mut AsyncPgConnection,
    event: &Event,
    guard: &AppletManagedDeviceScopeGuard,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<BusinessBasis> {
    business_basis_source(conn, event, Source::Local(guard), at).await
}

async fn business_basis_source(
    conn: &mut AsyncPgConnection,
    event: &Event,
    source: Source<'_>,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<BusinessBasis> {
    use arkret_models_collaboration::events_payloads::CapabilityGrantCreateBody;
    use arkret_models_collaboration::governance::grant_constraint::{
        IssuerAuthorityRef, ManagedActorRole,
    };
    let action = business_action(event)?;
    let (registration, _) = installation_source(conn, event, source, at).await?;
    let service = ActorId::service(registration.service_id.clone());
    let cut = crate::boxed_future(|| {
        crate::realm_authorization_cut::RealmAuthorizationCut::read_for_event(conn, event)
    })
    .await?;
    let cut = cut.with_forwarded_managed(source.forwarded());
    cut.require_open_lifecycle(event)?;
    cut.require_governed_member(&event.kind)?;
    let (target, mut facts) = cut.event_operation(event);
    cut.complete_event_facts_in_connection(conn, event, &mut facts)
        .await?;
    facts.applet_id = Some(registration.applet_id.to_string());
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
    let provision = if let Some(source) = source.forwarded() {
        source.provision().clone()
    } else {
        let sources=sql_query("SELECT e.envelope->'payload' AS value FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE e.state='committed' AND e.kind='ak.applet.managed_actor.provision' AND e.envelope#>'{payload,actor_id}'=$1")
        .bind::<Jsonb,_>(json!(event.actor_id)).load::<JsonRow>(&mut *conn).await.map_err(PersistenceError::database)?;
        if sources.len() != 1 {
            return Err(denied("native business has no unique accepted provision"));
        }
        let provision: arkret_models_integration::AppletManagedActorProvisionPayload =
            serde_json::from_value(sources.into_iter().next().unwrap().value)
                .map_err(PersistenceError::database)?;
        provision
    };
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
    // A selected positive child cannot erase an unproved independent Account
    // lineage from the global refusal set. Only known closed sources may drop.
    arkret_policy::grant_authority::current_subject_grants(
        &event.actor_id, action.as_str(), &target, &grants, at,
        |source| matches!(source, IssuerAuthorityRef::RealmRoot { realm_id, authority_event_ref, authority_generation }
            if realm_id==&event.realm_id && authority_event_ref==&root.authority_event_ref
                && authority_generation==&root.authority_generation),
    ).map_err(|error| PersistenceError::Conflict(error.to_string()))?;
    let sources = arkret_policy::grant_authority::current_sources(
        child, action.as_str(), &target, &grants, at,
        |source| matches!(source, IssuerAuthorityRef::RealmRoot { realm_id, authority_event_ref, authority_generation }
            if realm_id==&event.realm_id && authority_event_ref==&root.authority_event_ref
                && authority_generation==&root.authority_generation),
    ).map_err(|error| PersistenceError::Conflict(error.to_string()))?;
    let sources = sources.into_iter().cloned().collect();
    Ok(BusinessBasis {
        service,
        action,
        target,
        facts,
        grants,
        root,
        sources,
    })
}

pub(crate) async fn require_business_binding(
    conn: &mut AsyncPgConnection,
    event: &Event,
    guard: &AppletManagedDeviceScopeGuard,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    business_basis(conn, event, guard, at).await.map(|_| ())
}

/// Spend the original Service ancestor paths alongside the ordinary domain unit.
pub(crate) async fn require_business_source(
    conn: &mut AsyncPgConnection,
    event: &Event,
    source: Source<'_>,
    commit: &arkret_wire::RealmCommit,
    prepared: Option<&coland_storage::EventApprovalCommit>,
) -> PersistenceResult<Vec<crate::approval_admission::QualifiedApproval>> {
    use arkret_models_collaboration::governance::grant_constraint::IssuerAuthorityRef;
    let at = commit.committed_at;
    let BusinessBasis {
        service,
        action,
        target,
        facts,
        grants,
        root,
        sources,
    } = business_basis_source(conn, event, source, at).await?;
    let actions = [action.as_str()];

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
                &source,
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

/// Recheck physical permission without charging a second logical operation.
/// Refusal qualification may probe quota in a rolled-back savepoint; neither
/// the refusal nor this final physical check consumes a business quota.
pub(crate) async fn require_mls_permission_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    guard: &AppletManagedDeviceScopeGuard,
    at: chrono::DateTime<chrono::Utc>,
    probe_quota: bool,
) -> PersistenceResult<()> {
    require_mls_permission_source(conn, event, Source::Local(guard), at, probe_quota).await
}

pub(crate) async fn require_mls_permission_source(
    conn: &mut AsyncPgConnection,
    event: &Event,
    source: Source<'_>,
    at: chrono::DateTime<chrono::Utc>,
    probe_quota: bool,
) -> PersistenceResult<()> {
    use arkret_models_collaboration::governance::grant_constraint::IssuerAuthorityRef;
    if !matches!(event.kind, EventKind::MlsGenesis | EventKind::MlsCommit) {
        return Err(denied("native MLS permission requires an actual MLS Event"));
    }
    if !crate::moderation_report_current_results::scope_member_in_connection(
        conn,
        &event.realm_id,
        &event.scope_ref,
        &event.actor_id,
    )
    .await?
    {
        return Err(denied(
            "native MLS author is not a current member of its exact scope",
        ));
    }
    source.ensure_event(event, at)?;
    if let Source::Local(guard) = source {
        let producer =
            coland_storage::SelfProducerCommitGuard::AppletManagedDevice(Box::new(guard.clone()));
        crate::authority_commit::check_self_producer_guard_in_connection(
            conn, event, &producer, at,
        )
        .await?;
    }
    let (registration, _) = installation_source(conn, event, source, at).await?;
    let (_, decision) = select_management(conn, event, &registration, at).await?;
    if !decision.review_requirements.is_empty() {
        return Err(PersistenceError::Conflict(
            "approval_required: native MLS management review is unavailable".into(),
        ));
    }
    let BusinessBasis {
        service,
        action,
        target,
        facts,
        grants,
        root,
        sources,
    } = business_basis_source(conn, event, source, at).await?;
    let cut = crate::boxed_future(|| {
        crate::realm_authorization_cut::RealmAuthorizationCut::read_for_event(conn, event)
    })
    .await?;
    let cut = cut.with_forwarded_managed(source.forwarded());
    let mut reservations = cut.native_mls_reservations(event, action, &target, &facts, at)?;
    if crate::policy_action_admission::current_quorum(conn, event, action, &target, &facts, at)
        .await?
        .is_some_and(|quorum| quorum > 0)
    {
        return Err(PersistenceError::Conflict(
            "approval_required: native MLS has no governance approval carrier".into(),
        ));
    }
    let actions = [action.as_str()];
    let mut actors = std::collections::BTreeSet::from([service]);
    for source in &sources {
        if let CapabilitySubject::Actor(actor) = &source.subject {
            actors.insert(actor.clone());
        }
    }
    for actor in actors {
        let matching = arkret_policy::grant_authority::current_subject_grants(
            &actor, actions[0], &target, &grants, at,
            |source| matches!(source, IssuerAuthorityRef::RealmRoot { realm_id, authority_event_ref, authority_generation }
                if realm_id == &event.realm_id && authority_event_ref == &root.authority_event_ref
                    && authority_generation == &root.authority_generation),
        ).map_err(|error| PersistenceError::Conflict(error.to_string()))?;
        let mut source_facts = facts.clone();
        source_facts.executed_by = Some(actor.clone());
        let evaluation = coland_storage::evaluate_authority_sources_with_verified_approvals(
            &coland_storage::AuthorizationOperation {
                actor: &actor,
                actions: &actions,
                target: &target,
                at,
                facts: &source_facts,
            },
            matching.iter().copied(),
            &[],
        );
        if matches!(
            evaluation,
            coland_storage::GrantEvaluation::Denied
                | coland_storage::GrantEvaluation::Quarantined
                | coland_storage::GrantEvaluation::RequiresReview
        ) {
            return Err(denied("native MLS source has a current global refusal"));
        }
    }
    for source in sources {
        let CapabilitySubject::Actor(ref actor) = source.subject else {
            return Err(denied("native MLS source has no Actor"));
        };
        let mut source_facts = facts.clone();
        source_facts.executed_by = Some(actor.clone());
        match coland_storage::evaluate_authority_sources_with_verified_approvals(
            &coland_storage::AuthorizationOperation {
                actor,
                actions: &actions,
                target: &target,
                at,
                facts: &source_facts,
            },
            std::iter::once(&source),
            &[],
        ) {
            coland_storage::GrantEvaluation::Allowed(paths) => {
                let path = paths
                    .into_iter()
                    .next()
                    .ok_or_else(|| denied("native MLS source has no satisfied path"))?;
                reservations.extend(path.reservations);
            }
            _ => return Err(denied("native MLS source constraints refuse the operation")),
        }
    }
    if probe_quota {
        sql_query("SAVEPOINT native_mls_refusal_quota")
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
        let permitted = crate::capability_quota::try_reserve_in_connection(
            conn,
            &reservations,
            event.event_id.as_str(),
        )
        .await?;
        sql_query("ROLLBACK TO SAVEPOINT native_mls_refusal_quota")
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("RELEASE SAVEPOINT native_mls_refusal_quota")
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
        if !permitted {
            return Err(PersistenceError::Conflict(
                "rate_limited: native MLS source quota is exhausted".into(),
            ));
        }
    }
    Ok(())
}
