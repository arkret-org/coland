//! Native Device Event and creation facts for the shared private management ledger.
use arkret_models_integration::RealmActorCreatePayload;
use coland_storage::ManagementReviewCurrent;

use super::*;

pub(super) fn native_event(request: &ManagementReviewRequestBody) -> bool {
    matches!(&request.target, ManagementReviewTarget::Event {event} if event.applet_id.is_some())
}

pub(super) fn event_target(request: &ManagementReviewRequestBody) -> PersistenceResult<&Event> {
    request.validate().map_err(invalid)?;
    if creation(request) {
        return creation_target(request).map(|(event, _)| event);
    }
    let ManagementReviewTarget::Event { event } = &request.target;
    if crate::applet_scope_profiles::is_profile(event) {
        if request.management_operation != ManagementOperation::Publish
            || request.effective_scope.realm_id() != &event.realm_id
            || !matches!(request.requester_actor_id, ActorId::Service { .. })
        {
            return Err(hidden());
        }
        return Ok(event);
    }
    let ManagementReviewTarget::Event { event } = &request.target;
    if !native_event(request)
        || !matches!(
            (
                request.management_operation,
                crate::applet_device_admission::action(event)?
            ),
            (
                ManagementOperation::Join,
                arkret_wire::CapabilityActionId::AppletJoin
            ) | (
                ManagementOperation::Publish,
                arkret_wire::CapabilityActionId::AppletPublish
            )
        )
        || event.scope_ref != request.effective_scope
        || !matches!(request.requester_actor_id, ActorId::Service { .. })
    {
        return Err(hidden());
    }
    crate::applet_device_admission::action(event)?;
    Ok(event)
}

pub(super) async fn event_pins(
    conn: &mut AsyncPgConnection,
    request: &ManagementReviewRequestBody,
    at: DateTime<Utc>,
    current: &ManagementReviewCurrent,
) -> PersistenceResult<(Value, Vec<ManagementReviewRequirement>)> {
    let event = event_target(request)?;
    if crate::applet_scope_profiles::is_profile(event) {
        crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &event.realm_id).await?;
        let admission = crate::applet_scope_profiles::prepare_control(conn, event, at).await?;
        if admission.publish_scope.as_ref() != Some(&request.effective_scope) {
            return Err(hidden());
        }
        let (pins, decision) =
            crate::applet_scope_profiles::publish_basis(conn, event, &admission, at).await?;
        if pins["requester"] != json!(request.requester_actor_id) {
            return Err(hidden());
        }
        let authority =
            sql_query("SELECT to_jsonb(a) AS value FROM realm_authorities a WHERE realm_id=$1")
                .bind::<Text, _>(event.realm_id.as_str())
                .get_result::<JsonRow>(&mut *conn)
                .await
                .map_err(PersistenceError::database)?;
        if authority.value["service_id"] != json!(current.station_id) {
            return Err(hidden());
        }
        return Ok((pins, decision.review_requirements));
    }
    let material = current.applet_event.as_ref().ok_or_else(|| {
        refused(
            "revision_unavailable",
            "native management resolver material is unavailable",
        )
    })?;
    let authority = crate::realm_actor_device_authority::for_event_in_connection(conn, event, at)
        .await
        .map_err(crate::PgTransactionError::into_persistence)?
        .ok_or_else(hidden)?;
    if material.realm_id != authority.realm_id
        || current.station_id != authority.governance_service_id
        || request.requester_actor_id != ActorId::service(authority.source_service_id.clone())
    {
        return Err(refused(
            "capability_denied",
            "native management source or Service requester differs",
        ));
    }
    let guard = coland_storage::AppletManagedDeviceScopeGuard {
        authority: authority.clone(),
        effective_scope: event.scope_ref.clone(),
        service_did_document: material.service_did_document.clone(),
    };
    if event.kind == arkret_wire::EventKind::CircleMemberState {
        crate::applet_device_admission::require_business_binding(conn, event, &guard, at).await?;
    } else {
        crate::applet_device_admission::require_installation_binding(conn, event, &guard, at)
            .await?;
    }
    let (registration, installation) =
        crate::applet_device_admission::installation(conn, event, &guard, at).await?;
    let cut = crate::realm_authorization_cut::RealmAuthorizationCut::read(
        conn,
        &event.realm_id,
        &event.actor_id,
    )
    .await?;
    cut.require_open_lifecycle(event)?;
    let source = crate::realm_actor_device_authority::signer_fact(conn, event, at)
        .await
        .map_err(crate::PgTransactionError::into_persistence)?;
    let mut source = json!(source);
    source
        .as_object_mut()
        .ok_or_else(hidden)?
        .remove("accepted_at");
    let scope_profile = if crate::applet_scope_profiles::is_profile(event) {
        let profile =
            crate::boxed_future(|| crate::applet_scope_profiles::prepare(conn, event, &guard, at))
                .await?;
        if !profile.is_public() {
            return Err(hidden());
        }
        Some(profile.pins())
    } else {
        None
    };
    let (policies, decision) =
        crate::applet_device_admission::select_management(conn, event, &registration, at).await?;
    let ids = policies
        .iter()
        .map(|p| p.id.to_string())
        .collect::<Vec<_>>();
    let revisions=sql_query("SELECT to_jsonb(p) AS value FROM policy_current_results p WHERE policy_id=ANY($1) ORDER BY policy_id FOR SHARE")
        .bind::<diesel::sql_types::Array<Text>,_>(ids).load::<JsonRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let membership=sql_query("SELECT to_jsonb(m) AS value FROM member_state_current_results m WHERE realm_id=$1 AND member_id=$2 FOR SHARE")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(event.actor_id.to_string()).get_result::<JsonRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    let circle = match &event.scope_ref {
        ScopeRef::Circle { circle_id, .. } => {
            let circle = crate::circle_current_results::locked_circle_basis(
                conn,
                &event.realm_id,
                circle_id,
            )
            .await?;
            let member = crate::circle_current_results::locked_membership_basis(
                conn,
                &event.realm_id,
                circle_id,
                &event.actor_id,
                None,
            )
            .await?;
            let parent = crate::member_state_admission::locked_membership_revision(
                conn,
                &event.realm_id,
                &event.actor_id,
            )
            .await?;
            let payload: arkret_models_collaboration::events_payloads::circle::CircleMemberStatePayload = serde_json::from_value(json!(&event.payload)).map_err(invalid)?;
            if !matches!(parent, Some((arkret_wire::MembershipState::Join, ref revision)) if payload.parent_membership_revision.as_ref() == Some(revision))
            {
                return Err(refused(
                    "failed_precondition",
                    "native Circle review parent revision differs",
                ));
            }
            Some(json!({"circle":circle,"membership":member}))
        }
        _ => None,
    };
    let mut pending = std::collections::BTreeSet::from([event
        .authorization_ref
        .as_ref()
        .ok_or_else(hidden)?
        .to_string()]);
    let mut grants = std::collections::BTreeMap::new();
    while let Some(id) = pending.pop_first() {
        if grants.contains_key(&id) {
            continue;
        }
        let row=sql_query("SELECT to_jsonb(g) AS value FROM capability_grant_current_results g WHERE realm_id=$1 AND grant_id=$2 FOR SHARE")
            .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(&id).get_result::<JsonRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?.ok_or_else(hidden)?;
        let value: arkret_models_collaboration::governance::grant_constraint::CapabilityGrant =
            serde_json::from_value(row.value["value"].clone()).map_err(invalid)?;
        for source in value.issuer_authority_refs {
            if let arkret_models_collaboration::governance::grant_constraint::IssuerAuthorityRef::Grant {grant_id}=source {pending.insert(grant_id.to_string());}
        }
        grants.insert(id, row.value);
    }
    let root=sql_query("SELECT to_jsonb(r) AS value FROM realm_authority_root_current_results r WHERE realm_id=$1 FOR SHARE")
        .bind::<Text,_>(event.realm_id.as_str()).get_result::<JsonRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let identity = crate::realm_actor_control_source::current(conn, &authority.actor_id).await?;
    let profile = crate::realm_actor_control::optional_current_source(
        conn,
        &authority.actor_id,
        json!({"kind":"realm_actor_profile","actor_id":authority.actor_id}),
    )
    .await?;
    Ok((
        json!({"producer":source,"original_proof":event.producer_proof,"scope":event.scope_ref,
        "device_scopes":authority.scopes,"device_expires_at":authority.expires_at,"device_generation":authority.current_device_generation_ref,
        "registration":registration,"installation_status":installation["status"],"package":installation["package"],"registration_event":installation["registration_event"],
        "scope_profile":scope_profile,"circle":circle,"resolution":identity.value.resolution,"resolution_source":identity.current_event,"profile":profile,"membership":membership.map(|r|r.value),
        "grant_revisions":grants,"authority_root":root.value,"policies":policies,"policy_revisions":revisions.into_iter().map(|r|r.value).collect::<Vec<_>>() }),
        decision.review_requirements,
    ))
}

pub(super) fn creation(request: &ManagementReviewRequestBody) -> bool {
    matches!(&request.target, ManagementReviewTarget::Event { event } if event.kind == EventKind::RealmActorCreate)
}

fn creation_target(
    request: &ManagementReviewRequestBody,
) -> PersistenceResult<(&Event, RealmActorCreatePayload)> {
    request.validate().map_err(invalid)?;
    let ManagementReviewTarget::Event { event } = &request.target;
    let candidate = crate::realm_actor_control::creation(event)?.ok_or_else(hidden)?;
    if request.requester_actor_id != event.actor_id
        || request.effective_scope != candidate.creation_scope
    {
        return Err(hidden());
    }
    Ok((event, candidate))
}

pub(super) fn beneficiary(request: &ManagementReviewRequestBody) -> PersistenceResult<ActorId> {
    Ok(creation_target(request)?.1.actor_id)
}

pub(super) fn deadline(request: &ManagementReviewRequestBody) -> Option<DateTime<Utc>> {
    creation_target(request)
        .ok()
        .map(|(_, candidate)| candidate.expires_at)
}

pub(super) async fn lock(
    conn: &mut AsyncPgConnection,
    request: &ManagementReviewRequestBody,
    _station: &arkret_wire::DidCoreId,
) -> PersistenceResult<()> {
    if creation(request) {
        let (event, _) = creation_target(request)?;
        crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &event.realm_id).await?;
    }
    Ok(())
}

pub(super) async fn pins(
    conn: &mut AsyncPgConnection,
    request: &ManagementReviewRequestBody,
    at: DateTime<Utc>,
    current: &ManagementReviewCurrent,
) -> PersistenceResult<(Value, Vec<ManagementReviewRequirement>)> {
    let (event, candidate) = creation_target(request)?;
    let material = current.applet_event.as_ref().ok_or_else(|| {
        refused(
            "revision_unavailable",
            "creation Service resolver material is unavailable",
        )
    })?;
    if material.realm_id != event.realm_id {
        return Err(hidden());
    }
    crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &event.realm_id).await?;
    let cut = crate::realm_authorization_cut::RealmAuthorizationCut::read(
        conn,
        &event.realm_id,
        &event.actor_id,
    )
    .await?;
    cut.require_open_lifecycle(event)?;
    arkret_identity::verify_realm_actor_initial_resolution(&candidate, at).map_err(invalid)?;
    let signer = crate::managed_message_actor::prepare_applet_producer_in_connection(
        conn,
        event,
        &coland_storage::AppletEventProducerGuard {
            service_did_document: material.service_did_document.clone(),
        },
        at,
    )
    .await?;
    let authority =
        sql_query("SELECT to_jsonb(a) AS value FROM realm_authorities a WHERE realm_id=$1")
            .bind::<Text, _>(event.realm_id.as_str())
            .get_result::<JsonRow>(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
    if authority.value["service_id"] != json!(current.station_id) {
        return Err(refused(
            "revision_unavailable",
            "creation reviewer is not the current governor",
        ));
    }
    let scope_key = coland_storage::applet_effective_scope_key(&candidate.creation_scope)?;
    let installation = sql_query("SELECT record AS value FROM applet_installations WHERE applet_id=$1 AND effective_scope_key=$2 AND service_id=$3 FOR UPDATE")
        .bind::<Text,_>(candidate.applet_id.as_str()).bind::<Text,_>(scope_key).bind::<Text,_>(candidate.service_id.as_str())
        .get_result::<JsonRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let (policies, decision) = select_current_creation(conn, event, at).await?;
    let ids = policies
        .iter()
        .map(|policy| policy.id.to_string())
        .collect::<Vec<_>>();
    let revisions = sql_query("SELECT to_jsonb(p) AS value FROM policy_current_results p WHERE policy_id=ANY($1) ORDER BY policy_id FOR SHARE")
        .bind::<diesel::sql_types::Array<Text>,_>(ids).load::<JsonRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let mut pending =
        std::collections::BTreeSet::from([candidate.creation_authorization_ref.to_string()]);
    let mut grants = std::collections::BTreeMap::new();
    while let Some(id) = pending.pop_first() {
        if grants.contains_key(&id) {
            continue;
        }
        let row = sql_query("SELECT to_jsonb(g) AS value FROM capability_grant_current_results g WHERE realm_id=$1 AND grant_id=$2 FOR SHARE")
            .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(&id).get_result::<JsonRow>(&mut *conn)
            .await.optional().map_err(PersistenceError::database)?.ok_or_else(hidden)?;
        let grant: arkret_models_collaboration::governance::grant_constraint::CapabilityGrant =
            serde_json::from_value(row.value["value"].clone()).map_err(invalid)?;
        for source in grant.issuer_authority_refs {
            if let arkret_models_collaboration::governance::grant_constraint::IssuerAuthorityRef::Grant { grant_id } = source {
                pending.insert(grant_id.to_string());
            }
        }
        grants.insert(id, row.value);
    }
    let root = sql_query("SELECT to_jsonb(r) AS value FROM realm_authority_root_current_results r WHERE realm_id=$1 FOR SHARE")
        .bind::<Text,_>(event.realm_id.as_str()).get_result::<JsonRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    // Signing time is not a mutable security pin. Keep the verified original
    // producer key and its exact registration/grant source coordinates instead.
    let mut signer = json!(signer);
    signer
        .as_object_mut()
        .ok_or_else(hidden)?
        .remove("accepted_at");
    Ok((
        json!({"candidate":candidate,"producer":signer,
        "original_target_digest":request.target.canonical_target_digest().map_err(invalid)?,
        "registration":installation.value["registration_event"],"package":installation.value["package"],
        "installation_status":installation.value["status"],"grant_revisions":grants,
        "authority_root":root.value,"policies":policies,
        "policy_revisions":revisions.into_iter().map(|row| row.value).collect::<Vec<_>>()}),
        decision.review_requirements,
    ))
}

pub(super) async fn select_current_creation(
    conn: &mut AsyncPgConnection,
    event: &Event,
    at: DateTime<Utc>,
) -> PersistenceResult<(
    Vec<Policy>,
    arkret_policy::applet_management::AppletManagementDecision,
)> {
    use arkret_models_collaboration::governance::operation_wire::{
        AppletPolicyOperation, PolicyResourceKind, PolicyResourceSelector,
    };
    let candidate = crate::realm_actor_control::creation(event)?.ok_or_else(hidden)?;
    let scope = &candidate.creation_scope;
    let circle = match scope {
        ScopeRef::Circle { circle_id, .. } => Some(circle_id),
        _ => None,
    };
    let policies =
        crate::policy_current_results::read_scoped_applet_management_policies_in_connection(
            conn,
            scope.realm_id(),
            circle,
        )
        .await?;
    let resources = vec![PolicyResourceSelector {
        kind: PolicyResourceKind::Realm,
        realm_id: Some(scope.realm_id().clone()),
        resource_ref: Some(scope.realm_id().to_string()),
    }];
    let decision = arkret_policy::applet_management::select_applet_management(
        Some(&policies),
        &arkret_policy::applet_management::AppletManagementContext {
            device_control: None,
            realm_id: scope.realm_id(),
            requester_actor_id: &event.actor_id,
            applet_id: &candidate.applet_id,
            service_id: &candidate.service_id,
            effective_scope: scope,
            managed_actor_id: Some(&candidate.actor_id),
            operation: match candidate.actor_role {
                arkret_models_integration::RealmActorCreatePayloadActorRole::Bot => {
                    AppletPolicyOperation::CreateBot
                }
                arkret_models_integration::RealmActorCreatePayloadActorRole::Ghost => {
                    AppletPolicyOperation::MapGhost
                }
            },
            content_action: None,
            resources: Some(&resources),
            at,
        },
    )
    .map_err(invalid)?;
    if matches!(
        decision.effect,
        PolicyEffect::Deny | PolicyEffect::Quarantine
    ) {
        return Err(refused(
            "capability_denied",
            "Applet management Policy rejects creation",
        ));
    }
    Ok((policies, decision))
}
