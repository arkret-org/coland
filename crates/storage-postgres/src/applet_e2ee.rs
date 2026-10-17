//! Independent MLS consent from the existing accepted installation originals.
//! Device authority, membership and per-operation Policy remain separate gates.
use std::collections::BTreeMap;

use arkret_models_collaboration::governance::grant_constraint::CapabilitySubject;
use arkret_models_collaboration::governance::operation_wire::{
    AppletPolicyOperation, PolicyResourceKind, PolicyResourceSelector,
};
use arkret_models_integration::{
    AppletInstallOutcome, AppletInstallRequestBody, AppletRegistrationPayload,
};
use arkret_wire::{ActorId, Event, EventKind, GrantId, PolicyEffect, ScopeRef};
use coland_storage::{PersistenceError, PersistenceResult};
use diesel::sql_types::{Jsonb, Text, Timestamptz};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::{Value, json};

fn refused(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("applet_e2ee_join_unauthorized: {detail}"))
}

/// Installation policy is enforced under the aggregate's Realm lock. Installing
/// an MLS-capable Service never admits an Account or consumes a join review.
pub(crate) async fn require_install_policy(
    conn: &mut AsyncPgConnection,
    body: &AppletInstallRequestBody,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    let basis = &body.authoring_request_basis;
    let scope = &basis.effective_scope;
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
    let mut resources = vec![PolicyResourceSelector {
        kind: PolicyResourceKind::Realm,
        realm_id: Some(scope.realm_id().clone()),
        resource_ref: Some(scope.realm_id().to_string()),
    }];
    if let Some(circle) = circle {
        resources.push(PolicyResourceSelector {
            kind: PolicyResourceKind::Object,
            realm_id: Some(scope.realm_id().clone()),
            resource_ref: Some(circle.to_string()),
        });
    }
    let decision = arkret_policy::applet_management::select_applet_management(
        Some(&policies),
        &arkret_policy::applet_management::AppletManagementContext {
            device_control: None,
            realm_id: scope.realm_id(),
            requester_actor_id: &basis.install_actor_id,
            applet_id: &body.applet_package.applet_id,
            effective_scope: scope,
            managed_actor_id: None,
            operation: AppletPolicyOperation::Install,
            content_action: None,
            resources: Some(&resources),
            at,
        },
    )
    .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    if decision.effect != PolicyEffect::Allow {
        return Err(PersistenceError::Conflict(
            "capability_denied: current Applet management Policy rejects installation".into(),
        ));
    }
    Ok(())
}

#[derive(QueryableByName)]
struct AcceptedInstall {
    #[diesel(sql_type = Text)]
    canonical_request_hash: String,
    #[diesel(sql_type = Jsonb)]
    request_body: Value,
    #[diesel(sql_type = Jsonb)]
    response_body: Value,
    #[diesel(sql_type = Timestamptz)]
    accepted_at: chrono::DateTime<chrono::Utc>,
}

#[derive(QueryableByName)]
struct Original {
    #[diesel(sql_type = Jsonb)]
    envelope: Value,
}

/// Requires a current exact installation from `installation_for_device` at the
/// same locked cut. No cached boolean or membership/Welcome implies consent.
pub(crate) async fn require_current_consent(
    conn: &mut AsyncPgConnection,
    registration: &AppletRegistrationPayload,
    installation: &Value,
    scope: &ScopeRef,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    let digest = installation
        .get("install_body_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| refused("accepted installation request identity is absent"))?;
    let accepted = sql_query("SELECT canonical_request_hash,request_body,response_body,accepted_at FROM applet_authoring_units WHERE operation_id='ak.self.applet.command.install' AND canonical_request_hash=$1 AND request_body#>>'{authoring_request_basis,applet_id}'=$2 AND request_body#>'{authoring_request_basis,effective_scope}'=$3 FOR SHARE")
        .bind::<Text,_>(digest).bind::<Text,_>(registration.applet_id.as_str())
        .bind::<Jsonb,_>(json!(scope)).get_results::<AcceptedInstall>(&mut *conn).await
        .map_err(PersistenceError::database)?;
    let [accepted] = accepted.as_slice() else {
        return Err(refused("accepted installation consent is not unique"));
    };
    if accepted.accepted_at > at
        || arkret_canonical::canonical_sha256(&accepted.request_body).map_err(refused)?
            != accepted.canonical_request_hash
    {
        return Err(refused("accepted installation request identity differs"));
    }
    let body: AppletInstallRequestBody =
        serde_json::from_value(accepted.request_body.clone()).map_err(refused)?;
    let basis = &body.authoring_request_basis;
    let refs = body.e2ee_join_authorization_refs().map_err(refused)?;
    if refs.is_empty()
        || basis.effective_scope != *scope
        || basis.service_id != registration.service_id
        || basis.registration_event.kind != EventKind::AppletRegistration
        || json!(basis.registration_event.payload) != json!(registration)
        || installation["registration_event"] != json!(basis.registration_event)
        || installation["capability_grant_events"] != json!(basis.capability_grant_events)
        || installation["package"] != json!(body.applet_package)
    {
        return Err(refused(
            "exact accepted registration and install consent differ",
        ));
    }
    let outcome: AppletInstallOutcome =
        serde_json::from_value(accepted.response_body.clone()).map_err(refused)?;
    if outcome.registration_event_ref != basis.registration_event.event_id
        || outcome.e2ee_authorization_refs != refs
        || installation["install_response"] != accepted.response_body
        || outcome.capability_grant_refs
            != basis
                .capability_grant_events
                .iter()
                .map(|e| GrantId::from_event_id(&e.event_id))
                .collect::<Vec<_>>()
    {
        return Err(refused("accepted MLS consent references differ"));
    }
    // Reconstruct from retained canonical originals; an installation mirror or
    // exact-request row alone cannot replace the accepted Event/Commit pair.
    for source in std::iter::once(&basis.registration_event).chain(&basis.capability_grant_events) {
        let original = sql_query("SELECT e.envelope FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE e.envelope->>'event_id'=$1 AND e.state='committed' AND c.realm_id=$2 AND e.envelope->'scope_ref'=$3 AND c.committed_at<=$4 FOR SHARE OF e,c")
            .bind::<Text,_>(source.event_id.as_str()).bind::<Text,_>(scope.realm_id().as_str())
            .bind::<Jsonb,_>(json!(scope)).bind::<Timestamptz,_>(at)
            .get_result::<Original>(&mut *conn).await.optional().map_err(PersistenceError::database)?
            .ok_or_else(|| refused("original accepted installation Event is absent"))?;
        let event: Event = serde_json::from_value(original.envelope).map_err(refused)?;
        if json!(event) != json!(source) || source.actor_id != basis.install_actor_id {
            return Err(refused("original accepted installation Event differs"));
        }
    }
    let rows = sql_query("SELECT realm_id,grant_id,status,current_event_id,current_commit_id,current_stream_ref,current_stream_position,value FROM capability_grant_current_results WHERE realm_id=$1 ORDER BY grant_id FOR SHARE")
        .bind::<Text,_>(scope.realm_id().as_str())
        .get_results::<crate::capability_grant_current_results::CapabilityGrantCurrentResultReadRow>(&mut *conn)
        .await.map_err(PersistenceError::database)?;
    let mut grants = BTreeMap::new();
    for row in rows {
        let row = crate::capability_grant_current_results::decode_row(row)?;
        grants.insert(row.grant_id, row.value);
    }
    let root = sql_query("SELECT realm_id,controller_actor_id,controller_epoch,authority_generation,authority_event_ref FROM realm_authority_root_current_results WHERE realm_id=$1 FOR SHARE")
        .bind::<Text,_>(scope.realm_id().as_str())
        .get_result::<crate::capability_grant_current_results::RealmAuthorityRootReadRow>(&mut *conn)
        .await.map_err(PersistenceError::database)?;
    let root = crate::capability_grant_current_results::decode_authority_root(root)?;
    let mut current_binding = false;
    for source in &basis.capability_grant_events {
        let id = GrantId::from_event_id(&source.event_id);
        let grant = grants.get(&id).ok_or_else(|| {
            PersistenceError::Conflict(
                "temporarily_unavailable: original install grant current is unavailable".into(),
            )
        })?;
        if !matches!(&grant.subject, CapabilitySubject::Actor(actor) if actor == &ActorId::service(registration.service_id.clone()))
            || source.actor_id != grant.issuer_id
            || grant.realm_id.as_ref() != Some(scope.realm_id())
        {
            return Err(refused("exact install grant ownership differs"));
        }
        // Creation and business grants are independently withdrawable. Every
        // original remains audit provenance; a closed unrelated original is
        // not a new lifetime condition on the Account's explicit MLS consent.
        current_binding |= crate::capability_grant_current_results::accepted_grant_is_current(
            &id,
            &grants,
            &root,
            scope.realm_id(),
            at,
        )?;
    }
    if !current_binding {
        return Err(refused(
            "no current exact installation grant binds MLS consent",
        ));
    }
    Ok(())
}
