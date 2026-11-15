//! Finite accepted-parent installation source, never a permission evaluator.
use std::collections::BTreeMap;

use arkret_models_collaboration::events_payloads::{
    CapabilityGrantCreateBody, CapabilityGrantPayload, CapabilityRevokePayload,
};
use arkret_models_collaboration::governance::grant_constraint::{
    CapabilityGrant, CapabilitySubject, GrantConstraintKind, GrantConstraintSubkind,
    IssuerAuthorityRef, ManagedActorRole,
};
use arkret_models_integration::{AppletRegistrationPayload, RealmActorCreatePayloadActorRole};
use arkret_wire::{ActorId, CommittedEventFullView, Event, EventId, EventKind, GrantId, ScopeRef};
use coland_storage::{PersistenceError, PersistenceResult};
use diesel::sql_query;
use diesel::sql_types::{Nullable, Text};
use diesel_async::AsyncPgConnection;
use horme::{OptionalExtension as _, RunQueryDsl};

/// Computed host-local provenance only; no Serde/public field or grant mirror.
/// Applet/Service/epoch are read from the accepted registration/body, not copied
/// into another DTO. This object cannot by itself confer an action permission.
pub(crate) struct FiniteAppletSource {
    pub scope: ScopeRef,
    registration_epoch: arkret_wire::Hash,
    pub install_id: String,
}
fn refused(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("failed_precondition: {detail}"))
}
fn terminal_body(body: &CapabilityGrantCreateBody) -> bool {
    let CapabilitySubject::Actor(subject) = &body.subject else {
        return false;
    };
    let controls = body
        .constraints
        .iter()
        .filter(|c| {
            c.constraint_kind == GrantConstraintKind::AuthorityControl
                && c.constraint_subkind.is_none()
        })
        .collect::<Vec<_>>();
    subject.as_realm_actor_id().is_some()
        && matches!(body.issuer_id, ActorId::Service { .. })
        && !body.issuer_authority_refs.is_empty()
        && body
            .issuer_authority_refs
            .iter()
            .all(|r| matches!(r, IssuerAuthorityRef::Grant { .. }))
        && !controls.is_empty()
        && controls
            .iter()
            .all(|c| c.max_authority_depth == Some(0) && c.authority_regrant_allowed == Some(false))
}
fn original_body_matches(
    current: &CapabilityGrant,
    mut original: CapabilityGrantCreateBody,
    realm: &arkret_wire::RealmId,
) -> PersistenceResult<()> {
    original.realm_id.get_or_insert_with(|| realm.clone());
    // Compare the immutable closed CreateBody projection as typed fields.
    // Derived id/depth/root and reducer close state are separate current facts.
    let same_subject = matches!((&current.subject,&original.subject),
        (CapabilitySubject::Actor(current),CapabilitySubject::Actor(original)) if current==original);
    if current.schema != original.schema
        || current.realm_id != original.realm_id
        || current.issuer_id != original.issuer_id
        || !same_subject
        || current.actions != original.actions
        || current.resources != original.resources
        || current.constraints != original.constraints
        || current.issuer_authority_refs != original.issuer_authority_refs
        || current.issued_at != original.issued_at
    {
        return Err(refused("parent current changes its accepted original"));
    }
    Ok(())
}
async fn original_grant(
    conn: &mut AsyncPgConnection,
    id: &GrantId,
    realm: &arkret_wire::RealmId,
) -> PersistenceResult<(CommittedEventFullView, CapabilityGrantCreateBody)> {
    let event_id =
        EventId::from_token_bytes(id.token_bytes()).map_err(PersistenceError::database)?;
    let full = crate::applet_authority_material::accepted(conn, &event_id).await?;
    if full.event.kind != EventKind::CapabilityGrant
        || full.event.realm_id != *realm
        || full.event.scope_ref != ScopeRef::realm(realm.clone())
    {
        return Err(refused(
            "finite parent is not an accepted Realm governance grant",
        ));
    }
    let payload: CapabilityGrantPayload = serde_json::from_value(
        serde_json::to_value(&full.event.payload).map_err(PersistenceError::database)?,
    )
    .map_err(PersistenceError::database)?;
    Ok((full, payload.grant))
}

/// Returns None only for a different profile. Once a complete finite carrier
/// is recognized, missing/NULL/mixed/future/unaccepted provenance is a refusal,
/// never a fallback to a generic active installation or a singleton search.
pub(crate) fn finite_source_for_event<'a>(
    conn: &'a mut AsyncPgConnection,
    event: &'a Event,
    grants: &'a BTreeMap<GrantId, CapabilityGrant>,
) -> std::pin::Pin<
    Box<
        dyn std::future::Future<Output = PersistenceResult<Option<FiniteAppletSource>>> + Send + 'a,
    >,
> {
    crate::boxed_future(|| finite_source_for_event_inner(conn, event, grants))
}

async fn finite_source_for_event_inner(
    conn: &mut AsyncPgConnection,
    event: &Event,
    grants: &BTreeMap<GrantId, CapabilityGrant>,
) -> PersistenceResult<Option<FiniteAppletSource>> {
    let ActorId::Service { service_id } = &event.actor_id else {
        return Ok(None);
    };
    let Some(applet) = &event.applet_id else {
        return Ok(None);
    };
    if event.executed_by.is_some() {
        return Ok(None);
    }
    let (mut child, original_child_commit) = match event.kind {
        EventKind::CapabilityGrant => {
            let payload: CapabilityGrantPayload = serde_json::from_value(
                serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
            )
            .map_err(PersistenceError::database)?;
            (payload.grant, None)
        }
        EventKind::CapabilityRevoke => {
            let payload: CapabilityRevokePayload = serde_json::from_value(
                serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
            )
            .map_err(PersistenceError::database)?;
            let (original, body) = original_grant(conn, &payload.grant_id, &event.realm_id).await?;
            if original.event.actor_id != event.actor_id || body.issuer_id != event.actor_id {
                return Ok(None);
            }
            (body, Some(original.commit))
        }
        _ => return Ok(None),
    };
    if !terminal_body(&child) {
        return Ok(None);
    }
    if event.scope_ref != ScopeRef::realm(event.realm_id.clone()) {
        return Err(refused("finite governance Event must use the Realm stream"));
    }
    if child.issuer_id != event.actor_id {
        return Err(refused("finite child issuer differs from actual Service"));
    }
    child.realm_id.get_or_insert_with(|| event.realm_id.clone());
    let CapabilitySubject::Actor(subject) = &child.subject else {
        unreachable!("terminal body has an Actor");
    };
    if subject
        .as_realm_actor_id()
        .is_none_or(|id| id.realm_id != event.realm_id)
    {
        return Err(refused("finite child subject belongs to another Realm"));
    }
    let creation = crate::realm_actor_control::creation_source(conn, subject).await?;
    if creation.applet_id != *applet {
        return Err(refused(
            "finite child is not an accepted Actor of this Applet",
        ));
    }
    let role = match creation.actor_role {
        RealmActorCreatePayloadActorRole::Bot => ManagedActorRole::Bot,
        RealmActorCreatePayloadActorRole::Ghost => ManagedActorRole::Ghost,
    };
    let anchor = event
        .authorization_ref
        .as_ref()
        .ok_or_else(|| refused("finite Event authorization_ref absent"))?
        .as_str()
        .parse::<GrantId>()
        .map_err(PersistenceError::database)?;
    let mut selected: Option<FiniteAppletSource> = None;
    let mut parents = Vec::new();
    let mut anchor_seen = false;
    #[derive(diesel::QueryableByName)]
    struct Frozen {
        #[diesel(sql_type=Text)]
        registration_event_ref: String,
        #[diesel(sql_type=Nullable<Text>)]
        install_id: Option<String>,
    }
    for reference in &child.issuer_authority_refs {
        let IssuerAuthorityRef::Grant { grant_id } = reference else {
            return Err(refused("finite child has a non-Grant source"));
        };
        let parent = grants
            .get(grant_id)
            .ok_or_else(|| refused("finite parent current unavailable"))?;
        let (original, body) = original_grant(conn, grant_id, &event.realm_id).await?;
        if original_child_commit.as_ref().is_some_and(|child| {
            original.commit.stream_ref != child.stream_ref
                || original.commit.stream_position >= child.stream_position
        }) {
            return Err(refused("finite parent is not prior to the accepted child"));
        }
        original_body_matches(parent, body, &event.realm_id)?;
        if !matches!(&parent.subject,CapabilitySubject::Actor(actor) if actor==&event.actor_id) {
            return Err(refused("finite parent has another Service subject"));
        }
        let scope = super::exact_installation_scope(&event.realm_id, parent)
            .ok_or_else(|| refused("finite parent lacks one canonical installation scope"))?;
        let bindings = parent
            .constraints
            .iter()
            .filter(|c| {
                c.constraint_kind == GrantConstraintKind::AuthorityControl
                    && c.constraint_subkind == Some(GrantConstraintSubkind::AppletAuthority)
            })
            .collect::<Vec<_>>();
        let [binding] = bindings.as_slice() else {
            return Err(refused("finite parent Applet binding is not unique"));
        };
        if binding.applet_id.as_ref() != Some(applet)
            || binding.executed_by.as_ref() != Some(&event.actor_id)
        {
            return Err(refused("finite parent Applet/executor differs"));
        }
        let epoch = binding
            .registration_epoch
            .as_ref()
            .ok_or_else(|| refused("finite parent epoch absent"))?;
        let frozen=sql_query("SELECT registration_event_ref,install_id FROM applet_grant_registration_sources WHERE realm_id=$1 AND grant_id=$2 AND applet_id=$3 AND service_id=$4")
            .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(grant_id.as_str()).bind::<Text,_>(applet.as_str()).bind::<Text,_>(service_id.as_str())
            .get_result::<Frozen>(&mut *conn).await.optional().map_err(PersistenceError::database)?.ok_or_else(||refused("finite parent frozen source absent"))?;
        let install_id = frozen.install_id.filter(|s| !s.is_empty()).ok_or_else(|| {
            refused("registration-only parent is not a finite installation source")
        })?;
        let registration_id = frozen
            .registration_event_ref
            .parse::<EventId>()
            .map_err(PersistenceError::database)?;
        let registration =
            crate::applet_authority_material::accepted(conn, &registration_id).await?;
        let payload: AppletRegistrationPayload = serde_json::from_value(
            serde_json::to_value(&registration.event.payload)
                .map_err(PersistenceError::database)?,
        )
        .map_err(PersistenceError::database)?;
        if registration.event.kind != EventKind::AppletRegistration
            || registration.event.realm_id != event.realm_id
            || registration.event.scope_ref != ScopeRef::realm(event.realm_id.clone())
            || payload.applet_id != *applet
            || payload.service_id != *service_id
            || payload.registration_epoch != *epoch
            || registration.commit.stream_ref != original.commit.stream_ref
            || registration.commit.stream_position >= original.commit.stream_position
        {
            return Err(refused(
                "finite registration is not the parent's exact prior accepted source",
            ));
        }
        if let Some(old) = &selected {
            if old.scope != scope
                || old.install_id != install_id
                || old.registration_epoch != payload.registration_epoch
            {
                return Err(refused(
                    "finite parents mix historical source tuples or installation instances",
                ));
            }
        } else {
            selected = Some(FiniteAppletSource {
                scope,
                registration_epoch: payload.registration_epoch,
                install_id,
            });
        }
        anchor_seen |= *grant_id == anchor;
        parents.push(parent);
    }
    if !anchor_seen {
        return Err(refused(
            "finite authorization_ref is not a contributing parent",
        ));
    }
    // This existing owner proves every named parent's real contribution,
    // original retained constraints, per(action,resource) window union and role.
    // It deliberately does not re-run current business liveness for a Revoke.
    arkret_policy::grant_authority::validate_managed_service_sources(&child, &parents, role)
        .map_err(refused)?;
    Ok(Some(
        selected.ok_or_else(|| refused("finite source is empty"))?,
    ))
}
